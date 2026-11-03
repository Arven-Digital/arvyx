from __future__ import annotations
from arvyx_control.replica_authority import authority_context

import json
import shutil
import os
import re
from pathlib import Path
import socket
import sys
import sqlite3
import tempfile
from contextlib import closing
from http.server import ThreadingHTTPServer
import threading
from urllib.error import HTTPError
from urllib.request import Request
from urllib.request import urlopen
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "arvctl" / "src"))

from arvyx_control.cli import main
from arvyx_control.api import (
    CONTINUATION_STALE_SECONDS,
    MAX_BODY_BYTES,
    _approval_effective_status,
    _bound_work_cards,
    _continuation_by_agent,
    _safe_control_event,
    _workload_by_agent,
    handle_api_request,
    make_handler,
    serve_api,
)
from arvyx_control.audit import run_audit
from arvyx_control.benchmark import run_recall_benchmark
from arvyx_control.bridge import build_bridge_policy, write_bridge_policy
from arvyx_control.control import (
    ControlEvent,
    acknowledge_thread,
    accept_handoff,
    approve_request,
    complete_task,
    consume_approval,
    complete_handoff,
    create_handoff,
    create_task,
    list_approvals,
    list_bus_messages,
    list_handoffs,
    list_tasks,
    post_bus_message,
    post_thread,
    post_thread_message,
    read_events,
    request_approval,
    review_handoff,
)
from arvyx_control.doctor import doctor
from arvyx_control.dogfood import dogfood_live_api, dogfood_self
from arvyx_control.evidence import export_evidence
from arvyx_control.importers import import_basic_memory, import_markdown, import_obsidian
from arvyx_control.mcp_client_evidence import attest_evidence_file, generate_mcp_client_evidence, validate_mcp_client_evidence
from arvyx_control.mcp import TOOL_NAMES, handle_request, tools_for_profile
from arvyx_control.readiness import readiness
from arvyx_control.recall import context_pack, excerpt, recall
from arvyx_control.release_candidate import release_candidate_report
from arvyx_control.release_host import release_host_report
from arvyx_control.store import manifest_state, sync_sqlite
from arvyx_control.vault import init_vault, run_demo


VAULT = ROOT / "fixtures" / "synthetic-vault"
SIGNER_PRINCIPAL = "codex@ci.example"


def _handle_request_operator(payload: dict, **kwargs):
    """Call the MCP surface with the full operator catalog.

    These tests exercise the operator-visible tool set, so they name it
    explicitly; the library default is the read-only profile.
    """
    kwargs.setdefault("allowed_tools", set(TOOL_NAMES))
    payload = dict(payload)
    payload.setdefault('idempotency_key', 'recall-fixture-' + __import__('uuid').uuid4().hex)
    vault = kwargs['vault']
    state = kwargs.setdefault('state', vault / 'control-events.jsonl')
    with authority_context(vault, state):
        return handle_request(payload, **kwargs)


def _git_head() -> str:
    import subprocess

    completed = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=True)
    return completed.stdout.strip()


def _git_tree() -> str:
    import subprocess

    completed = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True, capture_output=True, check=True
    )
    return completed.stdout.strip()


def _make_pinned_signer(tmp: Path, principal: str = SIGNER_PRINCIPAL) -> tuple[Path, Path]:
    """Create an ephemeral ed25519 key and an allowed_signers file pinning its
    public key. Returns (private_key_path, allowed_signers_path)."""
    import subprocess

    key = tmp / "signer_ed25519"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", principal, "-f", str(key)],
        check=True,
        capture_output=True,
    )
    pub = (tmp / "signer_ed25519.pub").read_text(encoding="utf-8").split()
    allowed = tmp / "allowed_signers"
    allowed.write_text(f"{principal} {pub[0]} {pub[1]}\n", encoding="utf-8")
    return key, allowed


def _write_signed_external_mcp_evidence(
    path: Path,
    key_path: Path,
    *,
    checked_at: str | None = None,
    git_head: str | None = None,
    git_tree: str | None = None,
    principal: str = SIGNER_PRINCIPAL,
) -> None:
    from datetime import UTC, datetime

    payload = {
        "schema_version": 1,
        "client": "codex",
        # Synthetic external-client protocol fixture, not evidence that an SDK
        # ran here; the release gate additionally requires a pinned signer.
        "client_version": "fixture-1",
        "client_provenance": {
            "kind": "third-party-sdk", "distribution": "mcp",
            "version": "fixture-1", "implementation_sha256": "1" * 64,
        },
        "capture_sha256": "2" * 64,
        "capture_bytes": 1,
        "scan_scope": ["initialize", "tools/list", "memory.recall"],
        "checked_at": checked_at or datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "git_head": git_head or _git_head(),
        "git_tree": git_tree or _git_tree(),
        "transport": "stdio",
        "command": "python3 -m arvyx_control.cli mcp --vault fixtures/synthetic-vault",
        "result": {
            "tools_list_ok": True,
            "recall_ok": True,
            "sources_returned": True,
            "private_paths_leaked": False,
        },
    }
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    # A pinned signer signs off-host; the release operator never holds this key.
    attest_evidence_file(path, key_path=key_path, principal=principal)


def _pinned_release_policy(allowed: Path, principal: str = SIGNER_PRINCIPAL):
    """Pin the ephemeral signer and make only it release-grade for one test.

    Release MCP validation reads both seams from attestation at call time; the
    host provenance path imports them into release_host.
    """
    from contextlib import ExitStack
    from unittest.mock import patch

    stack = ExitStack()
    grade = frozenset({principal})
    stack.enter_context(patch("arvyx_control.release_host.allowed_signers_path", return_value=allowed))
    stack.enter_context(patch("arvyx_control.release_host.release_grade_principals", return_value=grade))
    stack.enter_context(patch("arvyx_control.attestation.allowed_signers_path", return_value=allowed))
    stack.enter_context(patch("arvyx_control.attestation.release_grade_principals", return_value=grade))
    return stack


def _release_host_fake_run(real_run, head: str, tree: str):
    """Fake only host smoke commands and a clean worktree; inventory is real.

    subprocess is patched globally, so every git read made by the audit binding,
    scanner and worktree check is routed here. Outputs honour text/bytes mode.
    """
    import subprocess

    inventory = (["git", "-C", str(ROOT), "ls-files", "--cached", "-z"],
                 ["git", "-C", str(ROOT), "ls-files", "--others", "--exclude-standard", "-z"])

    def reply(command, kwargs, stdout):
        text = kwargs.get("text") or kwargs.get("universal_newlines") or kwargs.get("encoding")
        return subprocess.CompletedProcess(command, 0, stdout if text else stdout.encode(), "" if text else b"")

    def fake_run(command, **kwargs):
        command = list(command)
        if command and str(command[0]) == "ssh-keygen":
            return real_run(command, **kwargs)
        if command in inventory or command == ["git", "ls-files", "-v", "-z"]:
            # The bounded scanner and skip-worktree refusal read the real
            # candidate via Git. Do not synthesize an inventory or waive flags.
            return real_run(command, **kwargs)
        if command[1:] == ["scripts/docker_runtime_smoke.py", "--json"]:
            return reply(command, kwargs,
                '{"command": ["docker", "run"], "error": "", "mode": "docker", "ok": true, "returncode": 0}')
        if any(Path(str(part)).name == "bridge_dogfood_smoke.py" for part in command):
            return reply(command, kwargs, '{"ok": true}')
        if command == ["git", "rev-parse", "HEAD"]:
            return reply(command, kwargs, head + "\n")
        if command == ["git", "rev-parse", "HEAD^{tree}"]:
            return reply(command, kwargs, tree + "\n")
        if command in (["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
                       ["git", "status", "--porcelain", "--untracked-files=all"]):
            # A clean worktree keeps docker/bridge/mcp checks the subject under test.
            return reply(command, kwargs, "")
        if command == ["git", "rev-parse", "--short", "HEAD"]:
            return reply(command, kwargs, "testhead\n")
        raise AssertionError(f"unexpected command: {command}")

    return fake_run


class SafeControlEventMotionContractTests(unittest.TestCase):
    def _safe(self, event_type: str, payload: dict[str, object]) -> dict[str, object]:
        return _safe_control_event(
            ControlEvent(
                id=f"event-{event_type}",
                type=event_type,
                task_id="subject-1",
                timestamp="2026-08-24T00:00:00Z",
                payload=payload,
            )
        )

    def test_projects_explicit_transition_principal_without_reusing_thread_creator(self) -> None:
        posted = self._safe(
            "thread.message.posted",
            {"actor": "amir", "target": "esme", "posted_by": "esme"},
        )
        self.assertEqual(posted["performed_by"], "esme")
        self.assertEqual(posted["route_target"], "amir")

        done = self._safe(
            "thread.done",
            {"actor": "amir", "target": "esme", "done_by": "esme"},
        )
        self.assertEqual(done["performed_by"], "esme")
        self.assertNotIn("route_target", done)

        completed = self._safe(
            "handoff.completed",
            {"from_agent": "amir", "to_agent": "kiran", "completed_by": "operator"},
        )
        self.assertEqual(completed["performed_by"], "operator")
        self.assertNotIn("route_target", completed)

    def test_only_explicit_communication_events_receive_route_targets(self) -> None:
        handoff = self._safe(
            "handoff.created",
            {"from_agent": "amir", "to_agent": "kiran"},
        )
        self.assertEqual(handoff["performed_by"], "amir")
        self.assertEqual(handoff["route_target"], "kiran")

        thread = self._safe(
            "thread.created",
            {"actor": "amir", "target": "kiran"},
        )
        self.assertEqual(thread["performed_by"], "amir")
        self.assertEqual(thread["route_target"], "kiran")

        accepted = self._safe(
            "handoff.accepted",
            {"from_agent": "amir", "to_agent": "kiran"},
        )
        self.assertEqual(accepted["performed_by"], "kiran")
        self.assertNotIn("route_target", accepted)

        reviewed = self._safe(
            "handoff.reviewed",
            {"from_agent": "amir", "to_agent": "kiran", "reviewer": "esme"},
        )
        self.assertEqual(reviewed["performed_by"], "esme")
        self.assertNotIn("route_target", reviewed)

        acknowledged = self._safe(
            "thread.acknowledged",
            {"actor": "amir", "target": "kiran", "acked_by": "kiran"},
        )
        self.assertEqual(acknowledged["performed_by"], "kiran")
        self.assertNotIn("route_target", acknowledged)


class RecallTests(unittest.TestCase):
    def setUp(self) -> None:
        self._denylist_environment = patch.dict(
            os.environ,
            {"ARVYX_PRIVATE_DENYLIST": str(ROOT / "fixtures" / "private-denylist.example.txt")},
        )
        self._denylist_environment.start()
        self.addCleanup(self._denylist_environment.stop)

    def test_api_control_plane_projects_bounded_private_fleet_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            (vault / "registry/agents").mkdir(parents=True)
            (vault / "registry/runtimes").mkdir(parents=True)
            (vault / "registry/machines").mkdir(parents=True)
            (vault / "agents/demobot/raw").mkdir(parents=True)
            (vault / "agents/vesper").mkdir(parents=True)
            (vault / "registry/agents/demobot.json").write_text(json.dumps({
                "id": "demobot", "display_name": "Atlas", "runtime_id": "runtime-a",
                "machine_id": "machine-a", "scopes": ["memory.read"], "skills": ["recall", {"name": "control"}],
                "dashboard": {"desk": "security", "hidden": "yes", "style": "color:red"},
            }), encoding="utf-8")
            (vault / "registry/agents/vesper.json").write_text(json.dumps({
                "id": "vesper", "display_name": "Vesper", "runtime_id": "runtime-a",
                "machine_id": "machine-a", "scopes": ["control.read"],
            }), encoding="utf-8")
            (vault / "registry/agents/invalid.json").write_text("{not-json", encoding="utf-8")
            (vault / "registry/runtimes/runtime-a.json").write_text(
                json.dumps({"id": "runtime-a", "display_name": "Runtime A", "harness": "codex"}), encoding="utf-8"
            )
            (vault / "registry/machines/machine-a.json").write_text(
                json.dumps({"id": "machine-a", "display_name": "Machine A", "role": "worker"}), encoding="utf-8"
            )
            # newline="\n" keeps the on-disk byte counts asserted below platform-independent.
            (vault / "agents/demobot/MEMORY.md").write_text("private memory marker\nsecond line\n", encoding="utf-8", newline="\n")
            (vault / "agents/demobot/raw/2026-08-23.md").write_text("secret raw marker\n", encoding="utf-8", newline="\n")
            (vault / "agents/vesper/SESSION-STATE.md").write_text("private session marker\n", encoding="utf-8", newline="\n")
            state = Path(tmp) / "events.jsonl"
            with authority_context(vault, state):
                task = create_task(state=state, title="Review fleet", owner="demobot")
                create_handoff(state=state, title="Verify fleet", from_agent="demobot", to_agent="vesper")
                blocker = post_thread(state=state, title="Fleet blocker", actor="operator", target="demobot", thread_type="blocker")
                acknowledge_thread(state=state, thread_id=blocker.thread.id, actor="demobot")
                progress = post_thread_message(
                    state=state,
                    thread_id=blocker.thread.id,
                    actor="demobot",
                    text="Working; next checkpoint recorded.",
                )
                informational = post_thread(
                    state=state,
                    title="Fleet status history",
                    actor="operator",
                    target="demobot",
                    thread_type="status",
                )

                denied = handle_api_request("GET", "/control-plane", {}, vault=vault, state=state)
                with (
                    patch("arvyx_control.api.read_events", wraps=read_events) as api_read_once,
                    patch("arvyx_control.control.read_events", wraps=read_events) as control_fallback,
                ):
                    response = handle_api_request(
                        "GET", "/control-plane", {}, vault=vault, state=state,
                        bearer_secret="synthetic-control-plane-operator",
                        authorization="Bearer synthetic-control-plane-operator",
                    )
                    self.assertEqual(api_read_once.call_count, 1)
                    self.assertEqual(control_fallback.call_count, 0)
                fixture_events = read_events(state)

        self.assertEqual(denied.status, 401)
        self.assertIn("control.read", denied.body["error"])
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["schema"], "arvyx-control-plane/v1")
        self.assertEqual(response.body["source"]["events"], 6)
        fixture_timestamps = [event.timestamp for event in fixture_events]
        self.assertEqual(response.body["source"]["event_count"], len(fixture_events))
        self.assertEqual(response.body["source"]["first_timestamp"], min(fixture_timestamps))
        self.assertEqual(response.body["source"]["last_timestamp"], max(fixture_timestamps))
        self.assertEqual(response.body["source"]["retention"], "append-only-jsonl")
        self.assertEqual(len(response.body["activity"]["buckets"]), 12)
        self.assertTrue(response.body["activity"]["event_types"])
        self.assertEqual([agent["id"] for agent in response.body["agents"]], ["demobot", "vesper"])
        demobot, vesper = response.body["agents"]
        self.assertEqual(demobot["presence"], {"state": "registered", "source": "registry", "heartbeat_at": None})
        self.assertEqual(demobot["blockers"], {"count": 1, "highest_severity": "notice"})
        self.assertEqual(demobot["continuation"]["state"], "active")
        self.assertEqual(demobot["continuation"]["active_count"], 1)
        self.assertEqual(demobot["continuation"]["stale_count"], 0)
        self.assertEqual(demobot["continuation"]["subjects"][0]["id"], blocker.thread.id)
        self.assertEqual(
            demobot["continuation"]["subjects"][0]["last_progress_at"],
            progress.thread.latest_at,
        )
        self.assertEqual(response.body["continuation"]["active_count"], 1)
        self.assertEqual(response.body["continuation"]["stale_count"], 0)
        self.assertEqual(response.body["continuation"]["stale_agents"], [])
        self.assertEqual(demobot["work"]["current"], 2)
        self.assertEqual(vesper["work"]["current"], 1)
        self.assertEqual(demobot["skills"], {"reported": True, "count": 2, "items": ["control", "recall"]})
        self.assertEqual(vesper["skills"], {"reported": False, "count": 0, "items": []})
        # Registry presentation hints pass through only as a known desk and a strict boolean.
        self.assertEqual(demobot["dashboard"], {"desk": "security", "hidden": False, "squad": False})
        self.assertEqual(vesper["dashboard"], {"desk": None, "hidden": False, "squad": False})
        self.assertEqual(
            demobot["memory"],
            {"documents": 2, "lines": 3, "bytes": 52, "curated_documents": 1, "raw_documents": 1, "session_documents": 0},
        )
        self.assertEqual(
            vesper["memory"],
            {"documents": 1, "lines": 1, "bytes": 23, "curated_documents": 0, "raw_documents": 0, "session_documents": 1},
        )
        self.assertEqual({card["kind"] for card in response.body["cards"]}, {"task", "handoff", "thread"})
        self.assertNotIn(informational.thread.id, {card["id"] for card in response.body["cards"]})
        thread_card = next(card for card in response.body["cards"] if card["kind"] == "thread")
        self.assertTrue(thread_card["pending"])
        self.assertEqual(thread_card["thread_type"], "blocker")
        self.assertEqual(next(card for card in response.body["cards"] if card["id"] == task.task.id)["lane"], "queued")
        self.assertEqual(sum(len(cards) for cards in response.body["kanban"].values()), 3)
        bounds = response.body["source"]["bounds"]
        self.assertEqual(bounds["cards_total"], 3)
        self.assertEqual(bounds["cards_returned"], 3)
        self.assertFalse(bounds["cards_truncated"])
        self.assertEqual(bounds["agents_discovered"], 3)
        self.assertEqual(bounds["agents_returned"], 2)
        self.assertEqual(bounds["agents_invalid"], 1)
        self.assertFalse(bounds["agents_truncated"])
        self.assertLessEqual(len(response.body["events"]), 100)
        serialized = json.dumps(response.body)
        self.assertNotIn("private memory marker", serialized)
        self.assertNotIn("secret raw marker", serialized)
        self.assertNotIn("private session marker", serialized)

    def test_control_plane_bounds_current_work_before_recent_history(self) -> None:
        history = [
            {
                "id": f"done-{index}",
                "kind": "thread",
                "lane": "done",
                "updated_at": f"2026-08-23T10:{index % 60:02d}:00Z",
                "owner": "demobot",
            }
            for index in range(205)
        ]
        current = {
            "id": "current-old",
            "kind": "thread",
            "lane": "queued",
            "updated_at": "2026-07-01T00:00:00Z",
            "owner": "demobot",
        }

        bounded = _bound_work_cards([*history, current], limit=200)

        self.assertEqual(len(bounded), 200)
        self.assertEqual(bounded[0]["id"], "current-old")
        self.assertIn("current-old", {card["id"] for card in bounded})
        workload, latest = _workload_by_agent([*history, current])
        self.assertEqual(
            workload["demobot"],
            {"queued": 1, "active": 0, "review": 0, "done": 205, "retired": 0, "current": 1, "total": 206, "bounded": False},
        )
        self.assertEqual(latest["demobot"], "2026-08-23T10:59:00Z")

    def test_continuation_projection_flags_stale_ack_without_exposing_body(self) -> None:
        from datetime import datetime, timezone
        from types import SimpleNamespace

        threads = [
            SimpleNamespace(
                id="thread_stale",
                type="handoff",
                target="esme",
                status="acked",
                pending=True,
                acked_at="2026-08-23T10:00:00Z",
                latest_at="2026-08-23T10:05:00Z",
                body="private execution context",
            )
        ]
        projection = _continuation_by_agent(
            threads,
            now=datetime(2026, 8, 23, 10, 30, tzinfo=timezone.utc),
            stale_seconds=900,
        )

        self.assertEqual(projection["esme"]["state"], "stale")
        self.assertEqual(projection["esme"]["stale_count"], 1)
        self.assertEqual(projection["esme"]["oldest_progress_age_seconds"], 1500)
        self.assertEqual(projection["esme"]["subjects"][0]["id"], "thread_stale")
        self.assertNotIn("body", projection["esme"]["subjects"][0])

    def test_continuation_default_stale_window_allows_hourly_progress(self) -> None:
        from datetime import datetime, timezone
        from types import SimpleNamespace

        self.assertEqual(CONTINUATION_STALE_SECONDS, 3_600)
        thread = SimpleNamespace(
            id="thread_hourly_progress",
            type="handoff",
            target="esme",
            status="acked",
            pending=True,
            acked_at="2026-08-23T10:00:00Z",
            latest_at="2026-08-23T10:00:01Z",
        )
        fresh = _continuation_by_agent(
            [thread],
            now=datetime(2026, 8, 23, 11, 0, tzinfo=timezone.utc),
        )
        stale = _continuation_by_agent(
            [thread],
            now=datetime(2026, 8, 23, 11, 0, 1, tzinfo=timezone.utc),
        )

        self.assertEqual(fresh["esme"]["stale_count"], 0)
        self.assertEqual(stale["esme"]["stale_count"], 1)

    def test_operator_summary_projects_expired_approval_without_mutating_history(self) -> None:
        from datetime import datetime, timezone
        from types import SimpleNamespace

        now = datetime(2026, 8, 23, 10, 0, tzinfo=timezone.utc)
        expired = SimpleNamespace(status="requested", expires_at="2026-08-23T09:59:59Z")
        live = SimpleNamespace(status="requested", expires_at="2026-08-23T10:00:01Z")
        naive_expired = SimpleNamespace(status="requested", expires_at="2026-08-23T09:59:59")
        consumed = SimpleNamespace(status="consumed", expires_at="2026-08-23T09:59:59Z")

        self.assertEqual(_approval_effective_status(expired, now), "expired")
        self.assertEqual(_approval_effective_status(live, now), "requested")
        self.assertEqual(_approval_effective_status(naive_expired, now), "expired")
        self.assertEqual(_approval_effective_status(consumed, now), "consumed")
        self.assertEqual(expired.status, "requested")

    def test_recall_rejects_question_longer_than_200_characters(self) -> None:
        with self.assertRaisesRegex(ValueError, "at most 200 characters"):
            recall("x" * 201, vault=VAULT)

    def test_recall_returns_compact_answer_with_sources(self) -> None:
        result = recall(
            "what did we decide about safe mcp bridge",
            vault=VAULT,
            project="demo-agent",
            max_tokens=80,
        )

        self.assertGreater(result.confidence, 0)
        self.assertEqual(result.retrieval_mode, "lexical")
        self.assertTrue(result.answer)
        self.assertTrue(result.sources)
        self.assertLessEqual(sum(len(item.split()) for item in result.answer), 80)
        self.assertTrue(any(source.path.endswith("DECISIONS.md") for source in result.sources))

    def test_recall_ignores_raw_and_archive_paths(self) -> None:
        result = recall("raw-only-marker-761", vault=VAULT, project="demo-agent")

        self.assertEqual(result.confidence, 0)
        self.assertEqual(result.sources, [])

    def test_recall_uses_semantic_aliases(self) -> None:
        result = recall(
            "which guardrail proxy protects credentials",
            vault=VAULT,
            project="demo-agent",
            max_tokens=100,
        )

        self.assertGreater(result.confidence, 0)
        self.assertTrue(any(source.path.endswith("DECISIONS.md") for source in result.sources))
        self.assertTrue(any("safe MCP bridge" in item for item in result.answer))

    def test_recall_hybrid_mode_returns_sources(self) -> None:
        result = recall(
            "safe bridge gateway credentials",
            vault=VAULT,
            project="demo-agent",
            retrieval_mode="hybrid",
        )

        self.assertEqual(result.retrieval_mode, "hybrid")
        self.assertGreater(result.confidence, 0)
        self.assertTrue(any(source.path.endswith("DECISIONS.md") for source in result.sources))

    def test_recall_uses_frontmatter_tags(self) -> None:
        result = recall("current truth", vault=VAULT, project="demo-agent")

        self.assertGreater(result.confidence, 0)
        self.assertTrue(any(source.path.endswith("STATUS.md") for source in result.sources))

    def test_cli_json_output_is_stable(self) -> None:
        from io import StringIO
        from contextlib import redirect_stdout

        out = StringIO()
        with redirect_stdout(out):
            code = main(
                [
                    "recall",
                    "live mcp endpoint",
                    "--vault",
                    str(VAULT),
                    "--project",
                    "demo-agent",
                    "--json",
                ]
            )

        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertIn("answer", payload)
        self.assertIn("cards", payload)
        self.assertIn("sources", payload)
        self.assertTrue(payload["expandable"])

    def test_cli_recall_rejects_long_question_without_traceback(self) -> None:
        from contextlib import redirect_stderr
        from io import StringIO

        err = StringIO()
        with redirect_stderr(err):
            code = main(["recall", "x" * 201, "--vault", str(VAULT)])

        self.assertEqual(code, 1)
        self.assertEqual(err.getvalue(), "error: question must be at most 200 characters\n")
        self.assertNotIn("Traceback", err.getvalue())

    def test_excerpt_reads_exact_cited_lines(self) -> None:
        result = excerpt(
            vault=VAULT,
            source_path="projects/demo-agent/DECISIONS.md",
            lines="3-12",
            max_tokens=80,
        )

        self.assertEqual(result.path, "projects/demo-agent/DECISIONS.md")
        self.assertEqual(result.lines, "3-12")
        self.assertIn("Safety Bridge Belongs", result.text)

    def test_excerpt_refuses_raw_path(self) -> None:
        with self.assertRaises(ValueError):
            excerpt(
                vault=VAULT,
                source_path="projects/demo-agent/raw/private-draft.md",
                lines="1-2",
            )

    def test_context_pack_returns_answer_and_excerpts(self) -> None:
        result = context_pack(
            "what did we decide about safe mcp bridge",
            vault=VAULT,
            project="demo-agent",
            max_tokens=160,
        )

        self.assertTrue(result.answer)
        self.assertTrue(result.cards)
        self.assertTrue(result.excerpts)
        self.assertTrue(any(item.path.endswith("DECISIONS.md") for item in result.excerpts))

    def test_recall_clamps_unbounded_limit_and_token_budget(self) -> None:
        result = recall(
            "safe mcp bridge",
            vault=VAULT,
            project="demo-agent",
            max_tokens=100_000,
            limit=100_000,
        )

        self.assertLessEqual(len(result.sources), 20)
        self.assertLessEqual(sum(len(item.split()) for item in result.answer), 2_000)

    def test_excerpt_clamps_large_line_ranges(self) -> None:
        result = excerpt(
            vault=VAULT,
            source_path="projects/demo-agent/DECISIONS.md",
            lines="1-500",
            max_tokens=100_000,
        )

        start, end = [int(part) for part in result.lines.split("-")]
        self.assertLessEqual(end - start + 1, 80)

    def test_init_vault_creates_synthetic_structure(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            result = init_vault(target)

            self.assertTrue((target / "projects/demo-agent/STATUS.md").exists())
            self.assertTrue((target / "agents/demobot/MEMORY.md").exists())
            self.assertGreater(len(result.files_created), 5)

    def test_init_vault_refuses_non_empty_target(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "existing.txt").write_text("occupied", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                init_vault(target)

    def test_demo_runs_core_checks(self) -> None:
        result = run_demo(VAULT)

        self.assertTrue(result.ok)
        self.assertEqual(
            {check["name"] for check in result.checks},
            {
                "recall",
                "context_pack",
                "forbidden_path_refused",
                "mcp_recall",
                "control_tasks",
                "control_approvals",
                "control_handoffs",
                "control_bus",
                "control_store",
                "control_api",
                "thread_war_room_loop",
                "thread_read_all",
                "health_daily_handoff",
                "health_notify_loop",
            },
        )

    def test_control_task_events_project_state(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                created = create_task(state=state, title="Review recall output", owner="demobot")
                completed = complete_task(state=state, task_id=created.task.id)
                tasks = list_tasks(state=state)
                events = read_events(state)

        self.assertEqual(created.task.status, "open")
        self.assertEqual(completed.task.status, "done")
        self.assertEqual(len(tasks.tasks), 1)
        self.assertEqual(tasks.tasks[0].status, "done")
        self.assertEqual([event.type for event in events], ["task.created", "task.completed"])
        self.assertEqual(len({event.id for event in events}), 2)

    def test_control_event_ids_do_not_collide_for_identical_events(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                post_bus_message(state=state, message="same", channel="ops", actor="demobot")
                post_bus_message(state=state, message="same", channel="ops", actor="demobot")
                events = read_events(state)

        self.assertEqual(len(events), 2)
        self.assertNotEqual(events[0].id, events[1].id)

    def test_control_unknown_task_is_rejected(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                with authority_context(Path(tmp) / "authority-vault", Path(tmp) / "events.jsonl"):
                    complete_task(state=Path(tmp) / "events.jsonl", task_id="task_missing")

    def test_control_approval_lifecycle_consumes_command_hash(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                requested = request_approval(
                    state=state,
                    command="arvyx recall demo-agent",
                    requester="demobot",
                    reason="demo",
                )
                approved = approve_request(state=state, approval_id=requested.approval.id, approver="operator")
                consumed = consume_approval(
                    state=state,
                    approval_id=requested.approval.id,
                    command="arvyx recall demo-agent",
                )
                approvals = list_approvals(state=state)

        self.assertEqual(requested.approval.status, "requested")
        self.assertEqual(approved.approval.status, "approved")
        self.assertEqual(consumed.approval.status, "consumed")
        self.assertEqual(approvals.approvals[0].status, "consumed")

    def test_control_approval_rejects_wrong_command(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                requested = request_approval(state=state, command="arvyx recall demo-agent", requester="demobot")
                approve_request(state=state, approval_id=requested.approval.id)
                with self.assertRaises(ValueError):
                    consume_approval(
                        state=state,
                        approval_id=requested.approval.id,
                        command="arvyx task done something-else",
                    )

    def test_control_approval_rejects_self_approval(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                requested = request_approval(state=state, command="arvyx recall demo-agent", requester="demobot")
                with self.assertRaises(ValueError):
                    approve_request(state=state, approval_id=requested.approval.id, approver="demobot")

    def test_control_approval_is_single_use(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                requested = request_approval(state=state, command="arvyx recall demo-agent", requester="demobot")
                approve_request(state=state, approval_id=requested.approval.id)
                consume_approval(state=state, approval_id=requested.approval.id, command="arvyx recall demo-agent")
                with self.assertRaises(ValueError):
                    consume_approval(state=state, approval_id=requested.approval.id, command="arvyx recall demo-agent")

    def test_control_approval_concurrent_consume_allows_one_success(self) -> None:
        import os
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                requested = request_approval(state=state, command="arvyx recall demo-agent", requester="demobot")
                approve_request(state=state, approval_id=requested.approval.id)
                script = (
                    "import sys\n"
                    "from pathlib import Path\n"
                    "from arvyx_control.control import consume_approval\n"
                    "from arvyx_control.replica_authority import authority_context\n"
                    # Each consumer binds the same explicit authority; a bare
                    # state path is refused before any consume is attempted.
                    "with authority_context(Path(sys.argv[3]), Path(sys.argv[1])):\n"
                    "    consume_approval(Path(sys.argv[1]), sys.argv[2], 'arvyx recall demo-agent')\n"
                )
                env = dict(os.environ)
                env["PYTHONPATH"] = str(ROOT / "packages" / "arvctl" / "src")
                processes = [
                    subprocess.Popen(
                        [sys.executable, "-c", script, str(state), requested.approval.id, str(vault)],
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    for _ in range(2)
                ]
                results = [process.communicate(timeout=10) + (process.returncode,) for process in processes]
                approvals = list_approvals(state=state)

        return_codes = [return_code for _stdout, _stderr, return_code in results]
        self.assertEqual(return_codes.count(0), 1)
        self.assertEqual(return_codes.count(1), 1)
        # The loser must lose the race, not fail authority binding or import.
        loser = next(stderr for _stdout, stderr, code in results if code == 1)
        self.assertIn("approval is not consumable", loser)
        self.assertIn("status=consumed", loser)
        self.assertEqual(approvals.approvals[0].status, "consumed")

    def test_store_sync_projects_events_to_sqlite(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                db = Path(tmp) / "control.sqlite"
                task = create_task(state=state, title="Persist task state", owner="demobot")
                complete_task(state=state, task_id=task.task.id)
                approval = request_approval(state=state, command="arvyx recall demo-agent", requester="demobot")
                approve_request(state=state, approval_id=approval.approval.id)
                consume_approval(state=state, approval_id=approval.approval.id, command="arvyx recall demo-agent")
                handoff = create_handoff(state=state, title="Persist handoff state", from_agent="demobot")
                accept_handoff(state=state, handoff_id=handoff.handoff.id)
                complete_handoff(state=state, handoff_id=handoff.handoff.id)
                post_bus_message(state=state, message="Persist bus state", channel="ops", actor="demobot")

                result = sync_sqlite(state=state, db=db)
                with closing(sqlite3.connect(db)) as conn:
                    task_status = conn.execute("SELECT status FROM tasks WHERE id = ?", (task.task.id,)).fetchone()[0]
                    approval_status = conn.execute(
                        "SELECT status FROM approvals WHERE id = ?",
                        (approval.approval.id,),
                    ).fetchone()[0]
                    handoff_status = conn.execute(
                        "SELECT status FROM handoffs WHERE id = ?",
                        (handoff.handoff.id,),
                    ).fetchone()[0]
                    bus_message = conn.execute(
                        "SELECT message FROM bus_messages WHERE channel = ?",
                        ("ops",),
                    ).fetchone()[0]

        self.assertEqual(result.events, 9)
        self.assertEqual(result.source_events, 9)
        self.assertEqual(result.tasks, 1)
        self.assertEqual(result.approvals, 1)
        self.assertEqual(result.handoffs, 1)
        self.assertEqual(result.bus_messages, 1)
        self.assertEqual(result.retention, "sqlite-events:all")
        self.assertEqual(task_status, "done")
        self.assertEqual(approval_status, "consumed")
        self.assertEqual(handoff_status, "completed")
        self.assertEqual(bus_message, "Persist bus state")

    def test_store_sync_can_bound_projected_event_retention(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                db = Path(tmp) / "control.sqlite"
                task = create_task(state=state, title="Retained projection task", owner="demobot")
                complete_task(state=state, task_id=task.task.id)
                post_bus_message(state=state, message="Retained recent event", channel="ops", actor="demobot")

                result = sync_sqlite(state=state, db=db, retain_events=1)
                with closing(sqlite3.connect(db)) as conn:
                    event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                    event_type = conn.execute("SELECT type FROM events").fetchone()[0]
                    task_status = conn.execute("SELECT status FROM tasks WHERE id = ?", (task.task.id,)).fetchone()[0]

        self.assertEqual(result.events, 1)
        self.assertEqual(result.source_events, 3)
        self.assertEqual(result.retention, "sqlite-events:last-1")
        self.assertEqual(event_count, 1)
        self.assertEqual(event_type, "bus.message")
        self.assertEqual(task_status, "done")

    def test_store_sync_rejects_invalid_retention(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            db = Path(tmp) / "control.sqlite"

            with self.assertRaises(ValueError):
                sync_sqlite(state=state, db=db, retain_events=0)

    def test_store_manifest_summarizes_append_only_log(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                create_task(state=state, title="Manifest task", owner="demobot")
                post_bus_message(state=state, message="Manifest bus", channel="ops", actor="demobot")

                manifest = manifest_state(state)

        self.assertEqual(manifest.events, 2)
        self.assertEqual(manifest.event_types, {"bus.message": 1, "task.created": 1})
        self.assertEqual(len(manifest.sha256), 64)
        self.assertEqual(manifest.retention, "append-only-jsonl")

    def test_cli_store_manifest_json_output(self) -> None:
        import tempfile
        from contextlib import redirect_stdout
        from io import StringIO

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                create_task(state=state, title="CLI manifest task", owner="demobot")
                out = StringIO()

                with redirect_stdout(out):
                    code = main(["--authority-vault", str(vault), "store", "manifest", "--state", str(state), "--json"])

        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["events"], 1)
        self.assertEqual(payload["event_types"], {"task.created": 1})
        self.assertEqual(payload["retention"], "append-only-jsonl")

    def test_api_health_and_memory_recall(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            health = handle_api_request("GET", "/health", {}, vault=VAULT, state=state, allow_unauthenticated_demo=True)
            memory = handle_api_request(
                "POST",
                "/memory/recall",
                {
                    "question": "which guardrail proxy protects credentials",
                    "project": "demo-agent",
                    "max_tokens": 100,
                },
                vault=VAULT,
                state=state, allow_unauthenticated_demo=True,)

        self.assertEqual(health.status, 200)
        self.assertTrue(health.body["ok"])
        self.assertEqual(memory.status, 200)
        self.assertTrue(memory.body["answer"])
        self.assertTrue(memory.body["sources"])

    def test_api_bearer_auth_protects_memory_and_control_routes(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            blocked = handle_api_request(
                "POST",
                "/memory/recall",
                {"question": "safe bridge", "project": "demo-agent"},
                vault=VAULT,
                state=state,
                bearer_secret="demo-secret",
            )
            allowed = handle_api_request(
                "POST",
                "/memory/recall",
                {"question": "safe bridge", "project": "demo-agent"},
                vault=VAULT,
                state=state,
                bearer_secret="demo-secret",
                authorization="Bearer demo-secret",
            )

        self.assertEqual(blocked.status, 401)
        self.assertEqual(blocked.body["error"], "unauthorized")
        self.assertEqual(allowed.status, 200)
        self.assertTrue(allowed.body["answer"])

    def test_api_dashboard_route_returns_control_plane_html(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            response = handle_api_request("GET", "/dashboard", {}, vault=VAULT, state=state, allow_unauthenticated_demo=True)

        self.assertEqual(response.status, 200)
        self.assertEqual(response.content_type, "text/html; charset=utf-8")
        self.assertIn("Arvyx Control Plane", response.body)
        self.assertIn("Squad Orbit", response.body)
        self.assertIn("Work Board", response.body)
        self.assertIn("Signal Room", response.body)
        self.assertIn("Memory Atlas & Skills", response.body)
        self.assertIn("Governance Rail", response.body)
        self.assertIn('id="agent-orbit"', response.body)
        self.assertIn('id="kanban"', response.body)
        self.assertIn('api("/control-plane")', response.body)
        self.assertIn("api(summaryPath())", response.body)
        self.assertIn("visibilitychange", response.body)
        self.assertIn("retryFailures", response.body)
        self.assertIn("Math.min(60000", response.body)
        self.assertIn("summaryPath", response.body)
        self.assertIn('fetchAudit()', response.body)
        self.assertIn('fetch("/audit/events?limit=25"', response.body)
        self.assertIn('state: audit.chain?.ok === true ? "ok" : "broken"', response.body)
        self.assertIn("UNKNOWN — operator token required", response.body)
        self.assertIn("UNAVAILABLE — audit chain not checked", response.body)
        self.assertNotIn("Integrity monitored via /audit/events", response.body)
        self.assertIn("sessionStorage.setItem", response.body)
        self.assertIn('localStorage.removeItem("arvyx_bearer")', response.body)
        self.assertNotIn('localStorage.setItem("arvyx_bearer"', response.body)
        self.assertIn("innerWidth <= 600 && agents.length > 6", response.body)
        self.assertIn("Complete within declared bounds", response.body)
        self.assertIn("bounds.agents_invalid", response.body)
        self.assertIn("global condition codes · not delivery records", response.body)
        self.assertNotIn("global outbox · continuation watchdog", response.body)
        self.assertIn("owned by ${selectedAgent}", response.body)
        self.assertIn("Mutation failed:", response.body)
        self.assertIn("crypto.getRandomValues", response.body)
        self.assertIn("@media (prefers-reduced-motion: reduce)", response.body)
        self.assertIn("textContent", response.body)
        self.assertNotIn("innerHTML", response.body)
        self.assertNotIn("outerHTML", response.body)
        self.assertNotIn("insertAdjacentHTML", response.body)
        self.assertNotIn("document.write", response.body)
        self.assertNotIn("eval(", response.body)
        self.assertNotIn("new Function", response.body)
        self.assertNotIn("srcdoc", response.body)
        self.assertNotIn("<script src=", response.body)
        for marker in (
            "create-task",
            "request-approval",
            "create-handoff",
            "post-bus",
            "run-recall",
            "select-handoffs",
            "bulk-accept",
            "bulk-review",
            "bulk-complete",
            "arvyx_dashboard_preferences",
            "encodeURIComponent",
            '"accept"',
            '"review"',
            '"complete"',
        ):
            self.assertIn(marker, response.body)

    def test_api_summary_reports_operator_state(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            shutil.copytree(VAULT, vault, dirs_exist_ok=True)
            with authority_context(vault, state):
                create_task(state=state, title="Review summary", owner="demobot")
                request_approval(state=state, command="arvyx readiness --json", requester="demobot")
                create_handoff(state=state, title="Continue summary", from_agent="demobot", to_agent="operator")
                post_bus_message(state=state, message="Summary bus", channel="ops", actor="demobot")
                response = handle_api_request(
                    "GET",
                    "/summary",
                    {},
                    vault=vault,
                    state=state,
                    mcp_profile="operator", bearer_secret="summary-fixture-secret",
                    authorization="Bearer summary-fixture-secret",)

        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["counts"]["tasks"]["open"], 1)
        self.assertEqual(response.body["counts"]["approvals"]["requested"], 1)
        self.assertEqual(response.body["counts"]["handoffs"]["open"], 1)
        self.assertEqual(response.body["counts"]["bus_messages"]["total"], 1)
        self.assertEqual(response.body["mcp_profile"], "operator")
        self.assertIn("control.task_create", response.body["mcp_tools"])
        self.assertEqual(response.body["store"]["source"]["events"], 4)
        self.assertEqual(response.body["store"]["source"]["retention"], "append-only-jsonl")
        self.assertEqual(response.body["store"]["projection"]["retention"], "sqlite-events:configurable")
        self.assertEqual(response.body["store"]["projection"]["bounded_by"], "store sync --retain-events N")
        self.assertEqual(
            [preset["id"] for preset in response.body["handoff_queue"]["presets"]],
            ["operator-open", "operator-review", "ready-to-complete"],
        )
        self.assertEqual(response.body["handoff_queue"]["workload"]["assignees"][0]["agent"], "operator")
        self.assertEqual(response.body["handoff_queue"]["workload"]["assignees"][0]["open"], 1)

    def test_api_summary_reports_posture_and_memory_queue(self) -> None:
        import tempfile

        from arvyx_control.vault import init_vault
        from arvyx_control.writes import refine_memory, suggest_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            log = Path(tmp) / "audit.jsonl"
            suggestion = suggest_memory(
                vault=vault, project="demo-agent", title="A", content="alpha content here", author="demobot"
            )
            suggest_memory(vault=vault, project="demo-agent", title="B", content="beta content here", author="demobot")
            refine_memory(vault=vault, project="demo-agent", source_path=suggestion.path, refined_by="vesper")
            response = handle_api_request(
                "GET",
                "/summary",
                {},
                vault=vault,
                state=state,
                audit_log=log,
                mcp_profile="operator",
                bearer_secret="summary-fixture-secret",
                authorization="Bearer summary-fixture-secret",
            )
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["memory_queue"]["pending"], 1)
        self.assertEqual(response.body["memory_queue"]["refining"], 1)
        self.assertEqual(response.body["memory_queue"]["by_project"]["demo-agent"], {"pending": 1, "refining": 1})
        posture = response.body["posture"]
        self.assertEqual(posture["provider"]["mcp_profile"], "operator")
        self.assertEqual(posture["fallback"]["role"], "primary")
        self.assertTrue(posture["hardening"]["secret_redaction"])
        self.assertEqual(posture["hardening"]["unauthenticated_scopes"], ["memory.read"])

    def test_api_audit_events_browser_and_scope(self) -> None:
        import tempfile

        from arvyx_control.vault import init_vault

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            log = Path(tmp) / "audit.jsonl"
            handle_api_request(
                "POST",
                "/memory/recall",
                {"question": "alpha", "project": "demo-agent"},
                vault=vault,
                state=state,
                audit_log=log,
                allow_unauthenticated_demo=True,
            )
            # denied control write still lands an audited record
            handle_api_request("POST", "/tasks", {"title": "nope"}, vault=vault, state=state, audit_log=log)
            # reading the audit browser needs control.read: unauthenticated is refused
            denied = handle_api_request("GET", "/audit/events", {}, vault=vault, state=state, audit_log=log)
            self.assertEqual(denied.status, 401)
            allowed = handle_api_request(
                "GET",
                "/audit/events?limit=10",
                {},
                vault=vault,
                state=state,
                audit_log=log,
                allow_unauthenticated_demo=True,
            )
        self.assertEqual(allowed.status, 200)
        self.assertTrue(allowed.body["chain"]["ok"])
        routes = [event.get("route") for event in allowed.body["events"]]
        self.assertIn("/memory/recall", routes)
        self.assertIn("/tasks", routes)
        # chain hashes are never exposed in the browse projection
        self.assertTrue(all("hash" not in event and "prev_hash" not in event for event in allowed.body["events"]))

    def test_api_summary_filters_handoffs_and_store_window(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            shutil.copytree(VAULT, vault, dirs_exist_ok=True)
            with authority_context(vault, state):
                create_handoff(state=state, title="Open handoff", from_agent="demobot", to_agent="operator")
                reviewed_handoff = create_handoff(
                    state=state,
                    title="Reviewed handoff",
                    from_agent="demobot",
                    to_agent="operator",
                )
                accept_handoff(state=state, handoff_id=reviewed_handoff.handoff.id)
                review_handoff(state=state, handoff_id=reviewed_handoff.handoff.id, reviewer="reviewer")
                summary = handle_api_request(
                    "GET",
                    "/summary?handoff_status=reviewed&handoff_to_agent=operator&handoff_sla_hours=1&retain_events=2",
                    {},
                    vault=vault,
                    state=state, bearer_secret="summary-operator-fixture", authorization="Bearer summary-operator-fixture",)
                handoffs = handle_api_request(
                    "GET",
                    "/handoffs?status=reviewed&to_agent=operator",
                    {},
                    vault=vault,
                    state=state, bearer_secret="summary-operator-fixture", authorization="Bearer summary-operator-fixture",)

        self.assertEqual(summary.status, 200)
        self.assertEqual(summary.body["filters"]["handoff_status"], "reviewed")
        self.assertEqual(summary.body["filters"]["handoff_to_agent"], "operator")
        self.assertEqual(summary.body["filters"]["handoff_sla_hours"], 1)
        self.assertEqual(summary.body["filters"]["retain_events"], 2)
        self.assertEqual(summary.body["store"]["projection"]["retention"], "sqlite-events:last-2")
        self.assertEqual(summary.body["counts"]["handoffs"]["open"], 1)
        self.assertEqual(summary.body["counts"]["handoffs"]["reviewed"], 1)
        self.assertEqual([handoff["status"] for handoff in summary.body["recent"]["handoffs"]], ["reviewed"])
        self.assertEqual([handoff["to_agent"] for handoff in summary.body["recent"]["handoffs"]], ["operator"])
        self.assertEqual(summary.body["recent"]["handoffs"][0]["sla_hours"], 1)
        self.assertIn(summary.body["recent"]["handoffs"][0]["sla_status"], {"within", "breached"})
        self.assertIn("age_hours", summary.body["recent"]["handoffs"][0])
        self.assertEqual(summary.body["handoff_queue"]["workload"]["reviewers"][0]["reviewer"], "reviewer")
        self.assertEqual(summary.body["handoff_queue"]["workload"]["reviewers"][0]["approved"], 1)
        self.assertEqual([handoff["status"] for handoff in handoffs.body["handoffs"]], ["reviewed"])

    def test_api_summary_rejects_invalid_store_window(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            response = handle_api_request("GET", "/summary?retain_events=0", {}, vault=VAULT, state=state, bearer_secret="summary-operator-fixture", authorization="Bearer summary-operator-fixture")

        self.assertEqual(response.status, 400)
        self.assertIn("retain_events", response.body["error"])

    def test_api_summary_limits_handoff_queue(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            shutil.copytree(VAULT, vault, dirs_exist_ok=True)
            with authority_context(vault, state):
                for index in range(3):
                    create_handoff(
                        state=state,
                        title=f"Queued handoff {index}",
                        from_agent="demobot",
                        to_agent="operator",
                    )
                response = handle_api_request("GET", "/summary?handoff_limit=2", {}, vault=vault, state=state, bearer_secret="summary-operator-fixture", authorization="Bearer summary-operator-fixture")

        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["filters"]["handoff_limit"], 2)
        self.assertEqual(response.body["counts"]["handoffs"]["open"], 3)
        self.assertEqual(len(response.body["recent"]["handoffs"]), 2)

    def test_api_summary_rejects_invalid_handoff_queue_limit(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            response = handle_api_request("GET", "/summary?handoff_limit=zero", {}, vault=VAULT, state=state, bearer_secret="summary-operator-fixture", authorization="Bearer summary-operator-fixture")

        self.assertEqual(response.status, 400)
        self.assertIn("handoff_limit", response.body["error"])

    def test_api_summary_filters_handoff_queue_by_assignee(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            shutil.copytree(VAULT, vault, dirs_exist_ok=True)
            with authority_context(vault, state):
                create_handoff(state=state, title="Operator handoff", from_agent="demobot", to_agent="operator")
                create_handoff(state=state, title="Vesper handoff", from_agent="demobot", to_agent="vesper")
                summary = handle_api_request("GET", "/summary?handoff_to_agent=vesper", {}, vault=vault, state=state, bearer_secret="summary-operator-fixture", authorization="Bearer summary-operator-fixture")
                handoffs = handle_api_request("GET", "/handoffs?to_agent=vesper", {}, vault=vault, state=state, bearer_secret="summary-operator-fixture", authorization="Bearer summary-operator-fixture")

        self.assertEqual(summary.status, 200)
        self.assertEqual(summary.body["filters"]["handoff_to_agent"], "vesper")
        self.assertEqual([handoff["to_agent"] for handoff in summary.body["recent"]["handoffs"]], ["vesper"])
        self.assertEqual([handoff["title"] for handoff in handoffs.body["handoffs"]], ["Vesper handoff"])

    def test_api_summary_rejects_invalid_handoff_sla_window(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            response = handle_api_request("GET", "/summary?handoff_sla_hours=0", {}, vault=VAULT, state=state, bearer_secret="summary-operator-fixture", authorization="Bearer summary-operator-fixture")

        self.assertEqual(response.status, 400)
        self.assertIn("handoff_sla_hours", response.body["error"])

    def test_api_auth_keeps_dashboard_public_and_protects_api_routes(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            dashboard = handle_api_request(
                "GET",
                "/dashboard",
                {},
                vault=VAULT,
                state=state,
                bearer_secret="local-secret",
            )
            denied = handle_api_request(
                "POST",
                "/memory/recall",
                {"question": "safe mcp bridge", "project": "demo-agent"},
                vault=VAULT,
                state=state,
                bearer_secret="local-secret",
            )
            allowed = handle_api_request(
                "POST",
                "/memory/recall",
                {"question": "safe mcp bridge", "project": "demo-agent"},
                vault=VAULT,
                state=state,
                bearer_secret="local-secret",
                authorization="Bearer local-secret",
            )

        self.assertEqual(dashboard.status, 200)
        self.assertIn("Arvyx Control Plane", dashboard.body)
        self.assertEqual(denied.status, 401)
        self.assertEqual(allowed.status, 200)
        self.assertTrue(allowed.body["answer"])

    def test_api_auth_protects_summary_route(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            denied = handle_api_request(
                "GET",
                "/summary",
                {},
                vault=VAULT,
                state=state,
                bearer_secret="local-secret",
            )
            allowed = handle_api_request(
                "GET",
                "/summary",
                {},
                vault=VAULT,
                state=state,
                bearer_secret="local-secret",
                authorization="Bearer local-secret",
            )

        self.assertEqual(denied.status, 401)
        self.assertEqual(allowed.status, 200)
        self.assertTrue(allowed.body["ok"])

    def test_api_task_lifecycle(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            created = handle_api_request(
                "POST",
                "/tasks",
                {"title": "Review API lifecycle", "owner": "demobot"},
                vault=VAULT,
                state=state, allow_unauthenticated_demo=True,)
            task_id = created.body["task"]["id"]
            done = handle_api_request("POST", f"/tasks/{task_id}/done", {}, vault=VAULT, state=state, allow_unauthenticated_demo=True)
            listed = handle_api_request("GET", "/tasks", {}, vault=VAULT, state=state, allow_unauthenticated_demo=True)

        self.assertEqual(created.status, 201)
        self.assertEqual(done.body["task"]["status"], "done")
        self.assertEqual(listed.body["tasks"][0]["status"], "done")

    def test_api_task_create_validates_title(self) -> None:
        invalid_bodies = ({}, {"title": ""}, {"title": " \t\n "}, {"title": 123})

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            for body in invalid_bodies:
                with self.subTest(body=body):
                    response = handle_api_request(
                        "POST",
                        "/tasks",
                        {"owner": "demobot", **body},
                        vault=VAULT,
                        state=state,
                        allow_unauthenticated_demo=True,
                    )
                    self.assertEqual(response.status, 400)
                    self.assertIn("title", response.body["error"])

            valid = handle_api_request(
                "POST",
                "/tasks",
                {"title": "Review validated API task", "owner": "demobot"},
                vault=VAULT,
                state=state,
                allow_unauthenticated_demo=True,
            )

        self.assertEqual(valid.status, 201)
        self.assertEqual(valid.body["task"]["title"], "Review validated API task")

    def test_api_approval_rejects_wrong_command(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            requested = handle_api_request(
                "POST",
                "/approvals/request",
                {"command": "arvyx recall demo-agent", "requester": "demobot"},
                vault=VAULT,
                state=state, allow_unauthenticated_demo=True,)
            approval_id = requested.body["approval"]["id"]
            handle_api_request("POST", f"/approvals/{approval_id}/approve", {}, vault=VAULT, state=state, allow_unauthenticated_demo=True)
            rejected = handle_api_request(
                "POST",
                f"/approvals/{approval_id}/consume",
                {"command": "arvyx task done something"},
                vault=VAULT,
                state=state, allow_unauthenticated_demo=True,)

        self.assertEqual(rejected.status, 400)
        self.assertIn("command hash", rejected.body["error"])

    def test_api_approval_rejects_self_approval(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            requested = handle_api_request(
                "POST",
                "/approvals/request",
                {"command": "arvyx recall demo-agent", "requester": "demobot"},
                vault=VAULT,
                state=state, allow_unauthenticated_demo=True,)
            approval_id = requested.body["approval"]["id"]
            rejected = handle_api_request(
                "POST",
                f"/approvals/{approval_id}/approve",
                {"approver": "demobot"},
                vault=VAULT,
                state=state, allow_unauthenticated_demo=True,)

        self.assertEqual(rejected.status, 400)
        self.assertIn("requester cannot approve", rejected.body["error"])

    def test_api_http_server_health(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            shutil.copytree(VAULT, vault, dirs_exist_ok=True)
            with authority_context(vault, state):
                server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(vault=vault, state=state))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    port = server.server_address[1]
                    with urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as response:
                        payload = json.loads(response.read().decode("utf-8"))
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

        self.assertEqual(payload["status"], 200)
        self.assertTrue(payload["body"]["ok"])

    def test_api_http_server_dashboard(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            shutil.copytree(VAULT, vault, dirs_exist_ok=True)
            with authority_context(vault, state):
                server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(vault=vault, state=state))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    port = server.server_address[1]
                    with urlopen(f"http://127.0.0.1:{port}/dashboard", timeout=5) as response:
                        html = response.read().decode("utf-8")
                        content_type = response.headers["Content-Type"]
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

        self.assertIn("text/html", content_type)
        self.assertIn("Arvyx Control Plane", html)
        self.assertIn('id="kanban"', html)
        # Desk roster and hidden agents are registry data, never agent ids in the page.
        self.assertIn("function planDesks(agents)", html)
        self.assertIn("return deskPlan().hidden.has(", html)
        self.assertIn("function itemIsVisible(item)", html)
        self.assertNotIn("excludedAgentIds", html)
        self.assertNotIn("roleMeta", html)
        self.assertIn('@media (max-width:1500px)', html)
        self.assertNotIn('@media (max-width:1200px)', html)
        self.assertNotIn('@media (max-width:1400px)', html)
        self.assertIn('.agent-desk.attention', html)
        self.assertIn('tone: "var(--amber)", attention: true', html)
        self.assertIn('"global condition codes · not delivery records"', html)
        self.assertNotIn('staleContinuations && outboxIssues', html)
        self.assertIn('b.style.setProperty("--tone", state.tone)', html)
        self.assertIn('row.style.setProperty("--tone", state.tone)', html)

    def test_cli_api_call_accepts_idempotency_key(self) -> None:
        from contextlib import redirect_stdout
        from io import StringIO

        with tempfile.TemporaryDirectory() as tmp:
            out = StringIO()
            with redirect_stdout(out):
                code = main(
                    [
                        "api-call",
                        "POST",
                        "/tasks",
                        "--body",
                        '{"title":"cli idempotent task","owner":"demobot"}',
                        "--vault",
                        str(Path(tmp) / "vault"),
                        "--state",
                        str(Path(tmp) / "events.jsonl"),
                        "--allow-unauthenticated-demo",
                        "--idempotency-key",
                        "cli-api-call-idempotency-0001",
                    ]
                )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["status"], 201)

    def test_api_mcp_route_returns_raw_json_rpc(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            response = handle_api_request(
                "POST",
                "/mcp",
                {"jsonrpc": "2.0", "id": "tools", "method": "tools/list"},
                vault=VAULT,
                state=state, allow_unauthenticated_demo=True,)
            payload = json.loads(response.body)

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["jsonrpc"], "2.0")
        self.assertEqual(payload["id"], "tools")
        self.assertIn("tools", payload["result"])

    def test_mcp_mutation_schemas_require_idempotency_key(self) -> None:
        from arvyx_control.mcp import MUTATING_TOOL_NAMES, handle_request

        with tempfile.TemporaryDirectory() as tmp:
            response = handle_request(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                vault=Path(tmp) / "vault",
                allowed_tools=set(MUTATING_TOOL_NAMES),
            )
        assert response is not None
        tools = {tool["name"]: tool for tool in response["result"]["tools"]}
        self.assertEqual(set(tools), set(MUTATING_TOOL_NAMES))
        for name, tool in tools.items():
            with self.subTest(tool=name):
                schema = tool["inputSchema"]
                self.assertIn("idempotency_key", schema["properties"])
                self.assertIn("idempotency_key", schema["required"])

    def test_api_mcp_accepts_body_idempotency_key_for_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = root / "vault"
            init_vault(vault)
            response = handle_api_request(
                method="POST",
                path="/mcp",
                body={
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {
                        "name": "control.task_create",
                        "arguments": {
                            "title": "body-key task",
                            "owner": "operator",
                            "idempotency_key": "-".join(("mcp", "body", "idempotency", "0001")),
                        },
                    },
                },
                vault=vault,
                state=root / "events.jsonl",
                allow_unauthenticated_demo=True,
                mcp_profile="operator",
            )
        self.assertEqual(response.status, 200)
        self.assertIn("result", response.body)

    def test_api_http_server_mcp_route_returns_raw_json_rpc(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            shutil.copytree(VAULT, vault, dirs_exist_ok=True)
            with authority_context(vault, state):
                server = ThreadingHTTPServer(
                    ("127.0.0.1", 0),
                    make_handler(vault=vault, state=state, allow_unauthenticated_demo=True),
                )
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    port = server.server_address[1]
                    body = json.dumps({"jsonrpc": "2.0", "id": "tools", "method": "tools/list"}).encode("utf-8")
                    request = Request(
                        f"http://127.0.0.1:{port}/mcp",
                        data=body,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urlopen(request, timeout=5) as response:
                        payload = json.loads(response.read().decode("utf-8"))
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

        self.assertEqual(payload["jsonrpc"], "2.0")
        self.assertIn("tools", payload["result"])

    def test_api_http_server_enforces_bearer_auth_when_configured(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            shutil.copytree(VAULT, vault, dirs_exist_ok=True)
            with authority_context(vault, state):
                server = ThreadingHTTPServer(
                    ("127.0.0.1", 0),
                    make_handler(vault=vault, state=state, bearer_secret="demo-secret"),
                )
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    port = server.server_address[1]
                    body = json.dumps({"question": "safe bridge", "project": "demo-agent"}).encode("utf-8")
                    blocked_request = Request(
                        f"http://127.0.0.1:{port}/memory/recall",
                        data=body,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with self.assertRaises(HTTPError) as raised:
                        urlopen(blocked_request, timeout=5)
                    allowed_request = Request(
                        f"http://127.0.0.1:{port}/memory/recall",
                        data=body,
                        headers={"Content-Type": "application/json", "Authorization": "Bearer demo-secret"},
                        method="POST",
                    )
                    with urlopen(allowed_request, timeout=5) as response:
                        payload = json.loads(response.read().decode("utf-8"))
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

        self.assertEqual(raised.exception.code, 401)
        self.assertEqual(payload["status"], 200)
        self.assertTrue(payload["body"]["answer"])

    def test_api_http_server_rejects_unauthenticated_before_reading_body(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            shutil.copytree(VAULT, vault, dirs_exist_ok=True)
            with authority_context(vault, state):
                server = ThreadingHTTPServer(
                    ("127.0.0.1", 0),
                    make_handler(vault=vault, state=state, bearer_secret="demo-secret"),
                )
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    port = server.server_address[1]
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                        line_end = bytes((13, 10))
                        sock.sendall(
                            line_end.join(
                                (
                                    b"POST /memory/recall HTTP/1.1",
                                    b"Host: 127.0.0.1",
                                    b"Content-Type: application/json",
                                    b"Content-Length: 100",
                                )
                            )
                            + line_end * 2
                        )
                        sock.settimeout(0.5)
                        response = sock.recv(256).decode("utf-8", errors="replace")
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

        self.assertIn("401", response.splitlines()[0])

    def test_api_http_server_preauthorizes_agent_only_and_public_get_paths(self) -> None:
        import tempfile

        scenarios = [(None, "/tasks"), ("demo-secret", "/health")]
        for shared_secret, route in scenarios:
            with self.subTest(shared_secret=bool(shared_secret), route=route), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / "events.jsonl"
                vault = Path(tmp) / "authority-vault"
                vault.mkdir(exist_ok=True)
                shutil.copytree(VAULT, vault, dirs_exist_ok=True)
                with authority_context(vault, state):
                    server = ThreadingHTTPServer(
                        ("127.0.0.1", 0),
                        make_handler(vault=vault, state=state, bearer_secret=shared_secret),
                    )
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    try:
                        port = server.server_address[1]
                        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                            line_end = bytes((13, 10))
                            sock.sendall(
                                line_end.join(
                                    (
                                        f"POST {route} HTTP/1.1".encode("ascii"),
                                        b"Host: 127.0.0.1",
                                        b"Content-Length: 100",
                                    )
                                )
                                + line_end * 2
                            )
                            sock.settimeout(0.5)
                            response = sock.recv(256).decode("utf-8", errors="replace")
                    finally:
                        server.shutdown()
                        server.server_close()
                        thread.join(timeout=5)
                    self.assertIn("401", response.splitlines()[0])

    def test_api_http_server_preauthorizes_token_only_mcp_before_body(self) -> None:
        import tempfile

        from arvyx_control.auth import issue_token
        from arvyx_control.vault import init_vault

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            issue_token(vault, "demobot", scopes=["memory.read"])
            state = Path(tmp) / "events.jsonl"
            with authority_context(vault, state):
                server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(vault=vault, state=state))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    port = server.server_address[1]
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                        line_end = bytes((13, 10))
                        sock.sendall(
                            line_end.join(
                                (
                                    b"POST /mcp HTTP/1.1",
                                    b"Host: 127.0.0.1",
                                    b"Content-Length: 100",
                                )
                            )
                            + line_end * 2
                        )
                        sock.settimeout(0.5)
                        response = sock.recv(256).decode("utf-8", errors="replace")
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)
        self.assertIn("401", response.splitlines()[0])

    def test_api_http_server_rejects_oversized_body(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            shutil.copytree(VAULT, vault, dirs_exist_ok=True)
            with authority_context(vault, state):
                server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(vault=vault, state=state))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    port = server.server_address[1]
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                        sock.sendall(
                            b"POST /memory/recall HTTP/1.1\r\n"
                            b"Host: 127.0.0.1\r\n"
                            b"Content-Type: application/json\r\n"
                            + f"Content-Length: {MAX_BODY_BYTES + 1}\r\n".encode("ascii")
                            + b"\r\n{}"
                        )
                        response = sock.recv(256).decode("utf-8", errors="replace")
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

        self.assertIn("413", response.splitlines()[0])

    def test_api_http_server_rejects_invalid_content_length(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            shutil.copytree(VAULT, vault, dirs_exist_ok=True)
            with authority_context(vault, state):
                server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(vault=vault, state=state))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    port = server.server_address[1]
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                        sock.sendall(
                            b"POST /memory/recall HTTP/1.1\r\n"
                            b"Host: 127.0.0.1\r\n"
                            b"Content-Type: application/json\r\n"
                            b"Content-Length: nope\r\n"
                            b"\r\n{}"
                        )
                        response = sock.recv(256).decode("utf-8", errors="replace")
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

        self.assertIn("400", response.splitlines()[0])

    def _raw_post(self, body: bytes, content_length: bytes) -> str:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            shutil.copytree(VAULT, vault, dirs_exist_ok=True)
            with authority_context(vault, state):
                server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(vault=vault, state=state))
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    port = server.server_address[1]
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                        sock.sendall(
                            b"POST /memory/recall HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                            b"Content-Type: application/json\r\nContent-Length: " + content_length + b"\r\n\r\n" + body
                        )
                        sock.settimeout(5)
                        return sock.recv(512).decode("utf-8", errors="replace")
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

    def test_api_rejects_negative_content_length(self) -> None:
        # -1 slips past the size cap and makes read(-1) drain the whole
        # connection into memory (OOM DoS); it must be refused
        response = self._raw_post(b"A" * 100, b"-1")
        self.assertIn("413", response.splitlines()[0])

    def test_api_rejects_non_utf8_body(self) -> None:
        response = self._raw_post(b"\xff\xfe\xff", b"3")
        self.assertIn("400", response.splitlines()[0])

    def test_api_rejects_deeply_nested_json(self) -> None:
        payload = b"[" * 3000 + b"]" * 3000
        response = self._raw_post(payload, str(len(payload)).encode("ascii"))
        self.assertIn("400", response.splitlines()[0])

    def test_store_sync_tolerates_duplicate_event_id(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                create_task(state=state, title="one", owner="demobot")
                line = state.read_text(encoding="utf-8").strip()
                state.write_text(line + "\n" + line + "\n", encoding="utf-8")  # exact duplicate event
                db = Path(tmp) / "control.sqlite"
                result = sync_sqlite(state=state, db=db, retain_events=10)  # must not raise
                self.assertTrue(db.is_file())
                self.assertEqual(result.events, 1)

    def test_excerpt_outside_vault_is_not_an_existence_oracle(self) -> None:
        import os

        from arvyx_control.recall import _resolve_source_path

        up = "../" * 8
        existing = up + ("Windows/win.ini" if os.name == "nt" else "etc/hosts")
        missing = up + "no/such/host/file/xyz123"
        with self.assertRaises(ValueError):
            _resolve_source_path(VAULT, existing)
        with self.assertRaises(ValueError):
            _resolve_source_path(VAULT, missing)  # same rejection whether or not it exists

    def test_context_pack_tolerates_an_excerpt_failure(self) -> None:
        from unittest import mock

        import arvyx_control.recall as recall_module

        real_excerpt = recall_module.excerpt
        calls = {"n": 0}

        def flaky_excerpt(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise ValueError("refusing to read outside vault")
            return real_excerpt(*args, **kwargs)

        with mock.patch.object(recall_module, "excerpt", flaky_excerpt):
            pack = context_pack(question="safe mcp bridge", vault=VAULT, project="demo-agent")
        # the failing source is skipped, the pack still returns
        self.assertTrue(pack.answer)

    def test_serve_api_refuses_non_loopback_without_auth(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            shutil.copytree(VAULT, vault, dirs_exist_ok=True)
            with authority_context(vault, state):
                routes = ROOT / "config" / "agent-delivery-routes.example.json"
                with self.assertRaisesRegex(ValueError, "refusing to bind non-loopback"):
                    serve_api(
                        host="0.0.0.0",
                        port=0,
                        vault=vault,
                        state=state,
                        delivery_routes=routes,
                    )

    def test_serve_api_refuses_non_loopback_unauthenticated_demo_even_with_auth(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            shutil.copytree(VAULT, vault, dirs_exist_ok=True)
            with authority_context(vault, state):
                routes = ROOT / "config" / "agent-delivery-routes.example.json"
                with self.assertRaisesRegex(ValueError, "loopback-only"):
                    serve_api(
                        host="0.0.0.0",
                        port=0,
                        vault=vault,
                        state=state,
                        bearer_secret="synthetic-test-secret",
                        allow_unauthenticated_demo=True,
                        delivery_routes=routes,
                    )

    def test_control_handoff_lifecycle_projects_state(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                created = create_handoff(
                    state=state,
                    title="Continue release gate review",
                    from_agent="demobot",
                    to_agent="operator",
                    summary="Check audit docs before public release.",
                )
                accepted = accept_handoff(state=state, handoff_id=created.handoff.id)
                reviewed = review_handoff(
                    state=state,
                    handoff_id=created.handoff.id,
                    reviewer="reviewer",
                    decision="approved",
                    notes="Evidence is sufficient.",
                )
                completed = complete_handoff(state=state, handoff_id=created.handoff.id)
                handoffs = list_handoffs(state=state)

        self.assertEqual(created.handoff.status, "open")
        self.assertEqual(accepted.handoff.status, "accepted")
        self.assertEqual(reviewed.handoff.status, "reviewed")
        self.assertEqual(reviewed.handoff.reviewer, "reviewer")
        self.assertEqual(reviewed.handoff.review_decision, "approved")
        self.assertEqual(completed.handoff.status, "completed")
        self.assertEqual(len(handoffs.handoffs), 1)
        self.assertEqual(handoffs.handoffs[0].status, "completed")
        self.assertEqual(handoffs.handoffs[0].review_notes, "Evidence is sufficient.")
        self.assertEqual(handoffs.handoffs[0].summary, "Check audit docs before public release.")

    def test_api_handoff_lifecycle(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            created = handle_api_request(
                "POST",
                "/handoffs",
                {
                    "title": "Review handoff path",
                    "from_agent": "demobot",
                    "to_agent": "operator",
                    "summary": "API route smoke.",
                },
                vault=VAULT,
                state=state, allow_unauthenticated_demo=True,)
            handoff_id = created.body["handoff"]["id"]
            accepted = handle_api_request("POST", f"/handoffs/{handoff_id}/accept", {}, vault=VAULT, state=state, allow_unauthenticated_demo=True)
            from unittest.mock import patch
            from arvyx_control.auth import OPERATOR_IDENTITY
            with patch('arvyx_control.api.resolve_identity', return_value=OPERATOR_IDENTITY):
                reviewed = handle_api_request(
                "POST",
                f"/handoffs/{handoff_id}/review",
                {"reviewer": "reviewer", "decision": "approved", "notes": "API review smoke."},
                vault=VAULT,
                state=state, allow_unauthenticated_demo=True,)
            completed = handle_api_request("POST", f"/handoffs/{handoff_id}/complete", {}, vault=VAULT, state=state, allow_unauthenticated_demo=True)
            listed = handle_api_request("GET", "/handoffs", {}, vault=VAULT, state=state, allow_unauthenticated_demo=True)

        self.assertEqual(created.status, 201)
        self.assertEqual(accepted.body["handoff"]["status"], "accepted")
        self.assertEqual(reviewed.body["handoff"]["status"], "reviewed")
        self.assertEqual(reviewed.body["handoff"]["reviewer"], "reviewer")
        self.assertEqual(completed.body["handoff"]["status"], "completed")
        self.assertEqual(completed.body["handoff"]["review_notes"], "API review smoke.")
        self.assertEqual(listed.body["handoffs"][0]["status"], "completed")

    def test_control_bus_messages_project_state(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                posted = post_bus_message(
                    state=state,
                    message="Bridge dogfood is ready for review.",
                    channel="ops",
                    actor="demobot",
                    severity="notice",
                )
                messages = list_bus_messages(state=state, channel="ops")

        self.assertEqual(posted.message.channel, "ops")
        self.assertEqual(len(messages.messages), 1)
        self.assertEqual(messages.messages[0].message, "Bridge dogfood is ready for review.")

    def test_api_bus_messages(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            posted = handle_api_request(
                "POST",
                "/bus",
                {"message": "API bus smoke", "channel": "ops", "actor": "demobot"},
                vault=VAULT,
                state=state, allow_unauthenticated_demo=True,)
            listed = handle_api_request("GET", "/bus", {}, vault=VAULT, state=state, allow_unauthenticated_demo=True)

        self.assertEqual(posted.status, 201)
        self.assertEqual(listed.body["messages"][0]["message"], "API bus smoke")

    def test_doctor_checks_synthetic_vault(self) -> None:
        result = doctor(VAULT)

        self.assertTrue(result.ok)
        self.assertGreater(result.checked_files, result.indexed_files)
        self.assertEqual(result.registry_files, 9)
        self.assertFalse(result.findings)

    def test_doctor_flags_missing_registry_fields(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            (target / "registry/agents/demobot.json").write_text(
                '{"id": "demobot"}',
                encoding="utf-8",
            )

            result = doctor(target)

        self.assertFalse(result.ok)
        self.assertTrue(any(finding.code == "registry_fields_missing" for finding in result.findings))

    def test_doctor_warns_on_missing_frontmatter(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            (target / "projects/demo-agent/STATUS.md").write_text(
                "# Demo Agent Project - Status\n\n## Current Truth\n\n- Still synthetic.\n",
                encoding="utf-8",
            )

            result = doctor(target)

        self.assertTrue(result.ok)
        self.assertTrue(any(finding.code == "frontmatter_missing" for finding in result.findings))

    def test_doctor_flags_secret_shapes_in_curated_files(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            fixture_line = "api_key = test-secret-value-12345"  # gitleaks:allow -- synthetic fixture
            (target / "projects/demo-agent/STATUS.md").write_text(
                "# Status\n\n" + fixture_line + "\n",
                encoding="utf-8",
            )

            result = doctor(target)

        self.assertFalse(result.ok)
        self.assertTrue(any(finding.code == "secret_shape" for finding in result.findings))

    def test_mcp_tools_list_exposes_memory_tools(self) -> None:
        response = _handle_request_operator({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, vault=VAULT)

        self.assertEqual(response["id"], 1)
        tools = response["result"]["tools"]
        names = {tool["name"] for tool in tools}
        self.assertIn("memory.recall", names)
        self.assertIn("memory.excerpt", names)
        self.assertIn("memory.context_pack", names)
        self.assertIn("control.task_create", names)
        self.assertIn("control.approval_request", names)
        task_create = next(tool for tool in tools if tool["name"] == "control.task_create")
        self.assertIn("title", task_create["inputSchema"]["required"])
        title_schema = task_create["inputSchema"]["properties"]["title"]
        self.assertEqual(title_schema["minLength"], 1)
        self.assertIsNone(re.fullmatch(title_schema["pattern"], "   "))
        self.assertIsNotNone(re.fullmatch(title_schema["pattern"], " valid "))

    def test_mcp_read_only_profile_hides_and_blocks_control_tools(self) -> None:
        allowed = {"memory.recall", "memory.excerpt", "memory.context_pack"}
        listed = handle_request(
            {"jsonrpc": "2.0", "id": "list", "method": "tools/list"},
            vault=VAULT,
            allowed_tools=allowed,
        )
        blocked = handle_request(
            {
                "jsonrpc": "2.0",
                "id": "blocked",
                "method": "tools/call",
                "params": {"name": "control.task_create", "arguments": {"title": "blocked"}},
            },
            vault=VAULT,
            allowed_tools=allowed,
        )

        names = {tool["name"] for tool in listed["result"]["tools"]}
        self.assertIn("memory.recall", names)
        self.assertNotIn("control.task_create", names)
        self.assertEqual(blocked["error"]["code"], -32000)
        self.assertIn("allowlisted", blocked["error"]["message"])

    def test_api_mcp_defaults_to_read_only_profile(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            listed = handle_api_request(
                "POST",
                "/mcp",
                {"jsonrpc": "2.0", "id": "list", "method": "tools/list"},
                vault=VAULT,
                state=state, allow_unauthenticated_demo=True,)
            blocked = handle_api_request(
                "POST",
                "/mcp",
                {
                    "jsonrpc": "2.0",
                    "id": "blocked",
                    "method": "tools/call",
                    "params": {"name": "control.task_create", "arguments": {"title": "blocked"}},
                },
                vault=VAULT,
                state=state, allow_unauthenticated_demo=True,)

        names = {tool["name"] for tool in json.loads(listed.body)["result"]["tools"]}
        self.assertIn("memory.recall", names)
        self.assertNotIn("control.task_create", names)
        self.assertEqual(json.loads(blocked.body)["error"]["code"], -32000)

    def test_api_mcp_operator_profile_exposes_control_tools(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            listed = handle_api_request(
                "POST",
                "/mcp",
                {"jsonrpc": "2.0", "id": "list", "method": "tools/list"},
                vault=VAULT,
                state=state,
                mcp_profile="operator", allow_unauthenticated_demo=True,)

        names = {tool["name"] for tool in json.loads(listed.body)["result"]["tools"]}
        self.assertIn("memory.recall", names)
        self.assertIn("control.task_create", names)

    def test_mcp_recall_returns_structured_content(self) -> None:
        response = handle_request(
            {
                "jsonrpc": "2.0",
                "id": "recall-1",
                "method": "tools/call",
                "params": {
                    "name": "memory.recall",
                    "arguments": {
                        "question": "what did we decide about safe mcp bridge",
                        "project": "demo-agent",
                        "max_tokens": 90,
                    },
                },
            },
            vault=VAULT,
        )

        self.assertEqual(response["id"], "recall-1")
        result = response["result"]["structuredContent"]
        self.assertTrue(result["answer"])
        self.assertTrue(result["cards"])
        self.assertTrue(result["sources"])

    def test_mcp_excerpt_refuses_raw_path(self) -> None:
        response = handle_request(
            {
                "jsonrpc": "2.0",
                "id": "raw-1",
                "method": "tools/call",
                "params": {
                    "name": "memory.excerpt",
                    "arguments": {
                        "source_path": "projects/demo-agent/raw/private-draft.md",
                        "lines": "1-2",
                    },
                },
            },
            vault=VAULT,
        )

        self.assertEqual(response["error"]["code"], -32000)
        self.assertIn("forbidden", response["error"]["message"])

    def test_mcp_control_task_create_and_list(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            created = _handle_request_operator(
                {
                    "jsonrpc": "2.0",
                    "id": "task-create",
                    "method": "tools/call",
                    "params": {
                        "name": "control.task_create",
                        "arguments": {"title": "Review MCP task control", "owner": "demobot"},
                    },
                },
                vault=VAULT,
                state=state,
            )
            listed = _handle_request_operator(
                {
                    "jsonrpc": "2.0",
                    "id": "task-list",
                    "method": "tools/call",
                    "params": {"name": "control.task_list", "arguments": {}},
                },
                vault=VAULT,
                state=state,
            )

        self.assertEqual(created["result"]["structuredContent"]["task"]["status"], "open")
        tasks = listed["result"]["structuredContent"]["tasks"]
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["title"], "Review MCP task control")

    def test_mcp_control_task_create_validates_title(self) -> None:
        invalid_arguments = ({}, {"title": ""}, {"title": " \t\n "}, {"title": 123})

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            for arguments in invalid_arguments:
                with self.subTest(arguments=arguments):
                    response = _handle_request_operator(
                        {
                            "jsonrpc": "2.0",
                            "id": "task-create-invalid",
                            "method": "tools/call",
                            "params": {"name": "control.task_create", "arguments": arguments},
                        },
                        vault=VAULT,
                        state=state,
                    )
                    self.assertEqual(response["error"]["code"], -32000)
                    self.assertIn("title", response["error"]["message"])

            valid = _handle_request_operator(
                {
                    "jsonrpc": "2.0",
                    "id": "task-create-valid",
                    "method": "tools/call",
                    "params": {
                        "name": "control.task_create",
                        "arguments": {"title": "Review validated MCP task", "owner": "demobot"},
                    },
                },
                vault=VAULT,
                state=state,
            )

        self.assertEqual(
            valid["result"]["structuredContent"]["task"]["title"],
            "Review validated MCP task",
        )

    def test_mcp_control_approval_rejects_wrong_command(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            requested = _handle_request_operator(
                {
                    "jsonrpc": "2.0",
                    "id": "approval-request",
                    "method": "tools/call",
                    "params": {
                        "name": "control.approval_request",
                        "arguments": {"command": "arvyx recall demo-agent", "requester": "demobot"},
                    },
                },
                vault=VAULT,
                state=state,
            )
            approval_id = requested["result"]["structuredContent"]["approval"]["id"]
            _handle_request_operator(
                {
                    "jsonrpc": "2.0",
                    "id": "approval-approve",
                    "method": "tools/call",
                    "params": {"name": "control.approval_approve", "arguments": {"approval_id": approval_id}},
                },
                vault=VAULT,
                state=state,
            )
            rejected = _handle_request_operator(
                {
                    "jsonrpc": "2.0",
                    "id": "approval-consume",
                    "method": "tools/call",
                    "params": {
                        "name": "control.approval_consume",
                        "arguments": {"approval_id": approval_id, "command": "arvyx task done something"},
                    },
                },
                vault=VAULT,
                state=state,
            )

        self.assertEqual(rejected["error"]["code"], -32000)
        self.assertIn("command hash", rejected["error"]["message"])

    def test_mcp_control_approval_rejects_self_approval(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            requested = _handle_request_operator(
                {
                    "jsonrpc": "2.0",
                    "id": "approval-request",
                    "method": "tools/call",
                    "params": {
                        "name": "control.approval_request",
                        "arguments": {"command": "arvyx recall demo-agent", "requester": "demobot"},
                    },
                },
                vault=VAULT,
                state=state,
            )
            approval_id = requested["result"]["structuredContent"]["approval"]["id"]
            rejected = _handle_request_operator(
                {
                    "jsonrpc": "2.0",
                    "id": "approval-approve",
                    "method": "tools/call",
                    "params": {
                        "name": "control.approval_approve",
                        "arguments": {"approval_id": approval_id, "approver": "demobot"},
                    },
                },
                vault=VAULT,
                state=state,
            )

        self.assertEqual(rejected["error"]["code"], -32000)
        self.assertIn("requester cannot approve", rejected["error"]["message"])

    def test_mcp_control_handoff_create_accept_and_complete(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            created = _handle_request_operator(
                {
                    "jsonrpc": "2.0",
                    "id": "handoff-create",
                    "method": "tools/call",
                    "params": {
                        "name": "control.handoff_create",
                        "arguments": {
                            "title": "Continue bridge dogfood",
                            "from_agent": "demobot",
                            "to_agent": "operator",
                            "summary": "Run bridge end-to-end next.",
                        },
                    },
                },
                vault=VAULT,
                state=state,
            )
            handoff_id = created["result"]["structuredContent"]["handoff"]["id"]
            accepted = _handle_request_operator(
                {
                    "jsonrpc": "2.0",
                    "id": "handoff-accept",
                    "method": "tools/call",
                    "params": {"name": "control.handoff_accept", "arguments": {"handoff_id": handoff_id}},
                },
                vault=VAULT,
                state=state,
            )
            reviewed = _handle_request_operator(
                {
                    "jsonrpc": "2.0",
                    "id": "handoff-review",
                    "method": "tools/call",
                    "params": {
                        "name": "control.handoff_review",
                        "arguments": {
                            "handoff_id": handoff_id,
                            "reviewer": "reviewer",
                            "decision": "approved",
                            "notes": "MCP review smoke.",
                        },
                    },
                },
                vault=VAULT,
                state=state,
            )
            completed = _handle_request_operator(
                {
                    "jsonrpc": "2.0",
                    "id": "handoff-complete",
                    "method": "tools/call",
                    "params": {"name": "control.handoff_complete", "arguments": {"handoff_id": handoff_id}},
                },
                vault=VAULT,
                state=state,
            )

        self.assertEqual(created["result"]["structuredContent"]["handoff"]["status"], "open")
        self.assertEqual(accepted["result"]["structuredContent"]["handoff"]["status"], "accepted")
        self.assertEqual(reviewed["result"]["structuredContent"]["handoff"]["status"], "reviewed")
        self.assertEqual(reviewed["result"]["structuredContent"]["handoff"]["reviewer"], "reviewer")
        self.assertEqual(completed["result"]["structuredContent"]["handoff"]["status"], "completed")
        self.assertEqual(completed["result"]["structuredContent"]["handoff"]["review_notes"], "MCP review smoke.")

    def test_mcp_control_bus_post_and_list(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            posted = _handle_request_operator(
                {
                    "jsonrpc": "2.0",
                    "id": "bus-post",
                    "method": "tools/call",
                    "params": {
                        "name": "control.bus_post",
                        "arguments": {
                            "message": "MCP bus smoke",
                            "channel": "ops",
                            "actor": "demobot",
                        },
                    },
                },
                vault=VAULT,
                state=state,
            )
            listed = _handle_request_operator(
                {
                    "jsonrpc": "2.0",
                    "id": "bus-list",
                    "method": "tools/call",
                    "params": {"name": "control.bus_list", "arguments": {"channel": "ops"}},
                },
                vault=VAULT,
                state=state,
            )

        self.assertEqual(posted["result"]["structuredContent"]["message"]["message"], "MCP bus smoke")
        self.assertEqual(listed["result"]["structuredContent"]["messages"][0]["channel"], "ops")

    def test_safe_mcp_bridge_examples_reference_real_tools(self) -> None:
        allowed = set(TOOL_NAMES)
        for relative in [
            "examples/safe-mcp-bridge/read-only.json",
            "examples/safe-mcp-bridge/operator.json",
        ]:
            payload = json.loads((ROOT / relative).read_text(encoding="utf-8"))
            self.assertEqual(payload["policy"]["mode"], "allowlist")
            self.assertTrue(set(payload["policy"]["allow_tools"]) <= allowed)
            self.assertEqual(payload["target"]["url"], "http://127.0.0.1:8765/mcp")
            self.assertTrue(payload["auth"]["env"])

    def test_operator_surface_doc_is_linked_and_public_safe(self) -> None:
        doc = ROOT / "docs/operator-surface.md"
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        text = doc.read_text(encoding="utf-8")

        self.assertIn("docs/operator-surface.md", readme)
        self.assertIn("--mcp-profile operator", text)
        self.assertIn("GET /summary", text)
        self.assertNotIn("/home/", text)
        self.assertNotIn("/srv/", text)

    def test_bridge_policy_generator_profiles_reference_real_tools(self) -> None:
        read_only = build_bridge_policy(profile="read-only")
        operator = build_bridge_policy(profile="operator")

        self.assertEqual(
            read_only.policy["policy"]["allow_tools"],
            [
                "memory.recall",
                "memory.excerpt",
                "memory.context_pack",
                # War Room reads only; post/ack/done/read-all stay operator-only
                "control.thread_get",
                "control.thread_inbox",
                "control.thread_pending",
            ],
        )
        self.assertEqual(
            operator.policy["policy"]["allow_tools"], list(tools_for_profile("operator")),
        )
        self.assertTrue(set(operator.policy["policy"]["allow_tools"]) <= set(TOOL_NAMES))

    def test_safe_mcp_bridge_e2e_fixture_covers_read_only_contract(self) -> None:
        from scripts.bridge_e2e_fixture_check import validate_fixture

        result = validate_fixture(ROOT / "fixtures/safe-mcp-bridge/read-only-e2e.json")

        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["visible_tools"], ["memory.recall", "memory.excerpt", "memory.context_pack"])
        self.assertTrue(result["recall_ok"])
        self.assertTrue(result["blocked_control_write"])
        self.assertIn("tools_list_filtered", result["audit_events"])
        self.assertIn("request_forwarded", result["audit_events"])
        self.assertIn("tool_blocked", result["audit_events"])
        self.assertFalse(result["credential_leaked"])

    def test_bridge_policy_generator_writes_policy_file(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "operator.json"
            result = write_bridge_policy(profile="operator", output=output, auth_env="DEMO_TOKEN")
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result.written_to, str(output))
        self.assertEqual(payload["auth"]["env"], "DEMO_TOKEN")
        self.assertEqual(
            payload["policy"]["allow_tools"], list(tools_for_profile("operator")),
        )

    def test_cli_bridge_policy_json_output(self) -> None:
        from contextlib import redirect_stdout
        from io import StringIO

        out = StringIO()
        with redirect_stdout(out):
            code = main(["bridge-policy", "--profile", "read-only", "--json"])

        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["profile"], "read-only")
        self.assertEqual(
            payload["policy"]["policy"]["allow_tools"],
            [
                "memory.recall",
                "memory.excerpt",
                "memory.context_pack",
                "control.thread_get",
                "control.thread_inbox",
                "control.thread_pending",
            ],
        )

    def test_readiness_reports_completed_product_gate(self) -> None:
        result = readiness(ROOT)
        statuses = {item.id: item.status for item in result.items}

        self.assertGreater(result.score, 50)
        self.assertTrue(result.structural_complete)
        self.assertEqual(statuses["recall"], "complete")
        self.assertEqual(statuses["bridge"], "complete")
        self.assertEqual(statuses["internal_audit"], "complete")
        self.assertEqual(statuses["audits"], "complete")

    def test_cli_readiness_json_output(self) -> None:
        from contextlib import redirect_stdout
        from io import StringIO

        out = StringIO()
        with redirect_stdout(out):
            code = main(["readiness", "--repo", str(ROOT), "--json"])

        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertIn("score", payload)
        self.assertIn("items", payload)
        self.assertTrue(payload["structural_complete"])
        self.assertNotIn("public_ready", payload)

    @patch.dict(os.environ, {"ARVYX_PRIVATE_DENYLIST": str(ROOT / "requirements/dev.lock/not-a-directory")})
    def test_internal_audit_without_usable_denylist_fails_closed(self) -> None:
        result = run_audit(repo=ROOT, vault=VAULT)

        self.assertFalse(result.ok)
        self.assertTrue(result.public_release_blocked)
        self.assertIn("security audit multi-model review is missing or invalid", result.release_blockers)
        private_context = next(check for check in result.checks if check.id == "private_context")
        self.assertFalse(private_context.ok)
        self.assertIn("private_denylist_loaded=false", private_context.evidence)

    @patch.dict(os.environ, {"ARVYX_PRIVATE_DENYLIST": str(ROOT / "requirements/dev.lock/not-a-directory")})
    def test_cli_audit_json_output(self) -> None:
        from contextlib import redirect_stdout
        from io import StringIO

        out = StringIO()
        with redirect_stdout(out):
            code = main(["audit", "--repo", str(ROOT), "--vault", str(VAULT), "--json"])

        self.assertEqual(code, 1)
        payload = json.loads(out.getvalue())
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["public_release_blocked"])
        self.assertTrue(payload["release_blockers"])

    def test_recall_benchmark_passes_golden_fixture(self) -> None:
        result = run_recall_benchmark(vault=VAULT, cases_path=ROOT / "fixtures/recall-benchmark.json")

        self.assertTrue(result.ok)
        self.assertEqual(result.score, 100)
        self.assertEqual(result.passed, result.total)
        self.assertEqual(result.retrieval_mode, "lexical")
        self.assertEqual(result.metadata["suite"], "synthetic-vault-recall")
        self.assertEqual(result.categories["decision-recall"]["score"], 100)
        self.assertEqual(result.cases[0].category, "decision-recall")

    def test_cli_recall_benchmark_json_output(self) -> None:
        from contextlib import redirect_stdout
        from io import StringIO

        out = StringIO()
        with redirect_stdout(out):
            code = main(["benchmark", "recall", "--vault", str(VAULT), "--json"])

        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["score"], 100)
        self.assertEqual(payload["metadata"]["schema_version"], 1)
        self.assertIn("cross-project-isolation", payload["categories"])
        self.assertEqual(payload["retrieval_mode"], "lexical")
        self.assertTrue(payload["cases"])

    def test_recall_benchmark_hybrid_mode_passes_golden_fixture(self) -> None:
        result = run_recall_benchmark(
            vault=VAULT,
            cases_path=ROOT / "fixtures/recall-benchmark.json",
            retrieval_mode="hybrid",
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.retrieval_mode, "hybrid")
        self.assertEqual(result.score, 100)
        self.assertTrue(all(case.retrieval_mode == "hybrid" for case in result.cases))

    def test_release_host_report_records_host_only_blockers(self) -> None:
        result = release_host_report(repo=ROOT)
        checks = {check.id: check.status for check in result.checks}

        # ok requires every check to actually complete; blocked checks are
        # honest failures, not passes.
        self.assertFalse(result.ok)
        self.assertFalse(result.public_release_ready)
        self.assertEqual(checks["docker_runtime"], "blocked")
        self.assertEqual(checks["mcp_client_real"], "blocked")
        self.assertEqual(checks["safe_mcp_bridge_e2e"], "blocked")
        self.assertTrue(any("docker_runtime" in blocker for blocker in result.blockers))
        self.assertTrue(any("safe_mcp_bridge_e2e" in blocker for blocker in result.blockers))

    def test_mcp_client_evidence_example_is_valid(self) -> None:
        result = validate_mcp_client_evidence(ROOT / "examples/mcp-clients/real-client-evidence.example.json")

        self.assertTrue(result["ok"])
        self.assertEqual(result["client"], "codex")
        self.assertEqual(result["transport"], "stdio")

    def test_mcp_client_evidence_rejects_private_markers(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "evidence.json"
            evidence.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "client": "codex",
                        "checked_at": "2026-07-02T00:00:00Z",
                        "transport": "stdio",
                        "command": "python3 -m arvyx_control.cli mcp --vault /home/operator/vault",
                        "result": {
                            "tools_list_ok": True,
                            "recall_ok": True,
                            "sources_returned": True,
                            "private_paths_leaked": False,
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = validate_mcp_client_evidence(evidence)

        self.assertFalse(result["ok"])
        self.assertTrue(any("private marker" in error for error in result["errors"]))

    def test_mcp_client_evidence_generator_writes_valid_file(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "mcp-client-evidence.json"
            payload = generate_mcp_client_evidence(vault=VAULT, output=output)
            validation = validate_mcp_client_evidence(output)

        self.assertTrue(payload["result"]["tools_list_ok"])
        self.assertTrue(payload["result"]["recall_ok"])
        self.assertTrue(payload["result"]["sources_returned"])
        self.assertTrue(validation["ok"])

    def test_cli_mcp_client_evidence_json_output(self) -> None:
        import tempfile
        from contextlib import redirect_stdout
        from io import StringIO

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "mcp-client-evidence.json"
            out = StringIO()
            with redirect_stdout(out):
                code = main(
                    [
                        "evidence",
                        "mcp-client",
                        "--vault",
                        str(VAULT),
                        "--output",
                        str(output),
                        "--json",
                    ]
                )
            payload = json.loads(out.getvalue())

        self.assertEqual(code, 0)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["validation"]["ok"])

    def test_release_host_validates_mcp_client_evidence(self) -> None:
        import tempfile
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "mcp-client-evidence.json"
            key, allowed = _make_pinned_signer(Path(tmp))
            _write_signed_external_mcp_evidence(evidence, key)
            with _pinned_release_policy(allowed):
                result = release_host_report(repo=ROOT, mcp_client_evidence=evidence)
        checks = {check.id: check.status for check in result.checks}

        self.assertEqual(checks["mcp_client_real"], "complete")
        self.assertEqual(checks["docker_runtime"], "blocked")

    def test_release_host_blocks_forged_external_mcp_evidence_without_attestation(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "forged-evidence.json"
            evidence.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "client": "claude-desktop",
                        "checked_at": "2020-01-01T00:00:00Z",
                        "git_head": _git_head(),
                        "transport": "stdio",
                        "command": "python3 -m arvyx_control.cli mcp --vault fixtures/synthetic-vault",
                        "result": {
                            "tools_list_ok": True,
                            "recall_ok": True,
                            "sources_returned": True,
                            "private_paths_leaked": False,
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = release_host_report(repo=ROOT, mcp_client_evidence=evidence)

        checks = {check.id: check for check in result.checks}
        self.assertEqual(checks["mcp_client_real"].status, "blocked")
        self.assertTrue(any("stale" in item or "attestation" in item for item in checks["mcp_client_real"].evidence))

    def test_cli_release_host_json_output(self) -> None:
        from contextlib import redirect_stdout
        from io import StringIO

        out = StringIO()
        with redirect_stdout(out):
            code = main(["release-host", "--repo", str(ROOT), "--json"])

        self.assertEqual(code, 1)
        payload = json.loads(out.getvalue())
        self.assertFalse(payload["ok"])
        self.assertFalse(payload["public_release_ready"])
        self.assertTrue(payload["blockers"])

    def test_self_dogfood_classifies_before_copying_document_bodies(self) -> None:
        from arvyx_control.dogfood import _stage_public_docs
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / 'repo'
            (repo / 'config').mkdir(parents=True)
            (repo / 'docs').mkdir()
            for name, text in {
                'public.md': 'Public retrieval documentation',
                'private.md': 'Private prose without any credential pattern',
                'unknown.md': 'Unclassified prose',
                'notice.md': '# PRIVATE: DO NOT PUBLISH\nPrivate despite classification',
            }.items():
                (repo / 'docs' / name).write_text(text, encoding='utf-8')
            policy = repo / 'config/public-release-paths.json'
            policy.write_text(json.dumps({'version': 1, 'paths': {
                'docs/public.md': 'reimplemented-clean-room',
                'docs/private.md': 'private-only',
                'docs/notice.md': 'public-approved',
            }}), encoding='utf-8')
            destination = Path(tmp) / 'selected'
            _stage_public_docs(repo, destination)
            self.assertEqual([p.name for p in destination.rglob('*.md')], ['public.md'])
            policy.write_text('{"version":1,"paths":{"docs/public.md":"public-approved",'
                              '"docs/public.md":"private-only"}}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'duplicate key'):
                _stage_public_docs(repo, Path(tmp) / 'duplicate')
            self.assertFalse((Path(tmp) / 'duplicate').exists())

    def test_live_api_dogfood_checks_real_http_server(self) -> None:
        result = dogfood_live_api(vault=VAULT)
        checks = {check.name: check for check in result.checks}

        self.assertTrue(result.ok)
        self.assertTrue(checks["health"].ok)
        self.assertTrue(checks["dashboard"].ok)
        self.assertTrue(checks["unauthorized_recall"].ok)
        self.assertTrue(checks["authorized_recall"].ok)
        self.assertTrue(checks["mcp_tools_list"].ok)
        self.assertTrue(checks["tasks_round_trip"].ok)

    def test_cli_live_api_dogfood_json_output(self) -> None:
        from contextlib import redirect_stdout
        from io import StringIO

        out = StringIO()
        with redirect_stdout(out):
            code = main(["dogfood", "live-api", "--vault", str(VAULT), "--json"])

        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertTrue(payload["ok"])
        self.assertTrue(any(check["name"] == "mcp_tools_list" and check["ok"] for check in payload["checks"]))

    def test_import_markdown_adds_governed_project_note(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            source = Path(tmp) / "notes"
            source.mkdir()
            (source / "Operator Memory.md").write_text(
                "The operator memory lane keeps imported markdown behind review before it becomes current truth.\n",
                encoding="utf-8",
            )

            result = import_markdown(source=source, vault=target, project="demo-agent")
            manifest = target / "projects/demo-agent/imported/import-manifest.jsonl"
            manifest_event = json.loads(manifest.read_text(encoding="utf-8").splitlines()[-1])
            recalled = recall("operator memory lane review", vault=target, project="demo-agent")

        self.assertEqual(result.imported, ["projects/demo-agent/imported/operator-memory.md"])
        self.assertEqual(result.skipped, [])
        self.assertEqual(result.manifest_path, "projects/demo-agent/imported/import-manifest.jsonl")
        self.assertEqual(manifest_event["source_type"], "imported-markdown")
        self.assertEqual(manifest_event["imported_count"], 1)
        self.assertTrue(any(source.path.endswith("imported/operator-memory.md") for source in recalled.sources))

    def test_import_markdown_rejects_project_path_traversal(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            source = Path(tmp) / "note.md"
            source.write_text("Safe note.\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                import_markdown(source=source, vault=target, project="../../escape")

            self.assertFalse((Path(tmp) / "escape").exists())

    def test_import_markdown_rejects_absolute_project_slug(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / "vault"
            init_vault(target)
            source = base / "note.md"
            source.write_text("safe note", encoding="utf-8")

            with self.assertRaises(ValueError):
                import_markdown(source=source, vault=target, project="/tmp/escape")

            self.assertFalse((base / "escape").exists())

    def test_recall_rejects_project_path_traversal(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / "vault"
            init_vault(target)
            outside = base / "outside" / "imported"
            outside.mkdir(parents=True)
            (outside / "note.md").write_text("safe note", encoding="utf-8")

            with self.assertRaises(ValueError):
                recall("safe note", vault=target, project="../../outside")

    def test_valid_project_id_shapes_are_accepted(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            for project in ("demo-agent", "agent_1", "project123"):
                project_dir = target / "projects" / project
                project_dir.mkdir(parents=True, exist_ok=True)
                (project_dir / "STATUS.md").write_text(f"{project} current truth\n", encoding="utf-8")
                result = recall("current truth", vault=target, project=project)
                self.assertTrue(result.sources)

    def test_import_markdown_skips_secret_shaped_notes(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            source = Path(tmp) / "notes"
            source.mkdir()
            (source / "clean.md").write_text("Clean imported memory about scoped recall.\n", encoding="utf-8")
            (source / "secret.md").write_text("api_key = synthetic-secret-value\n", encoding="utf-8")

            result = import_markdown(source=source, vault=target, project="demo-agent")
            manifest=(target / result.manifest_path).read_text()
            self.assertNotIn(str(source), manifest)
            self.assertNotIn("secret", manifest)


        self.assertEqual(result.imported, ["projects/demo-agent/imported/clean.md"])
        self.assertEqual(len(result.skipped), 1)
        self.assertRegex(result.skipped[0], r"^input-[0-9]+:rejected$")
        self.assertNotIn("secret", str(result))
        self.assertNotIn(str(source), str(result))

    def test_import_markdown_skips_wider_secret_shapes(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            source = Path(tmp) / "notes"
            source.mkdir()
            (source / "vercel.md").write_text("temporary vcp_abcdefghijklmnopqrst token\n", encoding="utf-8")

            result = import_markdown(source=source, vault=target, project="demo-agent")
            manifest=(target / result.manifest_path).read_text()
            self.assertNotIn(str(source), manifest)
            self.assertNotIn("vercel", manifest)


        self.assertEqual(result.imported, [])
        self.assertEqual(len(result.skipped), 1)
        self.assertRegex(result.skipped[0], r"^input-[0-9]+:rejected$")
        self.assertNotIn("vercel", str(result))
        self.assertNotIn(str(source), str(result))

    def test_import_markdown_disambiguates_duplicate_filenames(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            source = Path(tmp) / "notes"
            (source / "one").mkdir(parents=True)
            (source / "two").mkdir(parents=True)
            (source / "one" / "Status.md").write_text("First status import.\n", encoding="utf-8")
            (source / "two" / "Status.md").write_text("Second status import.\n", encoding="utf-8")

            result = import_markdown(source=source, vault=target, project="demo-agent")

        self.assertEqual(
            result.imported,
            ["projects/demo-agent/imported/status.md", "projects/demo-agent/imported/status-2.md"],
        )

    def test_import_markdown_dry_run_does_not_write(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            source = Path(tmp) / "note.md"
            source.write_text("Preview-only imported note.\n", encoding="utf-8")

            result = import_markdown(source=source, vault=target, project="demo-agent", dry_run=True)
            wrote_file = (target / "projects/demo-agent/imported/note.md").exists()
            wrote_manifest = (target / "projects/demo-agent/imported/import-manifest.jsonl").exists()

        self.assertTrue(result.dry_run)
        self.assertIsNone(result.manifest_path)
        self.assertEqual(result.imported, ["projects/demo-agent/imported/note.md"])
        self.assertFalse(wrote_file)
        self.assertFalse(wrote_manifest)

    def test_import_obsidian_adds_source_lane_and_tags(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            source = Path(tmp) / "obsidian"
            source.mkdir()
            (source / "Bridge Notes.md").write_text(
                "The [[safe bridge]] keeps read-only clients away from control writes.\n",
                encoding="utf-8",
            )

            result = import_obsidian(source=source, vault=target, project="demo-agent")
            imported_path = target / result.imported[0]
            imported_text = imported_path.read_text(encoding="utf-8")
            recalled = recall("read only clients control writes", vault=target, project="demo-agent")

        self.assertEqual(result.imported, ["projects/demo-agent/imported/obsidian/bridge-notes.md"])
        self.assertIn("type: imported-obsidian", imported_text)
        self.assertTrue(any(source.path.endswith("imported/obsidian/bridge-notes.md") for source in recalled.sources))

    def test_import_basic_memory_adds_source_lane_and_tags(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            source = Path(tmp) / "basic-memory"
            source.mkdir()
            (source / "Project Memory.md").write_text(
                "Basic Memory export: governed recall should preserve project context.\n",
                encoding="utf-8",
            )

            result = import_basic_memory(source=source, vault=target, project="demo-agent")
            imported_path = target / result.imported[0]
            imported_text = imported_path.read_text(encoding="utf-8")
            recalled = recall("governed recall preserve project context", vault=target, project="demo-agent")

        self.assertEqual(result.imported, ["projects/demo-agent/imported/basic-memory/project-memory.md"])
        self.assertIn("type: imported-basic-memory", imported_text)
        self.assertTrue(
            any(source.path.endswith("imported/basic-memory/project-memory.md") for source in recalled.sources)
        )

    def test_cli_import_markdown_json_output(self) -> None:
        import tempfile
        from contextlib import redirect_stdout
        from io import StringIO

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            source = Path(tmp) / "note.md"
            source.write_text("Imported command center note for MCP memory recall.\n", encoding="utf-8")
            out = StringIO()

            with redirect_stdout(out):
                code = main(
                    [
                        "import",
                        "markdown",
                        str(source),
                        "--vault",
                        str(target),
                        "--project",
                        "demo-agent",
                        "--json",
                    ]
                )

        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["imported"], ["projects/demo-agent/imported/note.md"])
        self.assertEqual(payload["skipped"], [])
        self.assertEqual(payload["manifest_path"], "projects/demo-agent/imported/import-manifest.jsonl")

    def test_cli_import_markdown_dry_run_json_output(self) -> None:
        import tempfile
        from contextlib import redirect_stdout
        from io import StringIO

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            source = Path(tmp) / "note.md"
            source.write_text("Preview command center import.\n", encoding="utf-8")
            out = StringIO()

            with redirect_stdout(out):
                code = main(
                    [
                        "import",
                        "markdown",
                        str(source),
                        "--vault",
                        str(target),
                        "--project",
                        "demo-agent",
                        "--dry-run",
                        "--json",
                    ]
                )

        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["imported"], ["projects/demo-agent/imported/note.md"])

    def test_cli_import_obsidian_json_output(self) -> None:
        import tempfile
        from contextlib import redirect_stdout
        from io import StringIO

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            source = Path(tmp) / "obsidian"
            source.mkdir()
            (source / "Agent Wiki.md").write_text("Obsidian wiki note for governed agent memory.\n", encoding="utf-8")
            out = StringIO()

            with redirect_stdout(out):
                code = main(
                    [
                        "import",
                        "obsidian",
                        str(source),
                        "--vault",
                        str(target),
                        "--project",
                        "demo-agent",
                        "--json",
                    ]
                )

        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["imported"], ["projects/demo-agent/imported/obsidian/agent-wiki.md"])


if __name__ == "__main__":
    unittest.main()
