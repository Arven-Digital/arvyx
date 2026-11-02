from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from arvyx_control.replica_authority import authority_context
from arvyx_control.cli import main
from arvyx_control.control import (
    THREAD_NOTIFICATION_EVENT,
    acknowledge_thread,
    list_thread_inbox,
    post_thread,
    project_thread_notifications,
    read_events,
)
from arvyx_control.health_ops import (
    DEFAULT_DAILY_ROLES,
    agent_matrix,
    daily_handoff,
    notify_check,
)
from arvyx_control.mcp import handle_request, tools_for_profile

FIXTURE_AGENTS = {"demobot", "vesper", "operator", "nova"}
def fixture_roles(root: str) -> Path:
    path = Path(root) / "fixture-roles.json"
    path.write_text(json.dumps({"roles": DEFAULT_DAILY_ROLES}), encoding="utf-8")
    return path


class DailyHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.roles_config = fixture_roles(self._tmp.name)
        self.state = Path(self._tmp.name) / "events.jsonl"
        self.vault = Path(self._tmp.name) / "vault"
        self.vault.mkdir(exist_ok=True)
        self.enterContext(authority_context(self.vault, self.state))

    def test_creates_expected_threads_once_per_date(self) -> None:
        result = daily_handoff(state=self.state, date="2026-07-08", config=self.roles_config)
        self.assertEqual(result.date, "2026-07-08")
        self.assertEqual(len(result.created), len(DEFAULT_DAILY_ROLES))
        self.assertEqual(result.skipped, [])
        for thread in result.created:
            self.assertEqual(thread.type, "ask")
            self.assertEqual(thread.channel, "daily-handoff")
            self.assertTrue(thread.pending)
            self.assertIn("[2026-07-08]", thread.title)
            # generic fixture agents only, never live topology
            self.assertIn(thread.target, FIXTURE_AGENTS)
        roles = {thread.title.split("daily ")[1].split(" check")[0] for thread in result.created}
        self.assertEqual(roles, {"ops", "build", "memory", "research"})

    def test_second_run_skips_same_date_handoffs(self) -> None:
        first = daily_handoff(state=self.state, date="2026-07-08", config=self.roles_config)
        second = daily_handoff(state=self.state, date="2026-07-08", config=self.roles_config)
        self.assertEqual(second.created, [])
        self.assertEqual(len(second.skipped), len(DEFAULT_DAILY_ROLES))
        # a new date creates a fresh set
        next_day = daily_handoff(state=self.state, date="2026-07-09", config=self.roles_config)
        self.assertEqual(len(next_day.created), len(DEFAULT_DAILY_ROLES))
        created_events = [event for event in read_events(self.state) if event.type == "thread.created"]
        self.assertEqual(len(created_events), len(first.created) + len(next_day.created))

    def test_duplicate_roles_in_one_config_create_once(self) -> None:
        config = Path(self._tmp.name) / "roles.json"
        role = {"role": "ops", "target": "demobot", "title": "ops check"}
        config.write_text(json.dumps({"roles": [role, dict(role)]}), encoding="utf-8")
        result = daily_handoff(state=self.state, date="2026-07-08", config=config)
        self.assertEqual(len(result.created), 1)
        self.assertEqual(len(result.skipped), 1)
        created_events = [event for event in read_events(self.state) if event.type == "thread.created"]
        self.assertEqual(len(created_events), 1)

    def test_overlapping_daily_handoff_runs_do_not_duplicate(self) -> None:
        # Widen the read->create window: the title read sleeps, so without a
        # lock spanning read+create both runs would see an empty channel and
        # both create. The lock serializes them; the loser must skip.
        def slow_inbox(state, target=None):
            result = list_thread_inbox(state, target=target)
            time.sleep(0.25)
            return result

        barrier = threading.Barrier(2)
        results: list = []
        errors: list = []

        def worker() -> None:
            with authority_context(self.vault, self.state):
                barrier.wait()
                try:
                    results.append(daily_handoff(state=self.state, date="2026-07-08", config=self.roles_config))
                except Exception as exc:  # noqa: BLE001 - surfaced via assertion
                    errors.append(exc)

        with patch("arvyx_control.health_ops.list_thread_inbox", side_effect=slow_inbox):
            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        created_events = [event for event in read_events(self.state) if event.type == "thread.created"]
        self.assertEqual(len(created_events), len(DEFAULT_DAILY_ROLES))
        self.assertEqual(sum(len(result.created) for result in results), len(DEFAULT_DAILY_ROLES))
        self.assertEqual(sum(len(result.skipped) for result in results), len(DEFAULT_DAILY_ROLES))

    def test_custom_roles_config(self) -> None:
        config = Path(self._tmp.name) / "roles.json"
        config.write_text(
            json.dumps(
                {
                    "roles": [
                        {"role": "ops", "target": "demobot", "title": "ops check", "severity": "warn"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        result = daily_handoff(state=self.state, date="2026-07-08", config=config)
        self.assertEqual(len(result.created), 1)
        self.assertEqual(result.created[0].target, "demobot")
        self.assertEqual(result.created[0].severity, "warn")

    def test_rejects_bad_inputs(self) -> None:
        with self.assertRaises(ValueError):
            daily_handoff(state=self.state, date="not-a-date")
        bad = Path(self._tmp.name) / "bad.json"
        bad.write_text(json.dumps({"roles": []}), encoding="utf-8")
        with self.assertRaises(ValueError):
            daily_handoff(state=self.state, date="2026-07-08", config=bad)
        with self.assertRaises(FileNotFoundError):
            daily_handoff(state=self.state, date="2026-07-08", config=Path(self._tmp.name) / "missing.json")

    def test_daily_threads_respect_identity_scope(self) -> None:
        daily_handoff(state=self.state, date="2026-07-08", config=self.roles_config)
        demobot_inbox = handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "control.thread_inbox", "arguments": {}}},
            vault=Path(self._tmp.name) / "vault",
            state=self.state,
            allowed_tools=set(tools_for_profile("operator")),
            actor="demobot",
        )
        threads = demobot_inbox["result"]["structuredContent"]["threads"]
        self.assertEqual([thread["target"] for thread in threads], ["demobot"])
        foreign = handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "control.thread_inbox", "arguments": {"target": "nova"}},
            },
            vault=Path(self._tmp.name) / "vault",
            state=self.state,
            allowed_tools=set(tools_for_profile("operator")),
            actor="demobot",
        )
        self.assertIn("error", foreign)


class NotifyCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.roles_config = fixture_roles(self._tmp.name)
        self.state = Path(self._tmp.name) / "events.jsonl"
        self.vault = Path(self._tmp.name) / "vault"
        self.vault.mkdir(exist_ok=True)
        self.enterContext(authority_context(self.vault, self.state))

    def _notification_events(self) -> list:
        return [event for event in read_events(self.state) if event.type == THREAD_NOTIFICATION_EVENT]

    def test_emits_candidates_for_new_pending_threads(self) -> None:
        ask = post_thread(state=self.state, title="Needs attention", thread_type="ask", target="vesper", actor="demobot")
        post_thread(state=self.state, title="FYI only", thread_type="status", target="vesper", actor="demobot")
        result = notify_check(state=self.state)
        kinds = [(candidate["kind"], candidate["thread_id"]) for candidate in result.candidates]
        self.assertEqual(kinds, [("notification", ask.thread.id)])
        self.assertEqual(len(self._notification_events()), 1)

    def test_dedupes_repeated_runs_inside_window(self) -> None:
        post_thread(state=self.state, title="Needs attention", thread_type="ask", target="vesper", actor="demobot")
        first = notify_check(state=self.state)
        self.assertEqual(len(first.candidates), 1)
        second = notify_check(state=self.state)
        self.assertEqual(second.candidates, [])
        self.assertEqual(len(second.suppressed), 1)
        # after the dedupe window passes, the reminder fires again
        future = datetime.now(timezone.utc) + timedelta(minutes=300)
        with patch("arvyx_control.health_ops._utcnow", return_value=future):
            third = notify_check(state=self.state, dedupe_window_minutes=240, escalate_after_minutes=10_000)
        self.assertEqual(len(third.candidates), 1)

    def test_dry_run_writes_no_state(self) -> None:
        post_thread(state=self.state, title="Needs attention", thread_type="ask", target="vesper", actor="demobot")
        events_before = len(read_events(self.state))
        first = notify_check(state=self.state, dry_run=True)
        second = notify_check(state=self.state, dry_run=True)
        self.assertEqual(len(first.candidates), 1)
        self.assertEqual(len(second.candidates), 1)  # nothing recorded, so no dedupe
        self.assertEqual(len(read_events(self.state)), events_before)

    def test_escalation_after_threshold_if_unacked(self) -> None:
        with patch("arvyx_control.control._now", return_value="2026-07-08T00:00:00Z"):
            stale = post_thread(state=self.state, title="Stale ask", thread_type="ask", target="vesper", actor="demobot")
            acked = post_thread(state=self.state, title="Acked ask", thread_type="ask", target="vesper", actor="demobot")
        acknowledge_thread(state=self.state, thread_id=acked.thread.id, actor="vesper")
        result = notify_check(state=self.state, escalate_after_minutes=60)
        by_kind = {}
        for candidate in result.candidates:
            by_kind.setdefault(candidate["kind"], []).append(candidate["thread_id"])
        # only the unacked thread escalates, and exactly once
        self.assertEqual(by_kind.get("escalation"), [stale.thread.id])
        self.assertIn("ESCALATION", next(c["text"] for c in result.candidates if c["kind"] == "escalation"))
        again = notify_check(state=self.state, escalate_after_minutes=60)
        self.assertEqual([c for c in again.candidates if c["kind"] == "escalation"], [])

    def test_notification_text_has_no_localhost_links_unless_configured(self) -> None:
        post_thread(state=self.state, title="Needs attention", thread_type="ask", target="vesper", actor="demobot")
        default = notify_check(state=self.state, dry_run=True)
        for candidate in default.candidates:
            self.assertNotIn("127.0.0.1", candidate["text"])
            self.assertNotIn("localhost", candidate["text"])
            self.assertNotIn("http", candidate["text"])
        local = notify_check(state=self.state, dry_run=True, dashboard_url="http://127.0.0.1:8765/dashboard")
        self.assertIn("http://127.0.0.1:8765/dashboard", local.candidates[0]["text"])

    def test_overlapping_notify_check_runs_do_not_duplicate(self) -> None:
        # Widen the project->append window: the history projection sleeps, so
        # without a lock spanning project+decide+append both runs would see no
        # prior notification and both append one. The lock serializes them;
        # the later run must suppress.
        post_thread(state=self.state, title="Needs attention", thread_type="ask", target="vesper", actor="demobot")

        def slow_project(state):
            result = project_thread_notifications(state)
            time.sleep(0.25)
            return result

        barrier = threading.Barrier(2)
        results: list = []
        errors: list = []

        def worker() -> None:
            with authority_context(self.vault, self.state):
                barrier.wait()
                try:
                    results.append(notify_check(state=self.state))
                except Exception as exc:  # noqa: BLE001 - surfaced via assertion
                    errors.append(exc)

        with patch("arvyx_control.health_ops.project_thread_notifications", side_effect=slow_project):
            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        # exactly one notification event per dedupe window, no matter the overlap
        self.assertEqual(len(self._notification_events()), 1)
        self.assertEqual(sum(len(result.candidates) for result in results), 1)
        self.assertEqual(sum(len(result.suppressed) for result in results), 1)

    def test_rejects_bad_thresholds(self) -> None:
        for kwargs in ({"dedupe_window_minutes": 0}, {"escalate_after_minutes": 0}):
            with self.assertRaises(ValueError):
                notify_check(state=self.state, **kwargs)


class _MatrixHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        status = 200 if self.path == "/healthz" else 503
        self.send_response(status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


class AgentMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.roles_config = fixture_roles(self._tmp.name)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _MatrixHandler)
        self.port = self.server.server_address[1]
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def _config(self, payload: dict) -> Path:
        path = Path(self._tmp.name) / "agents.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_reports_ok_warn_fail_skip(self) -> None:
        config = self._config(
            {
                "agents": [
                    {
                        "id": "demobot",
                        "runtime": "local-demo-demobot",
                        "endpoints": [
                            {"name": "memory", "url": f"http://127.0.0.1:{self.port}/healthz"},
                            {"name": "degraded", "url": f"http://127.0.0.1:{self.port}/broken"},
                        ],
                    },
                    {
                        "id": "vesper",
                        "endpoints": [
                            {"name": "unreachable", "url": "http://127.0.0.1:9/healthz"},
                            {"name": "browser", "url": "", "enabled": False},
                            {"name": "bad-scheme", "url": "file:///etc/passwd"},
                        ],
                    },
                ]
            }
        )
        result = agent_matrix(config=config, timeout=3.0)
        by_agent = {agent.id: agent for agent in result.agents}
        statuses = {probe.name: probe.status for probe in by_agent["demobot"].endpoints}
        self.assertEqual(statuses, {"memory": "OK", "degraded": "WARN"})
        statuses = {probe.name: probe.status for probe in by_agent["vesper"].endpoints}
        self.assertEqual(statuses["unreachable"], "FAIL")
        self.assertEqual(statuses["browser"], "SKIP")
        self.assertEqual(statuses["bad-scheme"], "FAIL")
        note = next(probe.note for probe in by_agent["vesper"].endpoints if probe.name == "bad-scheme")
        self.assertIn("refusing non-http(s) url", note)
        self.assertEqual(by_agent["demobot"].status, "WARN")
        self.assertEqual(by_agent["vesper"].status, "FAIL")
        self.assertFalse(result.ok)
        self.assertEqual(result.counts["OK"], 1)
        self.assertEqual(result.counts["SKIP"], 1)

    def test_ok_when_all_endpoints_healthy_or_skipped(self) -> None:
        config = self._config(
            {
                "agents": [
                    {
                        "id": "demobot",
                        "endpoints": [
                            {"name": "memory", "url": f"http://127.0.0.1:{self.port}/healthz"},
                            {"name": "browser", "url": "", "enabled": False},
                        ],
                    }
                ]
            }
        )
        result = agent_matrix(config=config, timeout=3.0)
        self.assertTrue(result.ok)
        self.assertEqual(result.agents[0].status, "OK")

    def test_rejects_bad_config(self) -> None:
        with self.assertRaises(FileNotFoundError):
            agent_matrix(config=Path(self._tmp.name) / "missing.json")
        with self.assertRaises(ValueError):
            agent_matrix(config=self._config({"agents": []}))
        with self.assertRaises(ValueError):
            agent_matrix(config=self._config({"agents": [{"endpoints": []}]}))


class HealthCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.roles_config = fixture_roles(self._tmp.name)
        self.state = str(Path(self._tmp.name) / "events.jsonl")
        self.vault = Path(self._tmp.name) / "vault"
        self.vault.mkdir(exist_ok=True)
        self.enterContext(authority_context(self.vault, self.state))

    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["--authority-vault", str(self.vault), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_daily_handoff_and_notify_check_cli(self) -> None:
        code, out, _ = self._run(
            ["health", "daily-handoff", "--date", "2026-07-08", "--state", self.state, "--config", str(self.roles_config), "--json"]
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(len(payload["created"]), len(DEFAULT_DAILY_ROLES))

        code, out, _ = self._run(["health", "notify-check", "--state", self.state, "--dry-run", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(payload["dry_run"])
        self.assertEqual(len(payload["candidates"]), len(DEFAULT_DAILY_ROLES))

    def test_bare_health_command_still_works(self) -> None:
        code, out, _ = self._run(["health", "--json"])
        payload = json.loads(out)
        # no checks requested -> not ok, but the flat command still parses/runs
        self.assertEqual(code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["checks"][0]["name"], "no_checks_requested")

    def test_agent_matrix_cli_reports_missing_config(self) -> None:
        code, _, err = self._run(
            ["health", "agent-matrix", "--config", str(Path(self._tmp.name) / "missing.json"), "--json"]
        )
        self.assertEqual(code, 1)
        self.assertIn("config file not found", err)


if __name__ == "__main__":
    unittest.main()
