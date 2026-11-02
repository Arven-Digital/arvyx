from __future__ import annotations
from arvyx_control.replica_authority import authority_context

from http.server import ThreadingHTTPServer
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
import uuid
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from arvyx_control.api import make_handler
from arvyx_control.auth import issue_token, list_tokens, resolve_identity, revoke_token
from arvyx_control.cli import main as cli_main
from arvyx_control.control import (
    accept_handoff,
    approve_request,
    create_handoff,
    create_task,
    list_approvals,
    list_handoffs,
    list_tasks,
    post_thread,
    request_approval,
)
from arvyx_control.mcp import handle_request, tools_for_profile
from arvyx_control.recall import recall
from arvyx_control.session import get_session, set_session
from arvyx_control.vault import init_vault


class SessionStateTests(unittest.TestCase):
    def test_set_then_get_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            written = set_session(vault, "demobot", "Debugging quota reconciliation; blocker: Turso sync lag.")
            self.assertEqual(written.path, "agents/demobot/SESSION-STATE.md")
            read = get_session(vault, "demobot")
            self.assertIn("quota reconciliation", read.content)
            self.assertEqual(read.agent, "demobot")
            self.assertTrue(read.updated_at)

    def test_missing_session_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            with self.assertRaises(FileNotFoundError):
                get_session(vault, "nobody")

    def test_session_refuses_literal_secret_allows_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            with self.assertRaises(ValueError):
                set_session(vault, "demobot", "token = ghp_" + "a" * 24)
            ok = set_session(vault, "demobot", "creds at secret://railway/DATABASE_URL")
            self.assertTrue(ok.path)

    def test_session_state_is_excluded_from_curated_recall(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            set_session(vault, "demobot", "Working on the zephyr subsystem migration right now.")
            result = recall("zephyr subsystem migration", vault=vault)
            self.assertFalse(any("SESSION-STATE.md" in s.path for s in result.sources))
            self.assertIn('zephyr subsystem migration', get_session(vault, 'demobot').content)

    def test_doctor_ok_with_session_state(self) -> None:
        from arvyx_control.doctor import doctor

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            set_session(vault, "demobot", "current state note")
            self.assertTrue(doctor(vault=vault).ok)


class SessionMcpProfileTests(unittest.TestCase):
    def test_agent_profile_has_memory_and_coordination_without_authority_tools(self) -> None:
        tools = set(tools_for_profile("agent"))
        self.assertIn("memory.session_get", tools)
        self.assertIn("memory.session_set", tools)
        self.assertIn("memory.suggest", tools)
        self.assertIn("control.task_create", tools)
        self.assertIn("control.approval_request", tools)
        self.assertIn("control.approval_consume", tools)
        self.assertIn("control.thread_ack", tools)
        self.assertNotIn("control.approval_approve", tools)
        self.assertNotIn("control.handoff_review", tools)
        self.assertNotIn("memory.promote", tools)
        self.assertNotIn("secret.resolve", tools)

    def test_read_only_cannot_get_or_set_session_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            set_session(vault, "demobot", "state")
            got = handle_request(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": "memory.session_get", "arguments": {"agent": "demobot"}}},
                vault=vault, allowed_tools=set(tools_for_profile("read-only")),
            )
            self.assertIn("error", got)
            blocked = handle_request(
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "memory.session_set", "arguments": {"agent": "demobot", "content": "x"}}},
                vault=vault, allowed_tools=set(tools_for_profile("read-only")),
            )
            self.assertIn("error", blocked)

    def test_agent_can_read_another_agents_session_but_only_writes_its_own(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            set_session(vault, "vesper", "vesper is migrating the relay subsystem")
            # demobot (agent identity) reads vesper's session for a handoff:
            # the `agent` arg is NOT rebound on session_get
            got = handle_request(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": "memory.session_get", "arguments": {"agent": "vesper"}}},
                vault=vault, allowed_tools=set(tools_for_profile("operator")), actor="demobot",
            )
            self.assertEqual(got["result"]["structuredContent"]["agent"], "vesper")
            self.assertIn("relay subsystem", got["result"]["structuredContent"]["content"])
            # but a write is still identity-bound: demobot claiming vesper writes demobot
            from arvyx_control.replica_authority import authority_context
            with authority_context(vault, vault/'events.jsonl'):
                wrote = handle_request(
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                     "idempotency_key": "session-own-write-fixture",
                     "params": {"name": "memory.session_set", "arguments": {"agent": "vesper", "content": "hi"}}},
                    vault=vault, state=vault/'events.jsonl', allowed_tools=set(tools_for_profile("operator")), actor="demobot",
                )
            self.assertEqual(wrote["result"]["structuredContent"]["agent"], "demobot")


class SessionHttpIdentityTests(unittest.TestCase):
    def _serve(self, vault, state, **kwargs):
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(vault=vault, state=state, **kwargs))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, f"http://127.0.0.1:{server.server_port}"

    def _post(self, url, body, token):
        data = json.dumps(body).encode("utf-8")
        req = Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": f"session-test-{uuid.uuid4().hex}",
            },
            method="POST",
        )
        try:
            with urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _get(self, url, token=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        req = Request(url, headers=headers, method="GET")
        try:
            with urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_session_read_requires_dedicated_authenticated_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            set_session(vault, "demobot", "private in-flight state")
            state = Path(tmp) / "events.jsonl"
            memory_only = issue_token(vault, "vesper", scopes=["memory.read"]).token
            session_reader = issue_token(vault, "demobot", scopes=["session.read"]).token
            server, thread, base = self._serve(vault, state, mcp_profile="operator")
            try:
                self.assertEqual(self._get(f"{base}/memory/session?agent=demobot")[0], 401)
                self.assertEqual(self._get(f"{base}/memory/session?agent=demobot", memory_only)[0], 403)
                status, body = self._get(f"{base}/memory/session?agent=demobot", session_reader)
                self.assertEqual(status, 200)
                self.assertEqual(body["body"]["agent"], "demobot")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_session_write_binds_to_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            token = issue_token(vault, "demobot", scopes=["memory.read", "session.write"]).token
            no_write = issue_token(vault, "vesper", scopes=["memory.read"]).token
            server, thread, base = self._serve(vault, state, mcp_profile="operator")
            try:
                # demobot claims to be vesper, but identity binds it to demobot
                status, body = self._post(f"{base}/memory/session", {"agent": "vesper", "content": "hi"}, token)
                self.assertEqual(status, 201)
                self.assertEqual(body["body"]["agent"], "demobot")
                # vesper lacks session.write
                status2, _ = self._post(f"{base}/memory/session", {"agent": "vesper", "content": "hi"}, no_write)
                self.assertEqual(status2, 403)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_real_short_ttl_expires_without_editing_token_record(self) -> None:
        import time

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            issued = issue_token(vault, "demobot", scopes=["memory.read"], ttl_seconds=1)
            authorization = f"Bearer {issued.token}"
            self.assertIsNotNone(resolve_identity(vault, authorization))
            deadline = time.monotonic() + 3
            while resolve_identity(vault, authorization) is not None and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertIsNone(resolve_identity(vault, authorization))

    def test_issue_token_ttl_arguments_are_unambiguous_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            default = issue_token(vault, "demobot", scopes=["memory.read"])
            self.assertTrue(default.token)
            self.assertTrue(issue_token(vault, "demobot", scopes=["memory.read"], ttl_days=1).token)
            self.assertTrue(issue_token(vault, "demobot", scopes=["memory.read"], ttl_seconds=1).token)
            with self.assertRaisesRegex(ValueError, "mutually exclusive"):
                issue_token(vault, "demobot", scopes=["memory.read"], ttl_days=30, ttl_seconds=1)
            for invalid_days in (0, 366):
                with self.subTest(ttl_days=invalid_days), self.assertRaises(ValueError):
                    issue_token(vault, "demobot", scopes=["memory.read"], ttl_days=invalid_days)
            for invalid_seconds in (0, 31536001):
                with self.subTest(ttl_seconds=invalid_seconds), self.assertRaises(ValueError):
                    issue_token(vault, "demobot", scopes=["memory.read"], ttl_seconds=invalid_seconds)

    def test_named_slots_coexist_and_reissuing_one_does_not_invalidate_another(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            presence = issue_token(vault, "demobot", scopes=["control.read"], slot="presence")
            job_v1 = issue_token(vault, "demobot", scopes=["memory.read"], slot="job")
            job_v2 = issue_token(vault, "demobot", scopes=["memory.read"], slot="job")

            self.assertIsNotNone(resolve_identity(vault, f"Bearer {presence.token}"))
            self.assertIsNone(resolve_identity(vault, f"Bearer {job_v1.token}"))
            self.assertIsNotNone(resolve_identity(vault, f"Bearer {job_v2.token}"))
            self.assertEqual(presence.path, "registry/tokens/demobot.presence.json")
            self.assertEqual(job_v2.path, "registry/tokens/demobot.job.json")
            if os.name == "posix":  # chmod is a no-op beyond the read-only bit on Windows
                self.assertEqual((vault / presence.path).stat().st_mode & 0o777, 0o600)
                self.assertEqual((vault / job_v2.path).stat().st_mode & 0o777, 0o600)
            self.assertEqual({record.slot for record in list_tokens(vault).tokens}, {"job", "presence"})

    def test_revoke_is_slot_scoped_and_legacy_default_remains_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            legacy = issue_token(vault, "demobot", scopes=["memory.read"])
            presence = issue_token(vault, "demobot", scopes=["control.read"], slot="presence")

            revoked = revoke_token(vault, "demobot", slot="presence")
            self.assertEqual(revoked.slot, "presence")
            self.assertIsNone(resolve_identity(vault, f"Bearer {presence.token}"))
            self.assertIsNotNone(resolve_identity(vault, f"Bearer {legacy.token}"))
            self.assertTrue((vault / "registry/tokens/demobot.json").is_file())

    def test_legacy_slotless_record_remains_resolvable_listable_and_revocable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            issued = issue_token(vault, "demobot", scopes=["memory.read"])
            path = vault / issued.path
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload.pop("slot")
            path.write_text(json.dumps(payload), encoding="utf-8")

            self.assertIsNotNone(resolve_identity(vault, f"Bearer {issued.token}"))
            self.assertEqual(list_tokens(vault).tokens[0].slot, "default")
            self.assertEqual(revoke_token(vault, "demobot").slot, "default")
            self.assertIsNone(resolve_identity(vault, f"Bearer {issued.token}"))

    def test_agent_id_and_named_slot_namespaces_cannot_collide(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            source = vault / "registry/agents/demobot.json"
            collision_agent = vault / "registry/agents/demobot--presence.json"
            collision_agent.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

            presence = issue_token(vault, "demobot", scopes=["control.read"], slot="presence")
            other = issue_token(vault, "demobot--presence", scopes=["memory.read"])
            self.assertNotEqual(presence.path, other.path)
            self.assertEqual(resolve_identity(vault, f"Bearer {presence.token}").agent_id, "demobot")
            self.assertEqual(resolve_identity(vault, f"Bearer {other.token}").agent_id, "demobot--presence")

    def test_cli_issue_list_and_revoke_named_slot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cli_main(["auth", "issue", "demobot", "--vault", str(vault), "--slot", "job", "--scope", "memory.read", "--json"]), 0)
            issued = json.loads(output.getvalue())
            self.assertEqual(issued["slot"], "job")

            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cli_main(["auth", "list", "--vault", str(vault), "--json"]), 0)
            self.assertEqual(json.loads(output.getvalue())["tokens"][0]["slot"], "job")

            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cli_main(["auth", "revoke", "demobot", "--vault", str(vault), "--slot", "job", "--json"]), 0)
            self.assertEqual(json.loads(output.getvalue())["slot"], "job")

    def test_token_slot_rejects_path_or_ambiguous_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            for slot in ("", "../presence", "presence/job", "Presence", "a--b", "a" * 65):
                with self.subTest(slot=slot), self.assertRaisesRegex(ValueError, "invalid token slot"):
                    issue_token(vault, "demobot", scopes=["memory.read"], slot=slot)

    def test_agent_http_profile_rejects_cross_agent_terminal_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            with authority_context(vault, state):
                demobot = issue_token(
                    vault,
                    "demobot",
                    scopes=["control.read", "control.write"],
                ).token
                task = create_task(state, "Vesper-owned task", owner="vesper").task
                command = "deploy synthetic release"
                approval = request_approval(state, command, requester="vesper").approval
                approve_request(state, approval.id, approver="operator")
                handoff = create_handoff(state, "Foreign handoff", from_agent="vesper", to_agent="operator").handoff
                accept_handoff(state, handoff.id, actor="operator")
                foreign_thread = post_thread(
                    state,
                    title="Private Vesper thread",
                    body="synthetic",
                    actor="operator",
                    target="vesper",
                ).thread
                server, server_thread, base = self._serve(vault, state, mcp_profile="agent")

                def call(name, arguments):
                    return self._post(
                        f"{base}/mcp",
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {"name": name, "arguments": arguments},
                        },
                        demobot,
                    )

                try:
                    for name, arguments in (
                        ("control.task_done", {"task_id": task.id}),
                        ("control.approval_consume", {"approval_id": approval.id, "command": command}),
                        ("control.handoff_complete", {"handoff_id": handoff.id}),
                        ("control.thread_ack", {"thread_id": foreign_thread.id, "text": "foreign"}),
                        ("control.thread_inbox", {"target": "vesper"}),
                        ("control.approval_approve", {"approval_id": approval.id}),
                    ):
                        with self.subTest(tool=name):
                            status, body = call(name, arguments)
                            self.assertEqual(status, 200)
                            self.assertIn("error", body)
                    task_status, task_body = self._post(f"{base}/tasks/{task.id}/done", {}, demobot)
                    self.assertEqual(task_status, 400)
                    self.assertIn("task owner", task_body["body"]["error"])
                    approval_status, approval_body = self._post(
                        f"{base}/approvals/{approval.id}/consume",
                        {"command": command},
                        demobot,
                    )
                    self.assertEqual(approval_status, 400)
                    self.assertIn("approval requester", approval_body["body"]["error"])
                    self.assertEqual(next(item for item in list_tasks(state).tasks if item.id == task.id).status, "open")
                    self.assertEqual(
                        next(item for item in list_approvals(state).approvals if item.id == approval.id).status,
                        "approved",
                    )
                    self.assertEqual(
                        next(item for item in list_handoffs(state).handoffs if item.id == handoff.id).status,
                        "accepted",
                    )
                finally:
                    server.shutdown()
                    server.server_close()
                    server_thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
