from __future__ import annotations

from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.replica_authority import authority_context
from arvyx_control.api import handle_api_request
from arvyx_control.auth import issue_token
from arvyx_control import execution as execution_module
from arvyx_control.control import ControlEvent, _append_event, post_thread, read_events
from arvyx_control.execution import (
    acknowledge_execution_steer,
    cancel_execution,
    claim_execution,
    heartbeat_execution_as_target,
    list_execution_events,
    project_executions,
    request_execution_steer,
    resume_execution,
)
from arvyx_control.session_return import request_session_return
from arvyx_control.vault import init_vault

UTC = timezone.utc
T0 = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)


class ExecutionWorkbenchKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "events.jsonl"
        self.vault = Path(self.tmp.name) / "vault"
        self.vault.mkdir()
        self.enterContext(authority_context(self.vault, self.state))
        post_thread(self.state, title="work", actor="esme", target="demobot", thread_type="ask", actor_identity_bound=True)
        self.execution = claim_execution(self.state, worker="w1", execution_capable_targets={"demobot"}, now=T0, lease_seconds=60)
        assert self.execution is not None

    def test_cancel_pauses_and_fences_old_attempt_until_resume_claims_fresh_attempt(self) -> None:
        paused = cancel_execution(self.state, execution_id=self.execution.id, reason="operator pause", cancelled_by="operator", now=T0 + timedelta(seconds=1))
        self.assertEqual(paused.status, "paused")
        self.assertIsNone(claim_execution(self.state, worker="w2", execution_capable_targets={"demobot"}, now=T0 + timedelta(minutes=5)))
        with self.assertRaisesRegex(ValueError, "not live|leased"):
            heartbeat_execution_as_target(self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id, actor="demobot", now=T0 + timedelta(seconds=2))
        with self.assertRaisesRegex(ValueError, "not live|stale"):
            request_session_return(self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id, actor="demobot", message="safe return", expected_word_count=None, idempotency_key="old-attempt-key-0001", now=T0 + timedelta(seconds=2))
        pending = resume_execution(self.state, execution_id=self.execution.id, resumed_by="operator", now=T0 + timedelta(minutes=5, seconds=1))
        self.assertEqual(pending.status, "pending")
        fresh = claim_execution(self.state, worker="w2", execution_capable_targets={"demobot"}, now=T0 + timedelta(minutes=5, seconds=2))
        assert fresh is not None
        self.assertNotEqual(fresh.attempt_id, self.execution.attempt_id)

    def test_steer_is_bounded_secret_safe_idempotent_and_attempt_fenced(self) -> None:
        first = request_execution_steer(self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id, message="focus on tests", requested_by="operator", idempotency_key="steer-request-key-001", now=T0 + timedelta(seconds=1))
        same = request_execution_steer(self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id, message="focus on tests", requested_by="operator", idempotency_key="steer-request-key-001", now=T0 + timedelta(seconds=2))
        self.assertEqual(first["request_id"], same["request_id"])
        self.assertEqual(sum(e.type == "execution.steer.requested" for e in read_events(self.state)), 1)
        with self.assertRaisesRegex(ValueError, "another payload"):
            request_execution_steer(self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id, message="different", requested_by="operator", idempotency_key="steer-request-key-001", now=T0 + timedelta(seconds=2))
        secret_shaped = "".join(map(chr, (103, 104, 112, 95))) + "abcdefghijklmnopqrstuvwxyz123456"
        with self.assertRaisesRegex(ValueError, "secret-shaped"):
            request_execution_steer(self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id, message=f"token {secret_shaped}", requested_by="operator", idempotency_key="steer-request-key-002")
        ack = acknowledge_execution_steer(self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id, request_id=first["request_id"], actor="demobot", message="understood", idempotency_key="steer-ack-key-00001", now=T0 + timedelta(seconds=3))
        self.assertEqual(ack["status"], "acknowledged")
        self.assertEqual(acknowledge_execution_steer(self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id, request_id=first["request_id"], actor="demobot", message="understood", idempotency_key="steer-ack-key-00001", now=T0 + timedelta(seconds=4))["ack_id"], ack["ack_id"])
        cancel_execution(self.state, execution_id=self.execution.id, reason="pause", cancelled_by="operator", now=T0 + timedelta(seconds=5))
        with self.assertRaisesRegex(ValueError, "not live|stale"):
            acknowledge_execution_steer(self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id, request_id=first["request_id"], actor="demobot", message="late", idempotency_key="steer-ack-key-00002")

    def test_steer_request_rejects_lease_at_and_beyond_expiry(self) -> None:
        for offset, key in ((60, "steer-expiry-boundary-01"), (61, "steer-expiry-beyond-0001")):
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, "lease expired"):
                request_execution_steer(
                    self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id,
                    message="too late", requested_by="operator", idempotency_key=key,
                    now=T0 + timedelta(seconds=offset),
                )

    def test_steer_ack_rejects_lease_at_and_beyond_expiry(self) -> None:
        requested = request_execution_steer(
            self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id,
            message="before expiry", requested_by="operator",
            idempotency_key="aaaaaaaaaaaaaaaa", now=T0 + timedelta(seconds=1),
        )
        for offset, key in ((60, "ack-expiry-boundary-001"), (61, "ack-expiry-beyond-00001")):
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, "lease expired"):
                acknowledge_execution_steer(
                    self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id,
                    request_id=str(requested["request_id"]), actor="demobot", message="too late",
                    idempotency_key=key, now=T0 + timedelta(seconds=offset),
                )

    def test_steer_ack_rejects_cross_execution_and_corrupted_request_lineage(self) -> None:
        request = request_execution_steer(
            self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id,
            message="bound request", requested_by="operator",
            idempotency_key="steer-lineage-request-01", now=T0 + timedelta(seconds=1),
        )
        post_thread(self.state, title="other", actor="esme", target="demobot", thread_type="ask", actor_identity_bound=True)
        other = claim_execution(self.state, worker="w2", execution_capable_targets={"demobot"}, now=T0 + timedelta(seconds=2), lease_seconds=60)
        assert other is not None
        with self.assertRaisesRegex(ValueError, "unknown steer request"):
            acknowledge_execution_steer(
                self.state, execution_id=other.id, attempt_id=other.attempt_id,
                request_id=str(request["request_id"]), actor="demobot", message="wrong execution",
                idempotency_key="steer-cross-exec-ack-01", now=T0 + timedelta(seconds=3),
            )
        for index, (task_id, payload_execution_id) in enumerate((("corrupt-task", self.execution.id), (self.execution.id, "corrupt-execution"))):
            request_id = f"forged-request-{index:04d}"
            _append_event(self.state, ControlEvent(
                id=f"forged-event-{index}", type="execution.steer.requested", task_id=task_id,
                timestamp="2026-09-07T12:00:04Z",
                payload={"request_id": request_id, "execution_id": payload_execution_id, "attempt_id": self.execution.attempt_id},
            ))
            with self.subTest(task_id=task_id, payload_execution_id=payload_execution_id), self.assertRaisesRegex(ValueError, "unknown steer request"):
                acknowledge_execution_steer(
                    self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id,
                    request_id=request_id, actor="demobot", message="reject forged lineage",
                    idempotency_key=f"forged-ack-key-{index:04d}", now=T0 + timedelta(seconds=5),
                )

    def test_concurrent_steer_requests_and_acknowledgements_append_once(self) -> None:
        def request_once(_: int) -> str:
            with authority_context(self.vault, self.state):
                return str(request_execution_steer(
                    self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id,
                    message="one request", requested_by="operator",
                    idempotency_key="concurrent-steer-request", now=T0 + timedelta(seconds=1),
                )["request_id"])
        with ThreadPoolExecutor(max_workers=8) as pool:
            request_ids = list(pool.map(request_once, range(24)))
        self.assertEqual(len(set(request_ids)), 1)

        def ack_once(_: int) -> str:
            with authority_context(self.vault, self.state):
                return str(acknowledge_execution_steer(
                    self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id,
                    request_id=request_ids[0], actor="demobot", message="one ack",
                    idempotency_key="concurrent-steer-ack-key", now=T0 + timedelta(seconds=2),
                )["ack_id"])
        with ThreadPoolExecutor(max_workers=8) as pool:
            ack_ids = list(pool.map(ack_once, range(24)))
        self.assertEqual(len(set(ack_ids)), 1)
        events = read_events(self.state)
        self.assertEqual(sum(event.type == "execution.steer.requested" for event in events), 1)
        self.assertEqual(sum(event.type == "execution.steer.acknowledged" for event in events), 1)

    def test_event_history_is_cursor_ordered_bounded_and_safe(self) -> None:
        request_execution_steer(self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id, message="safe", requested_by="operator", idempotency_key="steer-request-key-003", now=T0 + timedelta(seconds=1))
        page = list_execution_events(self.state, execution_id=self.execution.id, target="demobot", limit=2)
        self.assertEqual(len(page["events"]), 2)
        self.assertTrue(page["has_more"])
        rest = list_execution_events(self.state, execution_id=self.execution.id, target="demobot", after=page["next_cursor"], limit=500)
        self.assertFalse(set(e["id"] for e in page["events"]) & set(e["id"] for e in rest["events"]))
        encoded = json.dumps(page) + json.dumps(rest)
        self.assertNotIn("provider_receipt", encoded)
        self.assertNotIn("credential", encoded)
        with self.assertRaisesRegex(ValueError, "at most 500"):
            list_execution_events(self.state, execution_id=self.execution.id, target="demobot", limit=501)

    def test_large_event_history_streams_once_and_materializes_only_page(self) -> None:
        for index in range(5000):
            _append_event(self.state, ControlEvent(
                id=f"noise-{index:05d}", type="bus.posted", task_id=f"noise-task-{index}",
                timestamp="2026-09-07T12:00:01Z", payload={"message": "safe noise"},
            ))
        for index in range(8):
            payload = self.execution.to_dict()
            payload["updated_at"] = "2026-09-07T12:00:02Z"
            _append_event(self.state, ControlEvent(
                id=f"execution-event-{index}", type="execution.heartbeat", task_id=self.execution.id,
                timestamp="2026-09-07T12:00:02Z", payload=payload,
            ))
        with patch("arvyx_control.execution._streamed_execution_events", wraps=execution_module._streamed_execution_events) as stream, patch("arvyx_control.execution._safe_execution_event", wraps=lambda event: {"id": event.id}) as safe:
            page = list_execution_events(self.state, execution_id=self.execution.id, target="demobot", limit=3)
        self.assertEqual(stream.call_count, 1)
        self.assertEqual(safe.call_count, 3)
        self.assertTrue(page["has_more"])

    def test_event_history_serves_a_log_past_the_snapshot_ceiling(self) -> None:
        """A log bigger than the snapshot ceiling is a scaling fact, not an outage.

        The route streams, so it answers in bounded memory whatever the log
        weighs. ``read_execution_event_snapshot`` still fails closed on its own
        ceiling; the route simply no longer depends on it.
        """
        for index in range(200):
            payload = self.execution.to_dict()
            payload["updated_at"] = "2026-09-07T12:00:02Z"
            _append_event(self.state, ControlEvent(
                id=f"execution-event-{index}", type="execution.heartbeat", task_id=self.execution.id,
                timestamp="2026-09-07T12:00:02Z", payload=payload,
            ))
        self.assertGreater(self.state.stat().st_size, 64)
        with patch("arvyx_control.execution.EXECUTION_EVENT_SNAPSHOT_MAX_BYTES", 64):
            page = list_execution_events(
                self.state, execution_id=self.execution.id, target="demobot", limit=3,
            )
            self.assertEqual(len(page["events"]), 3)
            self.assertTrue(page["has_more"])
            with self.assertRaisesRegex(ValueError, "snapshot exceeds"):
                execution_module.read_execution_event_snapshot(self.state)


class ExecutionWorkbenchSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name); self.state = root / "events.jsonl"; self.vault = root / "vault"; init_vault(self.vault)
        self.enterContext(authority_context(self.vault, self.state))
        self.demobot = issue_token(self.vault, "demobot", scopes=["control.read", "control.write"]).token
        self.vesper = issue_token(self.vault, "vesper", scopes=["control.read", "control.write"]).token
        self.operator = "operator-secret"
        post_thread(self.state, title="work", actor="esme", target="demobot", thread_type="ask", actor_identity_bound=True)
        self.execution = claim_execution(self.state, worker="w", execution_capable_targets={"demobot"}, lease_seconds=3600)
        assert self.execution is not None
        self.seq = 0

    def api(self, token: str, method: str, path: str, body: dict | None = None):
        self.seq += 1
        payload_key = (body or {}).get("idempotency_key")
        if payload_key is None and isinstance((body or {}).get("params"), dict):
            arguments = (body or {})["params"].get("arguments", {})
            if isinstance(arguments, dict):
                payload_key = arguments.get("idempotency_key")
        key = str(payload_key or f"workbench-http-key-{self.seq:04d}")
        return handle_api_request(method=method, path=path, body=body, vault=self.vault, state=self.state, bearer_secret=self.operator, authorization=f"Bearer {token}", idempotency_key=key, mcp_profile="operator")

    def test_http_event_history_serves_a_log_past_the_snapshot_ceiling(self) -> None:
        """Regression (2026-09-24): the route still took a whole-log snapshot first, so
        every call failed once the production log passed 16 MiB."""
        for index in range(200):
            payload = self.execution.to_dict()
            _append_event(self.state, ControlEvent(
                id=f"route-event-{index}", type="execution.heartbeat", task_id=self.execution.id,
                timestamp="2026-09-07T12:00:02Z", payload=payload,
            ))
        with patch("arvyx_control.execution.EXECUTION_EVENT_SNAPSHOT_MAX_BYTES", 64):
            events = self.api(self.demobot, "GET", f"/executions/{self.execution.id}/events?limit=5")
            denied = self.api(self.vesper, "GET", f"/executions/{self.execution.id}/events")
            unknown = self.api(self.demobot, "GET", "/executions/execution_unknown/events")
        self.assertEqual(events.status, 200, events.body)
        self.assertEqual(len(events.body["events"]), 5)
        self.assertTrue(events.body["has_more"])
        self.assertEqual(denied.status, 403)
        self.assertEqual(unknown.status, 400)

    def test_http_routes_order_authority_and_target_scope(self) -> None:
        events = self.api(self.demobot, "GET", f"/executions/{self.execution.id}/events")
        self.assertEqual(events.status, 200)
        self.assertEqual(self.api(self.vesper, "GET", f"/executions/{self.execution.id}/events").status, 403)
        self.assertEqual(self.api(self.demobot, "POST", f"/executions/{self.execution.id}/cancel", {"reason": "x"}).status, 403)
        steer = self.api(self.operator, "POST", f"/executions/{self.execution.id}/steer", {"attempt_id": self.execution.attempt_id, "message": "focus", "idempotency_key": "steer-http-body-key1"})
        self.assertEqual(steer.status, 201)
        request_id = steer.body["steer"]["request_id"]
        ack = self.api(self.demobot, "POST", f"/executions/{self.execution.id}/steer-acknowledgement", {"attempt_id": self.execution.attempt_id, "request_id": request_id, "message": "ok", "idempotency_key": "steer-http-ack-key01"})
        self.assertEqual(ack.status, 200)
        paused = self.api(self.operator, "POST", f"/executions/{self.execution.id}/cancel", {"reason": "pause"})
        self.assertEqual(paused.body["status"], "paused")
        self.assertEqual(self.api(self.operator, "POST", f"/executions/{self.execution.id}/resume", {}).body["status"], "pending")

    def test_mcp_exposes_event_read_and_target_ack_but_not_operator_mutations(self) -> None:
        listed = self.api(self.demobot, "POST", "/mcp", {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"control.execution_event_list","arguments":{"execution_id":self.execution.id}}})
        rpc = json.loads(listed.body)
        self.assertIn("events", rpc["result"]["structuredContent"])
        tools = self.api(self.demobot, "POST", "/mcp", {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
        names = {x["name"] for x in json.loads(tools.body)["result"]["tools"]}
        self.assertIn("control.execution_steer_acknowledge", names)
        self.assertNotIn("control.execution_cancel", names)
        self.assertNotIn("control.execution_resume", names)
        self.assertNotIn("control.execution_steer", names)

        steer = request_execution_steer(
            self.state, execution_id=self.execution.id, attempt_id=self.execution.attempt_id,
            message="focus", requested_by="operator", idempotency_key="mcp-steer-request-01",
        )
        acked = self.api(self.demobot, "POST", "/mcp", {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "control.execution_steer_acknowledge", "arguments": {
                    "execution_id": self.execution.id, "attempt_id": self.execution.attempt_id,
                    "request_id": steer["request_id"], "message": "understood",
                    "idempotency_key": "bbbbbbbbbbbbbbbb",
                },
            },
        })
        ack_rpc = json.loads(acked.body)
        self.assertEqual(
            ack_rpc["result"]["structuredContent"]["steer_acknowledgement"]["status"],
            "acknowledged",
        )

    def test_operator_mcp_does_not_advertise_or_execute_target_only_event_history(self) -> None:
        tools = self.api(self.operator, "POST", "/mcp", {
            "jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {},
        })
        names = {tool["name"] for tool in json.loads(tools.body)["result"]["tools"]}
        self.assertNotIn("control.execution_event_list", names)

        called = self.api(self.operator, "POST", "/mcp", {
            "jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {
                "name": "control.execution_event_list",
                "arguments": {"execution_id": self.execution.id},
            },
        })
        error = json.loads(called.body)["error"]
        self.assertIn("not allowlisted", error["message"])


if __name__ == "__main__":
    unittest.main()
