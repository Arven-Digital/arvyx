"""Approval authority at the real HTTP boundary, with synthetic identities only."""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from arvyx_control.replica_authority import authority_context
from arvyx_control.api import make_handler
from arvyx_control.auth import ALL_SCOPES, Identity, OPERATOR_IDENTITY


class ApprovalAuthorizationTests(unittest.TestCase):
    demo = False

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name) / "events.jsonl"
        self.vault = Path(tmp.name) / "vault"
        self.enterContext(authority_context(self.vault, self.state))
        identities = {
            "Bearer demobot": Identity("demobot", frozenset({"control.read", "control.write"}), "agent"),
            "Bearer vesper": Identity("vesper", ALL_SCOPES, "agent"),
            "Bearer operator": OPERATOR_IDENTITY,
        }
        # No token issuance or real auth store: mock only credential resolution.
        resolver = patch("arvyx_control.api.resolve_identity", side_effect=lambda _vault, authorization, **kw: identities.get(authorization))
        resolver.start()
        self.addCleanup(resolver.stop)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(
            vault=self.vault, state=self.state, mcp_profile="operator",
            allow_unauthenticated_demo=self.demo,
        ))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)

    def close_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(self, path: str, body: dict, actor: str | None = "demobot") -> tuple[int, dict]:
        headers = {"Content-Type": "application/json", "Idempotency-Key": uuid.uuid4().hex}
        if actor:
            headers["Authorization"] = f"Bearer {actor}"
        req = Request(f"http://127.0.0.1:{self.server.server_port}{path}",
                      data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            response = urlopen(req, timeout=5)
        except HTTPError as exc:
            response = exc
        with response:
            payload = json.loads(response.read())
            return response.code, payload.get("body", payload)

    def approval(self) -> str:
        status, body = self.request("/approvals/request", {"command": "synthetic-check", "requester": "operator"})
        self.assertEqual(status, 201, body)
        self.assertEqual(body["approval"]["requester"], "demobot")
        return body["approval"]["id"]

    def test_agents_cannot_approve_own_or_other_request(self) -> None:
        approval_id = self.approval()
        before = self.state.read_bytes()
        for actor in ("demobot", "vesper"):
            with self.subTest(actor=actor):
                status, body = self.request(f"/approvals/{approval_id}/approve", {"approver": "operator"}, actor)
                self.assertEqual(status, 403, body)
                self.assertIn("operator identity required", body["error"])
                self.assertEqual(self.state.read_bytes(), before)

    def test_operator_approves_and_requester_consumes(self) -> None:
        approval_id = self.approval()
        status, body = self.request(f"/approvals/{approval_id}/approve", {}, "operator")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["approval"]["status"], "approved")
        status, body = self.request(f"/approvals/{approval_id}/consume", {"command": "synthetic-check"})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["approval"]["status"], "consumed")

    def test_explicit_anonymous_demo_can_approve(self) -> None:
        approval_id = self.approval()
        before = self.state.read_bytes()
        status, body = self.request(f"/approvals/{approval_id}/approve", {}, None)
        if not self.demo:
            self.assertEqual(status, 401, body)
            self.assertEqual(self.state.read_bytes(), before)
            return
        self.assertEqual(status, 200, body)
        self.assertEqual(body["approval"]["status"], "approved")

    def test_agent_task_and_handoff_mutations_continue(self) -> None:
        status, body = self.request("/tasks", {"title": "Synthetic task"})
        self.assertEqual(status, 201, body)
        task_id = body["task"]["id"]
        status, body = self.request(f"/tasks/{task_id}/done", {})
        self.assertEqual(status, 200, body)
        status, body = self.request("/handoffs", {"title": "Synthetic handoff", "to_agent": "vesper", "summary": "Synthetic only"})
        self.assertEqual(status, 201, body)
        handoff_id = body["handoff"]["id"]
        status, body = self.request(f"/handoffs/{handoff_id}/accept", {}, "vesper")
        self.assertEqual(status, 200, body)
        status, body = self.request(f"/handoffs/{handoff_id}/complete", {"summary": "Synthetic completion"}, "vesper")
        self.assertEqual(status, 200, body)

    def test_mcp_approval_decision_is_also_denied_without_state_mutation(self) -> None:
        approval_id = self.approval()
        before = self.state.read_bytes()
        for actor in ("demobot", "vesper"):
            status, body = self.request("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "control.approval_approve", "arguments": {"approval_id": approval_id, "approver": "operator"},
            }}, actor)
            self.assertEqual(status, 200, body)
            self.assertIn("not allowlisted", body["error"]["message"])
            self.assertEqual(self.state.read_bytes(), before)


class DemoApprovalAuthorizationTests(ApprovalAuthorizationTests):
    demo = True


if __name__ == "__main__":
    unittest.main()
