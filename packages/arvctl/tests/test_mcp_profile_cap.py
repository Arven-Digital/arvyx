"""Identity-bound agent tokens never exceed the ``agent`` MCP profile.

Production launches the API with ``--mcp-profile operator`` so the dashboard
and ``arvctl`` (shared operator secret) get the full surface. The effective
tool set is ``profile ∩ scopes``, so before this cap a bound agent token
carrying ``control.write`` also received ``control.approval_approve`` and
``control.handoff_review`` - exactly the authority-bearing tools the agent
profile was written to withhold. The cap is per identity: agent tokens are
capped at ``agent``, the operator secret keeps the server profile, and a
``read-only`` server profile stays read-only for everyone.
"""
from __future__ import annotations

import json
import tempfile
import unittest
import uuid
from pathlib import Path

from arvyx_control.replica_authority import authority_context
from arvyx_control.api import handle_api_request
from arvyx_control.auth import issue_token
from arvyx_control.mcp import AGENT_CONTROL_TOOL_NAMES
from arvyx_control.vault import init_vault

WITHHELD_FROM_AGENTS = ("control.approval_approve", "control.handoff_review")
CHAIN_TOOLS = (
    "control.thread_ack",
    "control.thread_done",
    "control.execution_session_get",
    "control.execution_heartbeat",
    "control.execution_session_return_request",
    "control.execution_session_return_get",
    "control.delivery_receipt",
)


class AgentTokenProfileCapTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.state = root / "events.jsonl"
        self.vault = root / "vault"
        self.enterContext(authority_context(self.vault, self.state))
        init_vault(self.vault)
        self.operator_secret = "operator-shared-secret-for-profile-cap"
        self.agent_token = issue_token(
            self.vault, "demobot", scopes=["control.read", "control.write", "control.delivery"],
        ).token

    def _rpc(self, *, bearer: str, profile: str, method: str, params: dict) -> dict:
        response = handle_api_request(
            method="POST",
            path="/mcp",
            body={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {bearer}",
            mcp_profile=profile,
        )
        self.assertEqual(response.status, 200, response.body)
        return json.loads(response.body) if isinstance(response.body, str) else response.body

    def _tools(self, *, bearer: str, profile: str) -> set[str]:
        body = self._rpc(bearer=bearer, profile=profile, method="tools/list", params={})
        return {tool["name"] for tool in body["result"]["tools"]}

    def test_bound_agent_token_is_capped_at_agent_profile_under_operator_server(self) -> None:
        advertised = self._tools(bearer=self.agent_token, profile="operator")
        for name in WITHHELD_FROM_AGENTS:
            self.assertNotIn(name, advertised, f"{name} leaked to a bound agent token")
        for name in CHAIN_TOOLS:
            self.assertIn(name, advertised, f"{name} missing from the capped agent surface")
        self.assertTrue(set(AGENT_CONTROL_TOOL_NAMES).issubset(advertised))

        # Calling a withheld tool fails closed rather than acting.
        body = self._rpc(
            bearer=self.agent_token,
            profile="operator",
            method="tools/call",
            params={
                "name": "control.approval_approve",
                "arguments": {"approval_id": "approval_x", "idempotency_key": f"cap-{uuid.uuid4().hex}"},
            },
        )
        self.assertIn("error", body)
        self.assertIn("not allowlisted", str(body["error"].get("message", body["error"])))

    def test_operator_secret_keeps_the_operator_profile(self) -> None:
        advertised = self._tools(bearer=self.operator_secret, profile="operator")
        for name in WITHHELD_FROM_AGENTS:
            self.assertIn(name, advertised)

    def test_read_only_server_profile_stays_read_only_for_agent_tokens(self) -> None:
        advertised = self._tools(bearer=self.agent_token, profile="read-only")
        self.assertNotIn("control.thread_ack", advertised)
        self.assertNotIn("control.approval_approve", advertised)
        self.assertIn("control.thread_inbox", advertised)


if __name__ == "__main__":
    unittest.main()
