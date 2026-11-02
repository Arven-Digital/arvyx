"""MCP surface hardening.

Findings source: an exact-model review of commit 5882f3f (qwen3.8-max), first
pass plus same-model adjudication over the untruncated enforcement paths. Each
test names the finding it closes.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from arvyx_control.replica_authority import authority_context
from arvyx_control.api import default_audit_log, handle_api_request
from arvyx_control.mcp import (
    TOOL_NAMES,
    UNBOUND_IDENTITY_ARGUMENT_TOOLS,
    _tool_actor_args,
    handle_request,
)
from arvyx_control.security import contains_literal_secret, redact_secrets
from arvyx_control.vault import init_vault

ACTOR_ARGUMENT_NAMES = {
    # Every argument name the shipped tools use to name an acting, owning, or
    # targeted identity. Keep this in step with the live schemas: a name that
    # is missing here is an identity argument the guard cannot see.
    "actor", "author", "owner", "approver", "requester", "agent",
    "from_agent", "to_agent", "reviewer", "target",
    "promoted_by", "rejected_by", "refined_by", "replayed_by",
}


class McpHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.state = root / "events.jsonl"
        self.vault = root / "vault"
        self.enterContext(authority_context(self.vault, self.state))
        init_vault(self.vault)
        self.operator_secret = "operator-secret-for-mcp-hardening"

    def _rpc(self, method: str, params: dict, **kwargs) -> dict:
        return handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            vault=self.vault,
            state=self.state,
            **kwargs,
        )

    def test_default_tool_surface_is_least_privilege(self) -> None:
        """B1: omitting allowed_tools must not expose the whole tool catalog."""
        listed = self._rpc("tools/list", {})
        names = {tool["name"] for tool in listed["result"]["tools"]}
        self.assertIn("memory.recall", names)
        for withheld in ("secret.resolve", "control.approval_approve", "control.thread_post"):
            self.assertNotIn(withheld, names)
        denied = self._rpc(
            "tools/call",
            {"name": "control.thread_post", "arguments": {"title": "x", "target": "demobot"}},
        )
        self.assertIn("error", denied)

    def test_explicit_profiles_still_work(self) -> None:
        """The least-privilege default must not change explicit callers."""
        listed = self._rpc("tools/list", {}, allowed_tools=set(TOOL_NAMES))
        names = {tool["name"] for tool in listed["result"]["tools"]}
        self.assertIn("control.approval_approve", names)
        self.assertIn("secret.resolve", names)

    def test_secret_resolution_without_an_audit_lane_fails_closed(self) -> None:
        """M3: requiring the audit lane must refuse rather than resolve silently."""
        self._write_env_broker()
        with mock.patch('arvyx_control.mcp.append_audit_once', side_effect=OSError('synthetic audit unavailable')):
            response = self._rpc(
                "tools/call",
                {
                    "name": "secret.resolve",
                    "arguments": {"ref": "secret://demo/KEY", "idempotency_key": "k" * 16},
                },
                allowed_tools={"secret.resolve"},
                require_secret_audit=True,
            )
        self.assertIn("error", response)
        self.assertIn("mutation durability unavailable before dispatch", json.dumps(response))

    def test_secret_resolution_default_requires_the_audit_lane(self) -> None:
        """M3 residual: the library default must not resolve a secret unaudited."""
        self._write_env_broker()
        with mock.patch('arvyx_control.mcp.append_audit_once', side_effect=OSError('synthetic audit unavailable')):
            response = self._rpc(
                "tools/call",
                {
                    "name": "secret.resolve",
                    "arguments": {"ref": "secret://demo/KEY", "idempotency_key": "z" * 16},
                },
                allowed_tools={"secret.resolve"},
            )
        self.assertIn("error", response)
        self.assertIn("mutation durability unavailable before dispatch", json.dumps(response))

    def _write_env_broker(self) -> None:
        arvyx = self.vault / ".arvyx"
        arvyx.mkdir(parents=True, exist_ok=True)
        (arvyx / "secret-brokers.json").write_text(
            json.dumps({"brokers": {"demo": {"provider": "env"}}}), encoding="utf-8"
        )

    def _audit_entries(self) -> list[dict]:
        log = default_audit_log(self.state)
        if not log.is_file():
            return []
        return [
            json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()
        ]

    def _http_resolve_secret(self, idempotency_key: str) -> dict:
        response = handle_api_request(
            method="POST",
            path="/mcp",
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "secret.resolve",
                    "arguments": {"ref": "secret://demo/KEY", "idempotency_key": idempotency_key},
                },
            },
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {self.operator_secret}",
            mcp_profile="operator",
        )
        return json.loads(response.body) if isinstance(response.body, str) else response.body

    def test_http_secret_resolution_supplies_the_mcp_audit_lane(self) -> None:
        """HTTP owns one durable pair; MCP must not claim/audit it a second time.

        Assert durable intent/outcome identity and actual successful resolution,
        not merely a tool-labeled denial entry. The API supplies mutation_claimed
        to MCP only after its own intent is durable.
        """
        self._write_env_broker()
        with mock.patch.dict(os.environ, {"KEY": "lane155-resolved-value"}):
            body = self._http_resolve_secret("http-mcp-audit-lane-0001")
        self.assertNotIn("error", body, json.dumps(body))
        mcp_entries = [
            entry
            for entry in self._audit_entries()
            if entry.get("surface") == "api" and entry.get("tool") == "secret.resolve"
        ]
        self.assertEqual(len(mcp_entries), 2)
        self.assertEqual(
            {entry.get("phase") for entry in mcp_entries},
            {"intent", "outcome"},
            f"the HTTP route did not reach the MCP audit lane: {self._audit_entries()}",
        )

    def test_http_secret_resolution_succeeds_and_emits_intent_outcome_pair(self) -> None:
        """M3: the HTTP surface must resolve a real secret and emit the MCP pair."""
        self._write_env_broker()
        with mock.patch.dict(os.environ, {"KEY": "lane155-resolved-value"}):
            body = self._http_resolve_secret("http-mcp-audit-lane-0002")
        self.assertNotIn("error", body, json.dumps(body))
        self.assertEqual(
            ((body.get("result") or {}).get("structuredContent") or {}).get("value"),
            "lane155-resolved-value",
        )
        mcp_entries = {
            entry["phase"]: entry
            for entry in self._audit_entries()
            if entry.get("surface") == "api" and entry.get("tool") == "secret.resolve"
        }
        self.assertEqual(set(mcp_entries), {"intent", "outcome"}, f"missing MCP pair: {mcp_entries}")
        self.assertEqual(
            mcp_entries["intent"]["operation_id"], mcp_entries["outcome"]["operation_id"]
        )
        self.assertEqual(mcp_entries["outcome"]["decision"], "allowed")

    def test_actor_argument_tools_are_bound_or_documented(self) -> None:
        """M4: a tool that accepts an identity argument must bind it or document why not."""
        listed = self._rpc("tools/list", {}, allowed_tools=set(TOOL_NAMES))
        offenders = []
        for tool in listed["result"]["tools"]:
            properties = set((tool.get("inputSchema") or {}).get("properties") or {})
            if (
                properties & ACTOR_ARGUMENT_NAMES
                and not _tool_actor_args(tool["name"])
                and tool["name"] not in UNBOUND_IDENTITY_ARGUMENT_TOOLS
            ):
                offenders.append(tool["name"])
        self.assertEqual(offenders, [])
        # Every documented exemption must still name a real tool with an identity
        # argument, so the list cannot rot into stale permission.
        names = {tool["name"] for tool in listed["result"]["tools"]}
        for tool_name, reason in UNBOUND_IDENTITY_ARGUMENT_TOOLS.items():
            self.assertIn(tool_name, names)
            self.assertTrue(reason.strip())

    def test_quoted_secret_literal_is_caught_even_before_a_call_shape(self) -> None:
        """m1: a quoted literal is never a function call, so it must not be exempted.

        Values are low-entropy synthetic strings so the detector fixtures stay
        inert for entropy-based scanners; the shape is what is under test.
        """
        quoted_password = 'password = "aaaaaaaaaaaaaaaa"('  # gitleaks:allow -- synthetic detector fixture
        quoted_api_key = 'api_key = "aaaaaaaaaaaaaaaa"('  # gitleaks:allow -- synthetic detector fixture
        self.assertTrue(contains_literal_secret(quoted_password))
        self.assertTrue(contains_literal_secret(quoted_api_key))
        # The intentional exemption for real call sites must survive.
        self.assertFalse(contains_literal_secret("token = _env_value()"))
        self.assertFalse(contains_literal_secret("api_key = get_key("))
        self.assertFalse(contains_literal_secret("password = self._resolve("))

    def test_unquoted_value_followed_by_spaced_prose_is_still_a_secret(self) -> None:
        """m1 follow-up: only a paren that touches the identifier is a call.

        `\\s*` between the identifier and the opening paren let a literal value
        followed by parenthesised prose (`password = <value> (rotated ...)`)
        slip through the unquoted branch, which the pre-fix pattern caught and
        nothing else in SECRET_PATTERNS covers.
        """
        spaced_prose = "password = correcthorsebatterystaple (rotated 2026-01)"  # gitleaks:allow -- synthetic detector fixture
        spaced_vault = "api_key: hunter2hunter2 (see vault)"  # gitleaks:allow -- synthetic detector fixture
        wrapped_line = "secret = hunter2hunter2\n(see vault)"  # gitleaks:allow -- synthetic detector fixture
        self.assertTrue(contains_literal_secret(spaced_prose))
        self.assertTrue(contains_literal_secret(spaced_vault))
        self.assertTrue(contains_literal_secret(wrapped_line))
        self.assertEqual(
            redact_secrets(spaced_prose),
            "[REDACTED-SECRET] (rotated 2026-01)",
        )


if __name__ == "__main__":
    unittest.main()
