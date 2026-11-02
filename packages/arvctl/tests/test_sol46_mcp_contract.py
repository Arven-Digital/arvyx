"""Scoped regression sources. NOT_EXECUTED by instruction."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from arvyx_control import api, mcp, mutation_dispatch as dispatch
from arvyx_control import operation_journal as journal
from arvyx_control.replica_authority import authority_context


def envelope(correlation=1, argument_id="semantic-target"):
    return {"jsonrpc": "2.0", "id": correlation, "method": "tools/call",
            "params": {"name": "memory.suggest", "arguments": {
                "id": argument_id, "idempotency_key": "test-test-test-46"}}}


class MCPContractTests(unittest.TestCase):
    def test_only_correlation_id_is_excluded(self):
        original = envelope()
        snapshot = copy.deepcopy(original)
        self.assertEqual(dispatch.canonical_mutation_body(original, "/mcp"),
                         dispatch.canonical_mutation_body(envelope(2), "/mcp"))
        self.assertNotEqual(dispatch.canonical_mutation_body(original, "/mcp"),
                            dispatch.canonical_mutation_body(envelope(2, "other"), "/mcp"))
        self.assertNotEqual(dispatch.canonical_mutation_body(original, "/other"),
                            dispatch.canonical_mutation_body(envelope(2), "/other"))
        self.assertEqual(original, snapshot)

    def test_pending_claim_new_id_and_safe_legacy_upgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = root / "vault"
            vault.mkdir()
            store = root / "journal.sqlite3"
            common = dict(vault=vault, principal_scope="agent:alice", action="MCP:memory.suggest",
                          idempotency_key="test-test-test-46")
            with authority_context(vault, root / "events"):
                old = envelope()
                legacy = dispatch.canonical_mutation_body(old, "/mcp")
                legacy["id"] = old["id"]
                first = journal.claim_operation(store, **common, request_hash=journal.request_digest(legacy))
                journal.set_operation_state(store, first.operation_id, "outcome_pending",
                                            safe_outcome={"operation_id": first.operation_id})
                changed_old = dispatch.claim_mutation(store, **common, body=envelope(2), route="/mcp")
                self.assertTrue(changed_old.conflict)
                upgraded = dispatch.claim_mutation(store, **common, body=old, route="/mcp")
                self.assertFalse(upgraded.conflict)
                retried = dispatch.claim_mutation(store, **common, body=envelope(2), route="/mcp")
                self.assertFalse(retried.conflict)
                self.assertEqual(retried.operation_id, first.operation_id)
                self.assertEqual(retried.state, "outcome_pending")
                self.assertTrue(dispatch.claim_mutation(store, **common, body=envelope(3, "other"), route="/mcp").conflict)

    def test_stdio_pending_completion_uses_current_response_id_without_dispatch(self):
        pending = journal.OperationClaim("operation", "outcome_pending", False,
                                         safe_outcome={"operation_id": "operation"})
        with mock.patch.object(dispatch, "claim_mutation", return_value=pending), \
             mock.patch("arvyx_control.replica_authority.assert_mutation_authority"), \
             mock.patch.object(mcp, "append_audit_once") as append, \
             mock.patch.object(mcp, "set_operation_state") as complete, \
             mock.patch.object(mcp, "_call_tool") as call:
            response = mcp.handle_request(envelope(47), Path("vault"), state=Path("events"),
                                          allowed_tools={"memory.suggest"}, principal_scope="agent:alice")
        self.assertEqual(response["id"], 47)
        self.assertEqual(response["error"]["message"], "operation_completed_no_replay")
        append.assert_called_once()
        complete.assert_called_once()
        call.assert_not_called()

    def test_http_completion_response_uses_current_correlation_id(self):
        response = api._completed_mutation_response("/mcp", envelope(47),
                                                   "operation_completed_no_replay", "operation")
        body = json.loads(response.body)
        self.assertEqual(body["id"], 47)
        self.assertEqual(body["error"]["message"], "operation_completed_no_replay")
        self.assertEqual(body["error"]["data"]["operation_id"], "operation")

    def test_all_advertised_key_schemas_share_admission_constraints(self):
        for tool in mcp._tools(set(mcp.TOOL_NAMES)):
            key = tool["inputSchema"].get("properties", {}).get("idempotency_key")
            if key is None:
                continue
            expected = journal.idempotency_key_schema(key["maxLength"])
            if tool["name"] in {"memory.forget", "memory.restore"}:
                expected["pattern"] = dispatch.FORGET_KEY_PATTERN
            self.assertEqual(key, {**key, **expected})
            self.assertIn(key["maxLength"], (128, 256))
            for value in ("retry", "a" * 15, "a" * 16, "a" * key["maxLength"], "a" * 257, "é" * 16, "a b" * 16):
                admitted = journal.KEY_RE.fullmatch(value) is not None and len(value) <= key["maxLength"]
                import re
                advertised = key["minLength"] <= len(value) <= key["maxLength"] and re.fullmatch(key["pattern"], value) is not None
                self.assertEqual(admitted, advertised)

    def test_maintained_contract_keys_match_catalog(self):
        root = Path(__file__).resolve().parents[3]
        maintained = json.loads((root / "docs/contracts/external-contracts.json").read_text())
        current = {tool["name"]: tool for tool in mcp._tools(set(mcp.TOOL_NAMES))}
        for tool in maintained["mcp"]["tools"]:
            key = tool["inputSchema"].get("properties", {}).get("idempotency_key")
            if key is not None:
                self.assertEqual(key, current[tool["name"]]["inputSchema"]["properties"]["idempotency_key"])
