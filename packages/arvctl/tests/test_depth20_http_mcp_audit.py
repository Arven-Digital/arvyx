"""Depth20 HTTP/MCP audit regressions. Authored, NOT EXECUTED."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from arvyx_control import api, audit_log, mcp, mutation_dispatch
from arvyx_control.auth import Identity, ALL_SCOPES
from arvyx_control.replica_authority import authority_context


class HttpMcpAuditTests(unittest.TestCase):
    def test_storage_failure_after_dispatch_is_typed_uncertain_and_never_retried(self):
        import sqlite3
        identity = Identity('operator', frozenset(ALL_SCOPES), 'operator')
        for fault in (sqlite3.OperationalError('private-detail'), OSError('private-detail'), RuntimeError('private-detail')):
            with self.subTest(fault=type(fault).__name__), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                vault, state = root / 'vault', root / 'state'
                with authority_context(vault, state), \
                     mock.patch.object(api, 'resolve_identity', return_value=identity), \
                     mock.patch.object(api, '_audit_api_intent', return_value=True), \
                     mock.patch.object(api, '_dispatch_and_record', side_effect=fault) as dispatch:
                    first = api.handle_api_request('POST', '/control/tasks', {'title': 'synthetic'},
                        vault, state, idempotency_key='a' * 16)
                    second = api.handle_api_request('POST', '/control/tasks', {'title': 'synthetic'},
                        vault, state, idempotency_key='a' * 16)
                self.assertEqual(first.status, 503)
                self.assertEqual(first.body['outcome'], 'uncertain')
                self.assertFalse(first.body['retry_safe'])
                self.assertEqual(second.status, 409)
                dispatch.assert_called_once()
                self.assertNotIn('private-detail', first.to_json())

    def test_malformed_heartbeat_never_claims(self):
        identity = Identity("agent-a", frozenset(ALL_SCOPES), "agent")
        for lease in ([], {}, True, 0, -1, 3601, "120", 1.5, None):
            with self.subTest(lease=lease), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with mock.patch.object(api, "resolve_identity", return_value=identity), mock.patch.object(api, "claim_mutation") as claim:
                    response = api.handle_api_request("POST", "/executions/x/heartbeat", {"lease_seconds": lease}, root / "vault", root / "state", idempotency_key="a" * 16)
                self.assertEqual(response.status, 400)
                claim.assert_not_called()

    def test_summary_refuses_agent_before_serialization(self):
        identity = Identity("agent-a", frozenset(ALL_SCOPES), "agent")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(api, "resolve_identity", return_value=identity), mock.patch.object(api, "_operator_summary") as summary:
            response = api._handle_api_request("GET", "/summary", {}, Path(tmp), Path(tmp) / "state")
        self.assertEqual(response.status, 403)
        summary.assert_not_called()

    def test_control_plane_requires_operator_before_projection(self):
        for kind in ('agent', 'operator'):
            identity = Identity('synthetic-' + kind, frozenset(ALL_SCOPES), kind)
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp, \
                 mock.patch.object(api, 'resolve_identity', return_value=identity), \
                 mock.patch.object(api, '_control_plane', return_value={'ok': True}) as projection:
                response = api._handle_api_request('GET', '/control-plane', {}, Path(tmp), Path(tmp) / 'state')
            self.assertEqual(response.status, 200 if kind == 'operator' else 403)
            self.assertEqual(projection.call_count, 1 if kind == 'operator' else 0)

    def test_notification_failure_audit_and_actor_survive_revocation(self):
        identity = Identity("operator", frozenset(ALL_SCOPES), "operator")
        for name, arguments in (("secret.resolve", {"ref": "invalid-reference"}), ("control.task_create", {"title": "synthetic"})):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                payload = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": name, "arguments": arguments}}
                def refuse(**kwargs):
                    resolver.return_value = None  # Credential invalidated while dispatching.
                    raise ValueError("synthetic refusal")
                with mock.patch.object(api, "resolve_identity", return_value=identity) as resolver, mock.patch.object(mcp, "_call_tool", side_effect=refuse) as domain:
                    response = api.handle_api_request("POST", "/mcp", payload, root / "vault", root / "state", mcp_profile="operator", audit_log=root / "audit", idempotency_key="a" * 16)
                self.assertEqual(response.status, 202)
                self.assertEqual(response.body, "")
                self.assertNotIn("dispatch_decision", response.to_json())
                domain.assert_called_once()
                records = [json.loads(line) for line in (root / "audit").read_text().splitlines()]
                self.assertEqual([r["decision"] for r in records], ["pending", "error"])
                self.assertTrue(all(r["identity"] == "operator" for r in records))
                resolver.assert_called_once()

    def test_forget_restore_schema_and_admission_preserve_domain_grammar(self):
        for name in ("memory.forget", "memory.restore"):
            schema = mcp._tools({name})[0]["inputSchema"]["properties"]["idempotency_key"]
            self.assertEqual(schema["pattern"], mutation_dispatch.FORGET_KEY_PATTERN)
            for key in ("!" + "a" * 15, "a" * 15 + "!"):
                payload = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": name, "arguments": {"idempotency_key": key}}}
                with self.assertRaises(ValueError):
                    mutation_dispatch.resolve_mutation_key(payload, route="/mcp", explicit=None)
            payload["params"]["arguments"]["idempotency_key"] = "a" * 16
            self.assertEqual(mutation_dispatch.resolve_mutation_key(payload, route="/mcp", explicit=None), "a" * 16)

    def test_complete_unterminated_audit_is_not_healthy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / "audit"
            self.assertTrue(audit_log.verify_chain(log).ok)
            with authority_context(root / "vault"):
                audit_log.append_audit(log, {"event_id": "synthetic", "decision": "allowed"})
            self.assertTrue(audit_log.verify_chain(log).ok)
            self.assertTrue(audit_log.verify_chain_tail(log).ok)
            log.write_bytes(log.read_bytes()[:-1])
            self.assertFalse(audit_log.verify_chain(log).ok)
            self.assertFalse(audit_log.verify_chain_tail(log).ok)
            self.assertFalse(audit_log.verify_chain_tail(log, max_bytes=64).ok)
