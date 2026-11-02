"""Request metadata regression sources; NOT_EXECUTED by instruction."""
import json
from pathlib import Path
import unittest
from unittest import mock

from arvyx_control import api
from arvyx_control.request_metadata import request_metadata


class RequestMetadataTests(unittest.TestCase):
    def test_unknown_metadata_is_digest_only_in_intent_and_all_outcomes(self):
        literal = "synthetic-private-metadata"
        body = {"method": literal, "params": {"name": literal}}
        for status in (200, 400, 401, 403, 404, 500):
            with self.subTest(status=status), mock.patch.object(api, "resolve_identity", return_value=None), \
                 mock.patch.object(api, "append_audit_once") as append:
                api._audit_api_intent(Path("unused"), Path("unused"), literal, "/mcp", body,
                                      None, None, "operation")
                intent = append.call_args.args[1]
                outcome = api._build_api_audit_event(Path("unused"), literal, "/mcp", body,
                            api.ApiResponse(status, {"error": literal}), None, None, "operation")
            for event in (intent, outcome):
                self.assertNotIn(literal, json.dumps(event))
                for field in ("method", "mcp_method", "tool"):
                    self.assertTrue(event[field].startswith("unknown:sha256:"))

    def test_known_names_and_route_templates(self):
        metadata = request_metadata("POST", "/mcp", {"method": "tools/call", "params": {"name": "memory.suggest"}})
        self.assertEqual(metadata, {"method": "POST", "route": "/mcp", "mcp_method": "tools/call", "tool": "memory.suggest"})
        self.assertEqual(request_metadata("POST", "/threads/synthetic-secret/ack")["route"], "/threads/{id}/ack")
        self.assertTrue(request_metadata("GET", "/unknown/synthetic-secret")["route"].startswith("unknown:sha256:"))
        self.assertTrue(request_metadata("GET", "/decisions/not-valid/answer")["route"].startswith("unknown:sha256:"))

    def test_action_identity_does_not_collapse_targets_or_unknown_names(self):
        actions = [api._canonical_action("POST", route, {}) for route in
                   ("/threads/one/ack", "/threads/two/ack", "/unknown/one", "/unknown/two")]
        self.assertEqual(len(set(actions)), len(actions))
        for route, action in zip(("/threads/one/ack", "/threads/two/ack", "/unknown/one", "/unknown/two"), actions):
            self.assertNotIn(route, action)
        self.assertNotEqual(api._canonical_action("POST", "/mcp", {"params": {"name": "one"}}),
                            api._canonical_action("POST", "/mcp", {"params": {"name": "two"}}))
        self.assertEqual(api._canonical_action("POST", "/mcp", {"params": {"name": "memory.suggest"}}), "MCP:memory.suggest")

    def test_inputs_not_mutated_and_malformed_mcp_values_are_safe(self):
        for value in (None, [], {}, 7, "synthetic-secret"):
            body = {"method": value, "params": {"name": value}}
            before = json.dumps(body)
            metadata = request_metadata("POST", "/mcp", body)
            self.assertEqual(json.dumps(body), before)
            self.assertNotIn("synthetic-secret", json.dumps(metadata))

    def test_preauth_persists_only_canonical_metadata(self):
        handler_type = api.make_handler(Path("unused"), Path("unused"))
        handler = handler_type.__new__(handler_type)
        with mock.patch.object(api, "_claim_denial_audit_slot", return_value=True), \
             mock.patch.object(api, "append_audit") as append:
            handler._audit_preauth_denial("synthetic-private-method", "/synthetic-private-path", 401)
        event = append.call_args.args[1]
        self.assertEqual(event["phase"], "preauth")
        self.assertEqual(event["method"], request_metadata("synthetic-private-method", "/synthetic-private-path")["method"])
        self.assertNotIn("synthetic-private", json.dumps(event))

    def test_preauth_uses_same_boundary_without_constructing_server(self):
        # Source assertion complements intent/outcome calls without network runtime.
        import inspect
        source = inspect.getsource(api.make_handler)
        denial = source.split("def _audit_preauth_denial", 1)[1].split("def log_message", 1)[0]
        self.assertIn("request_metadata(method, route)", denial)
        self.assertNotIn('"route": route', denial)
