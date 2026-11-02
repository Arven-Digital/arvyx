"""Regression sources only: NOT EXECUTED under the latest15 no-checks order."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from arvyx_control import api, cli, defaults, mcp, mutation_dispatch as dispatch
from arvyx_control.replica_authority import authority_context


def call(name, request_id=1):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": name, "arguments": {}}}


class ToolNameBoundaryTests(unittest.TestCase):
    def test_direct_resolvers_reject_non_text_without_claim(self):
        for name in ([], {}, None, True, 17):
            body = call(name)
            with self.subTest(name=name), mock.patch.object(dispatch, "claim_operation") as claim:
                for invoke in (
                    lambda: dispatch.validate_mcp_envelope(body),
                    lambda: dispatch.resolve_mutation_key(body, route="/mcp", explicit=None),
                    lambda: dispatch.validate_domain_key(body, "/mcp", None),
                    lambda: dispatch.claim_mutation(Path("unused"), vault=Path("vault"),
                        principal_scope="test", action="MCP:invalid", idempotency_key="test-test-test-15",
                        body=body, route="/mcp"),
                ):
                    with self.assertRaises(dispatch.InvalidMCPParams) as raised:
                        invoke()
                    self.assertEqual(raised.exception.response["error"]["code"], -32602)
                claim.assert_not_called()

    def test_actual_cli_continues_after_requests_and_silent_notifications(self):
        for profile in ("read-only", "operator"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                frames = []
                for index, name in enumerate(([], {}), 1):
                    frames.append(call(name, index))
                    notification = call(name)
                    del notification["id"]
                    frames.append(notification)
                frames.extend([
                    {"jsonrpc": "2.0", "id": 3, "method": "ping"},
                    {"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
                ])
                stdout = io.StringIO()
                with mock.patch("sys.stdin", io.StringIO("\n".join(map(json.dumps, frames)) + "\n")), \
                     contextlib.redirect_stdout(stdout), \
                     mock.patch.object(dispatch, "claim_mutation") as claim, \
                     mock.patch.object(mcp, "_call_tool") as effect, \
                     mock.patch.object(mcp, "append_audit_once") as audit:
                    result = cli.main(["mcp", "--vault", str(root / "vault"),
                        "--state", str(root / "events"), "--audit-log", str(root / "audit"),
                        "--profile", profile])
                self.assertEqual(result, 0)
                responses = list(map(json.loads, stdout.getvalue().splitlines()))
                self.assertEqual([entry["id"] for entry in responses], [1, 2, 3, 4])
                self.assertEqual([entry["error"]["code"] for entry in responses[:2]], [-32602, -32602])
                self.assertEqual(responses[2]["result"], {})
                self.assertIn("tools", responses[3]["result"])
                claim.assert_not_called()
                effect.assert_not_called()
                audit.assert_not_called()
                self.assertFalse((root / "events").exists())
                self.assertFalse((root / "audit").exists())

    def test_http_shared_validator_rejects_before_audit_or_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ([], {}):
                with mock.patch.object(api, "resolve_identity", return_value=None), \
                     mock.patch.object(api, "claim_mutation") as claim, \
                     mock.patch.object(api, "_requires_audit_success") as admission:
                    response = api.handle_api_request("POST", "/mcp", call(name),
                        root / "vault", root / "events", allow_unauthenticated_demo=True)
                self.assertEqual(response.status, 400)
                payload = json.loads(response.body) if isinstance(response.body, str) else response.body
                self.assertEqual(payload["error"]["code"], -32602)
                admission.assert_not_called()
                claim.assert_not_called()

    def test_http_invalid_name_notification_has_no_protocol_response(self):
        # HTTP acknowledgment is transport-only; dispatch must remain an error.
        body = call([])
        del body["id"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(api, "resolve_identity", return_value=None), \
                 mock.patch.object(api, "claim_mutation") as claim:
                response = api.handle_api_request("POST", "/mcp", body,
                    root / "vault", root / "events", allow_unauthenticated_demo=True)
            self.assertEqual(response.status, 202)
            self.assertEqual(response.body, "")
            self.assertEqual(response.dispatch_decision, "error")
            self.assertFalse((root / "events").exists())
            self.assertFalse((root / "audit").exists())
            claim.assert_not_called()


class PackagedAuthorityTests(unittest.TestCase):
    def test_actual_api_call_binds_resolved_packaged_vault_before_router(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = Path.cwd()
            try:
                os.chdir(root)
                actual = root / "cache" / "synthetic-vault"
                seen = []

                def router(**kwargs):
                    # Exercise the real nested fence with the router's exact inputs.
                    with authority_context(kwargs["vault"], kwargs["state"]):
                        seen.append(kwargs["vault"])
                    return api.ApiResponse(200, {"ok": True})

                (root / "cache").mkdir(mode=0o700)
                with mock.patch.object(defaults, "_cache_root", return_value=root / "cache"), \
                     mock.patch.object(defaults, "init_vault") as initialize, \
                     mock.patch.object(cli, "handle_api_request", side_effect=router), \
                     contextlib.redirect_stdout(io.StringIO()):
                    result = cli.main(["api-call", "GET", "/health", "--vault",
                        "fixtures/synthetic-vault", "--state", str(root / "events"),
                        "--allow-unauthenticated-demo"])
                self.assertEqual(result, 0)
                self.assertEqual(seen, [actual])
                initialize.assert_called_once_with(actual, force=False)
            finally:
                os.chdir(previous)

    def test_explicit_custom_vault_and_conflicting_alias_fence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault, other, state = root / "vault", root / "other", root / "events"
            with mock.patch.object(cli, "_authority_dispatch", return_value=0) as dispatch_cli:
                self.assertEqual(cli.main(["api-call", "GET", "/health", "--vault", str(vault),
                                           "--state", str(state)]), 0)
                self.assertEqual(dispatch_cli.call_args.args[0].vault, vault)
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                cli.main(["--authority-vault", str(other), "api-call", "GET", "/health",
                          "--vault", str(vault), "--state", str(state)])
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                cli.main(["api-call", "GET", "/health", "--state", str(state)])
