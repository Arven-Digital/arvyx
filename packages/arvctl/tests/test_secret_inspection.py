from __future__ import annotations

import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

from arvyx_control.api import handle_api_request
from arvyx_control.auth import issue_token, revoke_token, tools_for_scopes
from arvyx_control.brokers import (
    InspectionGuard,
    _format_host_header,
    inspect_brokers,
    pointer_status,
)
from arvyx_control.mcp import handle_request as _handle_request, tools_for_profile
from arvyx_control.vault import init_vault


def handle_request(payload, *, vault, **kwargs):
    # Isolate direct MCP state/journals; bound_entry supplies actual authority.
    return _handle_request(payload, vault=vault, state=vault / "control-events.jsonl", **kwargs)


def _write_config(repo: Path, brokers: dict) -> None:
    (repo / ".arvyx").mkdir(parents=True, exist_ok=True)
    (repo / ".arvyx" / "secret-brokers.json").write_text(
        json.dumps({"brokers": brokers}), encoding="utf-8"
    )


def _one_shot_server(payload: bytes, *, drip_seconds: float = 0.0) -> tuple[int, threading.Thread]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                connection.recv(4096)
                for byte in payload:
                    try:
                        connection.sendall(bytes([byte]))
                    except BrokenPipeError:
                        break
                    if drip_seconds:
                        time.sleep(drip_seconds)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, thread


class SecretInspectionScopeTests(unittest.TestCase):
    def test_secret_inspect_scope_exposes_only_safe_tools(self) -> None:
        tools = tools_for_scopes(frozenset({"secret.inspect"}))
        self.assertEqual(tools, {"secret.providers", "secret.pointer_check"})
        self.assertNotIn("secret.resolve", tools)

    def test_agent_profile_allows_safe_inspection_but_not_resolution(self) -> None:
        profile = set(tools_for_profile("agent"))
        self.assertIn("secret.providers", profile)
        self.assertIn("secret.pointer_check", profile)
        self.assertNotIn("secret.resolve", profile)

    def test_issue_token_accepts_secret_inspect_as_independent_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            token = issue_token(vault, "demobot", scopes=["secret.inspect"])
            self.assertEqual(token.scopes, ["secret.inspect"])


class SecretProviderInspectionTests(unittest.TestCase):
    def test_provider_inventory_never_returns_sensitive_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write_config(
                repo,
                {
                    "kiran": {
                        "provider": "http-broker",
                        "health_url": "http://127.0.0.1:18084/health",
                        "token_file": "/private/provider-token",
                        "command": ["unsafe", "--secret", "literal"],
                    }
                },
            )
            with mock.patch("arvyx_control.brokers._probe_loopback_health", return_value=("ok", "0.9.0")):
                result = inspect_brokers(repo)
            encoded = json.dumps(result, sort_keys=True)
            self.assertEqual(result, [{"name": "kiran", "provider": "http-broker", "status": "ok", "version": "0.9.0"}])
            self.assertNotIn("health_url", encoded)
            self.assertNotIn("token_file", encoded)
            self.assertNotIn("command", encoded)
            self.assertNotIn("literal", encoded)

    def test_pointer_check_never_resolves_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write_config(repo, {"kiran": {"provider": "http-broker", "health_url": "http://127.0.0.1:18084/health"}})
            with mock.patch("arvyx_control.brokers.resolve_ref", side_effect=AssertionError("must not resolve")), mock.patch(
                "arvyx_control.brokers._probe_loopback_health"
            ) as probe:
                result = pointer_status("secret://kiran/project/item/field", repo)
            probe.assert_not_called()
            self.assertEqual(
                result,
                {"syntax_valid": True, "provider_known": True, "provider": "http-broker", "status": "configured"},
            )
            self.assertNotIn("secret://", json.dumps(result))
            self.assertNotIn("project/item/field", json.dumps(result))

    def test_health_probe_rejects_non_loopback_and_drops_response_body(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write_config(repo, {"kiran": {"provider": "http-broker", "health_url": "https://example.com/health"}})
            with mock.patch("socket.create_connection") as connect:
                result = inspect_brokers(repo)
            connect.assert_not_called()
            self.assertEqual(result, [{"name": "kiran", "provider": "http-broker", "status": "invalid_config"}])

    def test_malformed_http_response_is_sanitized_and_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            marker = "TOPSECRET-MALFORMED-RESPONSE"
            port, thread = _one_shot_server((marker + "\r\n").encode())
            repo = Path(tmp)
            _write_config(repo, {"kiran": {"provider": "http-broker", "health_url": f"http://127.0.0.1:{port}/health"}})
            result = inspect_brokers(repo)
            thread.join(timeout=1)
            self.assertEqual(result, [{"name": "kiran", "provider": "http-broker", "status": "unavailable"}])
            self.assertNotIn(marker, json.dumps(result))

    def test_secret_shaped_version_is_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            marker = "ghp_" + "a" * 24
            body = json.dumps({"status": "ok", "version": marker}).encode()
            response = (
                b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
            port, thread = _one_shot_server(response)
            repo = Path(tmp)
            _write_config(repo, {"kiran": {"provider": "http-broker", "health_url": f"http://127.0.0.1:{port}/health"}})
            result = inspect_brokers(repo)
            thread.join(timeout=1)
            self.assertEqual(result, [{"name": "kiran", "provider": "http-broker", "status": "ok"}])
            self.assertNotIn(marker, json.dumps(result))

    def test_ipv6_host_header_is_bracketed(self) -> None:
        self.assertEqual(_format_host_header("::1", 18084), "[::1]:18084")
        self.assertEqual(_format_host_header("127.0.0.1", 18084), "127.0.0.1:18084")

    def test_localhost_name_is_rejected_without_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write_config(repo, {"kiran": {"provider": "http-broker", "health_url": "http://localhost:18084/health"}})
            with mock.patch("socket.create_connection") as connect:
                result = inspect_brokers(repo)
            connect.assert_not_called()
            self.assertEqual(result, [{"name": "kiran", "provider": "http-broker", "status": "invalid_config"}])

    def test_probe_has_wall_clock_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            port, _ = _one_shot_server(b"HTTP/1.1 200 OK\r\n", drip_seconds=0.4)
            repo = Path(tmp)
            _write_config(repo, {"kiran": {"provider": "http-broker", "health_url": f"http://127.0.0.1:{port}/health"}})
            started = time.monotonic()
            result = inspect_brokers(repo)
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 3.0)
            self.assertEqual(result, [{"name": "kiran", "provider": "http-broker", "status": "unavailable"}])

    def test_untrusted_broker_labels_are_never_returned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            marker = "ghp_" + "a" * 24
            _write_config(repo, {marker: {"provider": marker}})
            result = inspect_brokers(repo)
            encoded = json.dumps(result)
            self.assertNotIn(marker, encoded)
            self.assertEqual(result, [{"name": "invalid-broker", "provider": "unknown", "status": "invalid_config"}])

    def test_unhealthy_provider_error_is_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            marker = "TOPSECRET-DO-NOT-RETURN"
            _write_config(repo, {"kiran": {"provider": "http-broker", "health_url": "http://127.0.0.1:18084/health"}})
            with mock.patch("arvyx_control.brokers._probe_loopback_health", side_effect=OSError(marker)):
                result = inspect_brokers(repo)
            self.assertEqual(result, [{"name": "kiran", "provider": "http-broker", "status": "unavailable"}])
            self.assertNotIn(marker, json.dumps(result))


class SecretInspectionMcpTests(unittest.TestCase):
    def _call(self, vault: Path, allowed: set[str], name: str, arguments: dict | None = None) -> dict:
        response = handle_request(
            {
                "jsonrpc": "2.0",
                "id": "secret-inspection",
                "method": "tools/call",
                "params": {"name": name, "arguments": {
                    "idempotency_key": f"inspection-{uuid.uuid4().hex}", **(arguments or {})}},
            },
            vault=vault,
            allowed_tools=allowed,
            actor="kiran",
        )
        assert response is not None
        return response

    def test_inspection_tool_schemas_require_fresh_idempotency_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            response = handle_request(
                {"jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": {}},
                vault=vault,
                allowed_tools={"secret.providers", "secret.pointer_check"},
                actor="kiran",
            )
            assert response is not None
            tools = {tool["name"]: tool for tool in response["result"]["tools"]}
            for name in ("secret.providers", "secret.pointer_check"):
                schema = tools[name]["inputSchema"]
                self.assertIn("idempotency_key", schema["required"])
                self.assertEqual(schema["properties"]["idempotency_key"]["minLength"], 16)
                self.assertEqual(schema["properties"]["idempotency_key"]["maxLength"], 256)
                self.assertEqual(schema["properties"]["idempotency_key"]["pattern"], r"^[!-~]+$")

    def test_provider_tool_is_denied_without_scope_filter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            response = self._call(vault, set(), "secret.providers")
            self.assertIn("error", response)
            self.assertEqual(response["error"]["code"], -32000)

    def test_missing_operation_key_is_rejected_before_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            with mock.patch("arvyx_control.brokers.inspect_brokers") as inspect:
                response = handle_request(
                    {"jsonrpc": "2.0", "id": "missing-key", "method": "tools/call",
                     "params": {"name": "secret.providers", "arguments": {}}},
                    vault=vault, allowed_tools={"secret.providers"}, actor="kiran",
                )
            inspect.assert_not_called()
            self.assertEqual(response["error"]["message"], "idempotency_key_required")

    def test_safe_tools_return_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            _write_config(vault, {"kiran": {"provider": "http-broker", "health_url": "http://127.0.0.1:18084/health"}})
            allowed = {"secret.providers", "secret.pointer_check"}
            with mock.patch("arvyx_control.brokers._probe_loopback_health", return_value=("ok", "0.9.0")):
                providers = self._call(vault, allowed, "secret.providers")
                pointer = self._call(
                    vault,
                    allowed,
                    "secret.pointer_check",
                    {"ref": "secret://kiran/project/item/field"},
                )
            encoded = json.dumps({"providers": providers, "pointer": pointer}, sort_keys=True)
            self.assertIn("structuredContent", providers["result"])
            self.assertIn("structuredContent", pointer["result"])
            self.assertNotIn("value", encoded)
            self.assertNotIn("health_url", encoded)
    def test_agent_with_inspect_and_resolve_scopes_still_cannot_resolve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            state = Path(tmp) / "events.jsonl"
            init_vault(vault)
            token = issue_token(vault, "demobot", scopes=["secret.inspect", "secret.resolve"]).token
            list_request = {"jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": {}}
            listed = handle_api_request(
                "POST", "/mcp", list_request, vault=vault, state=state,
                authorization=f"Bearer {token}", mcp_profile="agent",
            )
            listed_body = json.loads(listed.body) if isinstance(listed.body, str) else listed.body
            names = {tool["name"] for tool in listed_body["result"]["tools"]}
            self.assertEqual(names, {"secret.providers", "secret.pointer_check"})

            resolve_request = {
                "jsonrpc": "2.0", "id": "resolve", "method": "tools/call",
                "params": {"name": "secret.resolve", "arguments": {"ref": "secret://kiran/project/item/field", "idempotency_key": "scope-separation-0001"}},
            }
            denied = handle_api_request(
                "POST", "/mcp", resolve_request, vault=vault, state=state,
                authorization=f"Bearer {token}", mcp_profile="agent",
            )
            denied_body = json.loads(denied.body) if isinstance(denied.body, str) else denied.body
            self.assertEqual(denied_body["error"]["code"], -32000)
            self.assertIn("not allowlisted", denied_body["error"]["message"])

    def test_http_scope_intersection_hides_inspection_from_unscoped_agents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            state = Path(tmp) / "events.jsonl"
            init_vault(vault)
            inspect_token = issue_token(vault, "demobot", scopes=["secret.inspect"]).token
            read_token = issue_token(vault, "vesper", scopes=["memory.read"]).token
            request = {"jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": {}}

            inspected = handle_api_request(
                "POST", "/mcp", request, vault=vault, state=state,
                authorization=f"Bearer {inspect_token}", mcp_profile="agent",
            )
            unscoped = handle_api_request(
                "POST", "/mcp", request, vault=vault, state=state,
                authorization=f"Bearer {read_token}", mcp_profile="agent",
            )
            inspected_body = json.loads(inspected.body) if isinstance(inspected.body, str) else inspected.body
            unscoped_body = json.loads(unscoped.body) if isinstance(unscoped.body, str) else unscoped.body
            inspected_names = {tool["name"] for tool in inspected_body["result"]["tools"]}
            unscoped_names = {tool["name"] for tool in unscoped_body["result"]["tools"]}
            self.assertEqual(inspected_names, {"secret.providers", "secret.pointer_check"})
            self.assertFalse({"secret.providers", "secret.pointer_check", "secret.resolve"} & unscoped_names)
            self.assertNotIn("secret.resolve", inspected_names)


class SecretInspectionRuntimeGuardTests(unittest.TestCase):
    def _guard(self, **overrides: object) -> InspectionGuard:
        values = {
            "global_capacity": 2,
            "global_refill_per_second": 0.0,
            "principal_capacity": 1,
            "principal_refill_per_second": 0.0,
            "max_concurrent": 1,
            "circuit_failure_threshold": 2,
            "circuit_cooldown_seconds": 30.0,
        }
        values.update(overrides)
        return InspectionGuard(**values)

    def test_per_principal_rate_limit_is_fixed_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            _write_config(vault, {"kiran": {"provider": "env"}})
            guard = self._guard()
            payload = {
                "jsonrpc": "2.0",
                "id": "pointer",
                "method": "tools/call",
                "params": {
                    "name": "secret.pointer_check",
                    "arguments": {"ref": "secret://kiran/project/item/field",
                                  "idempotency_key": "principal-rate-first-0001"},
                },
            }
            first = handle_request(
                payload,
                vault=vault,
                allowed_tools={"secret.pointer_check"},
                actor="kiran",
                inspection_guard=guard,
            )
            # A new operation must reach the limiter, not replay the first key.
            payload["params"]["arguments"]["idempotency_key"] = "principal-rate-second-0002"
            second = handle_request(
                payload,
                vault=vault,
                allowed_tools={"secret.pointer_check"},
                actor="kiran",
                inspection_guard=guard,
            )
            assert first is not None and second is not None
            self.assertIn("result", first)
            self.assertEqual(second["error"]["message"], "secret inspection unavailable")

    def test_principal_denial_does_not_drain_global_capacity(self) -> None:
        guard = self._guard(global_capacity=2, principal_capacity=1)
        with guard.admit("kiran"):
            pass
        with self.assertRaisesRegex(ValueError, "secret inspection unavailable"):
            with guard.admit("kiran"):
                pass
        with guard.admit("demobot"):
            pass

    def test_global_denial_does_not_drain_principal_capacity(self) -> None:
        now = [100.0]
        guard = self._guard(
            global_capacity=1,
            global_refill_per_second=1.0,
            principal_capacity=2,
            principal_refill_per_second=0.0,
            clock=lambda: now[0],
        )
        with guard.admit("kiran"):
            pass
        with self.assertRaisesRegex(ValueError, "secret inspection unavailable"):
            with guard.admit("demobot"):
                pass
        now[0] += 1.0
        with guard.admit("demobot"):
            pass
        now[0] += 1.0
        with guard.admit("demobot"):
            pass

    def test_global_rate_limit_applies_across_principals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            _write_config(vault, {"kiran": {"provider": "env"}})
            guard = self._guard(global_capacity=1, principal_capacity=2)
            payload = {
                "jsonrpc": "2.0",
                "id": "pointer",
                "method": "tools/call",
                "params": {
                    "name": "secret.pointer_check",
                    "arguments": {"ref": "secret://kiran/project/item/field",
                                  "idempotency_key": "global-rate-first-0001"},
                },
            }
            first = handle_request(
                payload,
                vault=vault,
                allowed_tools={"secret.pointer_check"},
                actor="kiran",
                inspection_guard=guard,
            )
            payload["params"]["arguments"]["idempotency_key"] = "global-rate-second-0002"
            second = handle_request(
                payload,
                vault=vault,
                allowed_tools={"secret.pointer_check"},
                actor="demobot",
                inspection_guard=guard,
            )
            assert first is not None and second is not None
            self.assertIn("result", first)
            self.assertEqual(second["error"]["message"], "secret inspection unavailable")

    def test_dedicated_concurrency_slot_rejects_without_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            _write_config(
                vault,
                {"kiran": {"provider": "http-broker", "health_url": "http://127.0.0.1:18084/health"}},
            )
            guard = self._guard(principal_capacity=3)
            with guard.admit("other"):
                with mock.patch("arvyx_control.brokers._probe_loopback_health") as probe:
                    response = handle_request(
                        {
                            "jsonrpc": "2.0",
                            "id": "providers",
                            "method": "tools/call",
                            "params": {"name": "secret.providers", "arguments": {
                                "idempotency_key": "test-test-test-01"}},
                        },
                        vault=vault,
                        allowed_tools={"secret.providers"},
                        actor="kiran",
                        inspection_guard=guard,
                    )
                probe.assert_not_called()
            assert response is not None
            self.assertEqual(response["error"]["message"], "secret inspection unavailable")

    def test_concurrency_denial_does_not_drain_rate_capacity(self) -> None:
        guard = self._guard(global_capacity=3, principal_capacity=2)
        with guard.admit("holder"):
            with self.assertRaisesRegex(ValueError, "secret inspection unavailable"):
                with guard.admit("kiran"):
                    pass
        with guard.admit("kiran"):
            pass
        with guard.admit("kiran"):
            pass

    def test_circuit_breaker_suppresses_probe_after_bounded_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write_config(
                repo,
                {"kiran": {"provider": "http-broker", "health_url": "http://127.0.0.1:18084/health"}},
            )
            guard = self._guard(principal_capacity=10, global_capacity=10)
            with mock.patch(
                "arvyx_control.brokers._probe_loopback_health",
                side_effect=OSError("synthetic"),
            ) as probe:
                inspect_brokers(repo, guard=guard)
                inspect_brokers(repo, guard=guard)
                third = inspect_brokers(repo, guard=guard)
            self.assertEqual(probe.call_count, 2)
            self.assertEqual(
                third,
                [{"name": "kiran", "provider": "http-broker", "status": "unavailable"}],
            )

    def test_circuit_breaker_recovers_after_cooldown(self) -> None:
        now = [100.0]
        guard = self._guard(
            principal_capacity=10,
            global_capacity=10,
            circuit_failure_threshold=2,
            circuit_cooldown_seconds=30.0,
            clock=lambda: now[0],
        )
        guard.record_provider_result("kiran:http-broker", healthy=False)
        guard.record_provider_result("kiran:http-broker", healthy=False)
        self.assertFalse(guard.circuit_allows("kiran:http-broker"))
        now[0] += 31.0
        self.assertTrue(guard.circuit_allows("kiran:http-broker"))

    def test_duplicate_concurrent_request_dispatches_one_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            state = Path(tmp) / "events.jsonl"
            init_vault(vault)
            _write_config(
                vault,
                {"kiran": {"provider": "http-broker", "health_url": "http://127.0.0.1:18084/health"}},
            )
            token = issue_token(vault, "demobot", scopes=["secret.inspect"]).token
            request = {
                "jsonrpc": "2.0",
                "id": "providers",
                "method": "tools/call",
                "params": {
                    "name": "secret.providers",
                    "arguments": {"idempotency_key": "concurrent-probe-0001"},
                },
            }
            guard = self._guard(principal_capacity=5, global_capacity=5, max_concurrent=2)
            entered = threading.Event()
            release = threading.Event()
            responses: list[object] = []

            def slow_probe(_url: str) -> tuple[str, str]:
                entered.set()
                self.assertTrue(release.wait(timeout=5))
                return "ok", "0.9.0"

            def call() -> None:
                responses.append(
                    handle_api_request(
                        "POST",
                        "/mcp",
                        request,
                        vault=vault,
                        state=state,
                        authorization=f"Bearer {token}",
                        mcp_profile="agent",
                        inspection_guard=guard,
                    )
                )

            with mock.patch("arvyx_control.brokers._probe_loopback_health", side_effect=slow_probe) as probe:
                first = threading.Thread(target=call)
                first.start()
                self.assertTrue(entered.wait(timeout=5))
                second = threading.Thread(target=call)
                second.start()
                second.join(timeout=5)
                release.set()
                first.join(timeout=5)
            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertEqual(probe.call_count, 1)
            statuses = sorted(response.status for response in responses)  # type: ignore[attr-defined]
            self.assertEqual(statuses, [200, 409])

    def test_operation_journal_failure_prevents_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            state = Path(tmp) / "events.jsonl"
            init_vault(vault)
            _write_config(
                vault,
                {"kiran": {"provider": "http-broker", "health_url": "http://127.0.0.1:18084/health"}},
            )
            token = issue_token(vault, "demobot", scopes=["secret.inspect"]).token
            request = {
                "jsonrpc": "2.0",
                "id": "providers",
                "method": "tools/call",
                "params": {
                    "name": "secret.providers",
                    "arguments": {"idempotency_key": "idem-00000000001"},
                },
            }
            with mock.patch("arvyx_control.api.claim_mutation", side_effect=OSError("synthetic")), mock.patch(
                "arvyx_control.brokers._probe_loopback_health"
            ) as probe:
                response = handle_api_request(
                    "POST",
                    "/mcp",
                    request,
                    vault=vault,
                    state=state,
                    authorization=f"Bearer {token}",
                    mcp_profile="agent",
                    inspection_guard=self._guard(),
                )
            probe.assert_not_called()
            self.assertEqual(response.status, 503)

    def test_invalid_and_unscoped_credentials_never_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            state = Path(tmp) / "events.jsonl"
            init_vault(vault)
            _write_config(
                vault,
                {"kiran": {"provider": "http-broker", "health_url": "http://127.0.0.1:18084/health"}},
            )
            revoked = issue_token(
                vault,
                "demobot",
                scopes=["secret.inspect"],
                slot="provider-revoked",
            )
            revoke_token(vault, "demobot", slot="provider-revoked")
            expired = issue_token(
                vault,
                "demobot",
                scopes=["secret.inspect"],
                slot="provider-expired",
            )
            expired_path = vault / expired.path
            expired_record = json.loads(expired_path.read_text(encoding="utf-8"))
            expired_record["expires_at"] = "2000-01-01T00:00:00Z"
            expired_path.write_text(json.dumps(expired_record), encoding="utf-8")
            wrong_scope = issue_token(
                vault,
                "demobot",
                scopes=["memory.read"],
                slot="presence",
            )
            authorizations = [
                None,
                "Bearer invalid",
                f"Bearer {revoked.token}",
                f"Bearer {expired.token}",
                f"Bearer {wrong_scope.token}",
            ]
            statuses: list[int] = []
            with mock.patch("arvyx_control.brokers._probe_loopback_health") as probe:
                for index, authorization in enumerate(authorizations):
                    request = {
                        "jsonrpc": "2.0",
                        "id": f"providers-{index}",
                        "method": "tools/call",
                        "params": {
                            "name": "secret.providers",
                            "arguments": {"idempotency_key": f"credential-denial-{index:04d}"},
                        },
                    }
                    response = handle_api_request(
                        "POST",
                        "/mcp",
                        request,
                        vault=vault,
                        state=state,
                        authorization=authorization,
                        bearer_secret="synthetic-operator-secret",
                        mcp_profile="agent",
                        inspection_guard=self._guard(
                            principal_capacity=10,
                            global_capacity=10,
                        ),
                    )
                    statuses.append(response.status)
            probe.assert_not_called()
            self.assertEqual(statuses[:4], [401, 401, 401, 401])
            self.assertEqual(statuses[4], 200)

    def test_audit_intent_failure_prevents_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            state = Path(tmp) / "events.jsonl"
            init_vault(vault)
            _write_config(
                vault,
                {"kiran": {"provider": "http-broker", "health_url": "http://127.0.0.1:18084/health"}},
            )
            token = issue_token(vault, "demobot", scopes=["secret.inspect"]).token
            request = {
                "jsonrpc": "2.0",
                "id": "providers",
                "method": "tools/call",
                "params": {
                    "name": "secret.providers",
                    "arguments": {"idempotency_key": "audit-before-probe-0001"},
                },
            }
            with mock.patch("arvyx_control.api._audit_api_intent", return_value=False), mock.patch(
                "arvyx_control.brokers._probe_loopback_health"
            ) as probe:
                response = handle_api_request(
                    "POST",
                    "/mcp",
                    request,
                    vault=vault,
                    state=state,
                    authorization=f"Bearer {token}",
                    mcp_profile="agent",
                    inspection_guard=self._guard(),
                )
            probe.assert_not_called()
            self.assertEqual(response.status, 503)


if __name__ == "__main__":
    unittest.main()
