from __future__ import annotations
from arvyx_control.replica_authority import authority_context

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import json
import os
import threading
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from arvyx_control.agent_delivery import AgentRoute, deliver_outbox_item, validate_agent_route
from arvyx_control.outbox import OutboxItem


NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        # Preserve HTTPMessage's case-insensitive lookup across transports.
        self.server.captured.append((self.path, self.headers, body))
        status = self.server.response_status
        payload = self.server.response_payload
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if self.server.redirect_location:
            self.send_header("Location", self.server.redirect_location)
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def log_message(self, *_args):
        return


class AgentDeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        authority_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(authority_tmp.cleanup)
        self.vault = Path(authority_tmp.name) / "vault"
        self.vault.mkdir()
        self.enterContext(authority_context(self.vault))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.captured = []
        self.server.response_status = 202
        self.server.response_payload = {"status": "accepted", "delivery_id": "outbox_1"}
        self.server.redirect_location = ""
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _item(self) -> OutboxItem:
        return OutboxItem(
            id="outbox_1",
            subject_id="handoff_1",
            target="amir",
            payload={
                "schema": "v2.agent-delivery/1",
                "source_event_id": "event_1",
                "source_event_type": "handoff.created",
                "subject_id": "handoff_1",
            },
            payload_hash="hash",
            epoch=0,
            status="leased",
            attempts=1,
            created_at="2026-08-10T12:00:00Z",
            updated_at="2026-08-10T12:00:00Z",
            next_attempt_at="2026-08-10T12:00:00Z",
            lease_owner="worker-a",
            lease_expires_at="2026-08-10T12:01:00Z",
        )

    def test_decision_card_rides_the_return_route_with_a_send_time_nonce_and_needs_a_receipt(self) -> None:
        from arvyx_control.decisions import decision_nonce

        route = AgentRoute(
            agent_id="amir", runtime="openclaw-hook", url_env="WAKE_URL", credential_env="WAKE_SECRET",
            return_runtime="hermes-webhook", return_url_env="RETURN_URL", return_credential_env="RETURN_SECRET",
        )
        decision_id = "decision_" + "a" * 24
        item = OutboxItem(**{**self._item().to_dict(), "subject_id": decision_id, "payload": {
            "delivery_mode": "decision_card", "source_event_type": "decision.requested",
            "decision_id": decision_id, "execution_id": "execution_1", "subject_id": "thread_1",
            "subject_type": "thread", "question": "Prod'a çıkayım mı?", "allow_text": True,
        }})
        env = {
            "WAKE_URL": f"{self.base}/webhooks/wake", "WAKE_SECRET": "wake-secret",
            "RETURN_URL": f"{self.base}/webhooks/session-return", "RETURN_SECRET": "return-secret",
            "ARVYX_V2_CONTROL_SECRET": "control-secret-for-nonce",
        }
        self.server.response_payload = {"status": "delivered", "message_id": "9001"}
        with patch.dict(os.environ, env, clear=False):
            result = deliver_outbox_item(item, route, now=NOW)
        self.assertTrue(result.accepted)
        self.assertEqual(result.provider_receipt, "9001")
        path, headers, body = self.server.captured[0]
        self.assertEqual(path, "/webhooks/session-return")
        payload = json.loads(body)
        self.assertEqual(payload["schema"], "v2.decision-card/1")
        self.assertEqual(payload["decision_id"], decision_id)
        self.assertEqual(payload["nonce"], decision_nonce(decision_id, environ=env))
        self.assertIn("Prod'a çıkayım mı?", payload["message"])
        self.assertTrue(payload["allow_text"])
        self.assertNotIn("nonce", item.payload)  # the persisted outbox payload never holds it
        expected = hmac.new(b"return-secret", headers["X-Webhook-Timestamp"].encode() + b"." + body,
                            hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-Webhook-Signature-V2"], expected)

        # Without the provider message id the send is ambiguous, never "delivered".
        self.server.response_payload = {"status": "delivered"}
        with patch.dict(os.environ, env, clear=False):
            missing = deliver_outbox_item(item, route, now=NOW)
        self.assertFalse(missing.accepted)
        self.assertEqual(missing.classification, "ambiguous")

    def test_session_return_uses_separate_fixed_destination_route(self) -> None:
        route = AgentRoute(
            agent_id="amir",
            runtime="openclaw-hook",
            url_env="WAKE_URL",
            credential_env="WAKE_SECRET",
            return_runtime="hermes-webhook",
            return_url_env="RETURN_URL",
            return_credential_env="RETURN_SECRET",
        )
        item = self._item()
        item = OutboxItem(
            **{
                **item.to_dict(),
                "subject_id": "session_return_1",
                "payload": {
                    "schema": "v2.agent-delivery/1",
                    "source_event_id": "event_return_1",
                    "source_event_type": "execution.session_return.requested",
                    "subject_id": "session_return_1",
                    "delivery_mode": "session_return",
                    "execution_id": "execution_1",
                    "attempt_id": "attempt_1",
                    "message": "Bir varmış bir yokmuş.",
                    "message_sha256": hashlib.sha256("Bir varmış bir yokmuş.".encode()).hexdigest(),
                    "word_count": 4,
                },
            }
        )
        env = {
            "WAKE_URL": f"{self.base}/webhooks/wake",
            "WAKE_SECRET": "wake-secret",
            "RETURN_URL": f"{self.base}/webhooks/session-return",
            "RETURN_SECRET": "return-secret",
        }
        self.server.response_payload = {"status": "sent", "message_id": "telegram-message-42"}
        with patch.dict(os.environ, env, clear=False):
            result = deliver_outbox_item(item, route, now=NOW)

        self.assertTrue(result.accepted)
        self.assertEqual(result.provider_receipt, "telegram-message-42")
        path, headers, body = self.server.captured[0]
        self.assertEqual(path, "/webhooks/session-return")
        payload = json.loads(body)
        self.assertEqual(payload["message"], "Bir varmış bir yokmuş.")
        self.assertEqual(payload["delivery_id"], "outbox_1")
        self.assertEqual(payload["execution_id"], "execution_1")
        self.assertEqual(
            set(payload),
            {"schema", "delivery_id", "execution_id", "attempt_id", "message", "message_sha256", "word_count"},
        )
        self.assertNotIn("destination", payload)
        self.assertNotIn("target", payload)
        expected = hmac.new(
            b"return-secret",
            headers["X-Webhook-Timestamp"].encode() + b"." + body,
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(headers["X-Webhook-Signature-V2"], expected)

        self.server.response_payload = {"status": "accepted", "delivery_id": "outbox_1"}
        with patch.dict(os.environ, env, clear=False):
            missing_receipt = deliver_outbox_item(item, route, now=NOW)
        self.assertFalse(missing_receipt.accepted)
        self.assertEqual(missing_receipt.classification, "ambiguous")
        self.assertIn("provider receipt", missing_receipt.detail)

        self.server.response_status = 504
        with patch.dict(os.environ, env, clear=False):
            gateway_timeout = deliver_outbox_item(item, route, now=NOW)
        self.assertFalse(gateway_timeout.accepted)
        self.assertEqual(gateway_timeout.classification, "ambiguous")
        self.server.response_status = 202

        captured_before = len(self.server.captured)
        malformed = OutboxItem(
            **{
                **item.to_dict(),
                "payload": {**item.payload, "word_count": "four"},
            }
        )
        with patch.dict(os.environ, env, clear=False):
            malformed_result = deliver_outbox_item(malformed, route, now=NOW)
        self.assertFalse(malformed_result.accepted)
        self.assertEqual(malformed_result.classification, "permanent")
        self.assertIn("word_count", malformed_result.detail)
        self.assertEqual(len(self.server.captured), captured_before)

        same_route_env = {**env, "RETURN_URL": env["WAKE_URL"]}
        with patch.dict(os.environ, same_route_env, clear=False):
            same_route_result = deliver_outbox_item(item, route, now=NOW)
        self.assertFalse(same_route_result.accepted)
        self.assertEqual(same_route_result.classification, "configuration")
        self.assertIn("must not reuse", same_route_result.detail)

    def test_session_return_without_dedicated_route_fails_closed(self) -> None:
        route = AgentRoute("amir", "hermes-webhook", "WAKE_URL", "WAKE_SECRET")
        item = self._item()
        item = OutboxItem(
            **{
                **item.to_dict(),
                "payload": {**item.payload, "delivery_mode": "session_return", "message": "merhaba"},
            }
        )
        with patch.dict(
            os.environ,
            {"WAKE_URL": f"{self.base}/wake", "WAKE_SECRET": "wake-secret"},
            clear=False,
        ):
            result = deliver_outbox_item(item, route, now=NOW)
        self.assertFalse(result.accepted)
        self.assertEqual(result.classification, "configuration")
        self.assertIn("session return", result.detail)
        self.assertEqual(self.server.captured, [])

    def test_hermes_uses_timestamp_bound_hmac_and_stable_delivery_id(self) -> None:
        route = AgentRoute(
            agent_id="amir",
            runtime="hermes-webhook",
            url_env="ARVYX_TEST_AGENT_URL",
            credential_env="ARVYX_TEST_AGENT_SECRET",
        )
        env = {
            "ARVYX_TEST_AGENT_URL": f"{self.base}/webhooks/v2-agent-push",
            "ARVYX_TEST_AGENT_SECRET": "route-hmac-secret",
        }
        with patch.dict(os.environ, env, clear=False):
            result = deliver_outbox_item(self._item(), route, now=NOW)

        self.assertTrue(result.accepted)
        self.assertEqual(result.classification, "accepted")
        path, headers, body = self.server.captured[0]
        headers = {key.lower(): value for key, value in headers.items()}
        self.assertEqual(path, "/webhooks/v2-agent-push")
        self.assertEqual(headers["x-request-id"], "outbox_1")
        self.assertEqual(headers["x-github-delivery"], "outbox_1")
        self.assertEqual(headers["x-webhook-timestamp"], "1786363200")
        expected = hmac.new(
            b"route-hmac-secret",
            b"1786363200." + body,
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(headers["x-webhook-signature-v2"], expected)
        payload = json.loads(body)
        self.assertEqual(payload["delivery_id"], "outbox_1")
        self.assertEqual(payload["target_agent"], "amir")
        self.assertTrue(payload["response_contract"].startswith("direct:"))
        self.assertNotIn("execution_mode", payload)
        self.assertNotIn("goal_id", payload)
        self.assertNotIn("runtime_prompt", payload)
        self.assertNotIn("route-hmac-secret", body.decode())

    def test_openclaw_uses_dedicated_bearer_and_idempotency_key(self) -> None:
        route = AgentRoute(
            agent_id="odin",
            runtime="openclaw-hook",
            url_env="ARVYX_TEST_ODIN_URL",
            credential_env="ARVYX_TEST_ODIN_TOKEN",
        )
        item = self._item()
        item = OutboxItem(
            **{
                **item.to_dict(),
                "target": "odin",
                "payload": {**item.payload, "delivery_mode": "broadcast"},
            }
        )
        hook_credential = "dedicated-" + "hook-material"
        env = {
            "ARVYX_TEST_ODIN_URL": f"{self.base}/hooks/agent",
            "ARVYX_TEST_ODIN_TOKEN": hook_credential,
        }
        with patch.dict(os.environ, env, clear=False):
            result = deliver_outbox_item(item, route, now=NOW)

        self.assertTrue(result.accepted)
        _, headers, body = self.server.captured[0]
        self.assertEqual(headers["Authorization"], f"Bearer {hook_credential}")
        payload = json.loads(body)
        self.assertEqual(payload["idempotencyKey"], "outbox_1")
        self.assertEqual(payload["agentId"], "odin")
        self.assertIn("handoff_1", payload["message"])
        self.assertIn("control.thread_reply", payload["message"])
        self.assertIn("do not ACK or DONE", payload["message"])
        self.assertNotIn(hook_credential, result.detail)

    def test_execution_wake_names_session_and_heartbeat_contract(self) -> None:
        route = AgentRoute("amir", "openclaw-hook", "URL", "TOKEN")
        item = self._item()
        item = OutboxItem(
            **{
                **item.to_dict(),
                "payload": {
                    **item.payload,
                    "delivery_mode": "execution",
                    "execution_id": "execution_1",
                    "attempt_id": "attempt_1",
                },
            }
        )
        with patch.dict(
            os.environ,
            {"URL": f"{self.base}/hooks/agent", "TOKEN": "dedicated-test-bearer"},
            clear=False,
        ):
            result = deliver_outbox_item(item, route, now=NOW)
        self.assertTrue(result.accepted)
        message = json.loads(self.server.captured[0][2])["message"]
        self.assertIn("control.execution_session_get", message)
        self.assertIn("control.execution_heartbeat", message)
        self.assertIn("control.execution_session_return_request", message)
        self.assertIn("control.execution_session_return_get", message)
        self.assertIn("control.decision_request", message)
        self.assertIn("WAITING: operator decision", message)
        self.assertIn("operator-configured fixed session route", message)
        self.assertIn("fresh idempotency_key for every heartbeat", message)
        self.assertIn("execution_1", message)
        self.assertIn("attempt_1", message)
        self.assertIn("thread.done or handoff.completed", message)

    def test_execution_wake_states_first_heartbeat_window_and_renewal_cadence(self) -> None:
        from arvyx_control.agent_delivery import _response_contract

        base = self._item()

        def contract(**extra: object) -> str:
            payload = {
                **base.payload,
                "delivery_mode": "execution",
                "execution_id": "execution_1",
                "attempt_id": "attempt_1",
                **extra,
            }
            return _response_contract(OutboxItem(**{**base.to_dict(), "payload": payload}))

        windowed = contract(lease_seconds=120, first_heartbeat_seconds=300)
        self.assertIn("the first one within 300 seconds of receiving this wake", windowed)
        self.assertIn("first-heartbeat window", windowed)
        self.assertIn("at least every 60 seconds (lease_seconds=120", windowed)
        self.assertIn("pass lease_seconds=120 on each heartbeat", windowed)
        self.assertIn("renews the lease for only 120 seconds from that call", windowed)
        self.assertIn("fresh idempotency_key for every heartbeat", windowed)
        # A wake without the window (older worker) keeps the renewal-only text.
        legacy = contract(lease_seconds=120)
        self.assertNotIn("first-heartbeat window", legacy)
        self.assertIn("at least every 60 seconds (lease_seconds=120", legacy)
        # A malformed window never produces a claim the kernel would not honour.
        for bogus in (60, True, "300"):
            with self.subTest(first_heartbeat_seconds=bogus):
                self.assertNotIn(
                    "first-heartbeat window",
                    contract(lease_seconds=120, first_heartbeat_seconds=bogus),
                )

    def test_openclaw_notification_does_not_require_source_object_visibility(self) -> None:
        route = AgentRoute("amir", "openclaw-hook", "URL", "TOKEN")
        item = self._item()
        item = OutboxItem(
            **{
                **item.to_dict(),
                "payload": {
                    **item.payload,
                    "source_event_type": "thread.done",
                    "delivery_mode": "notification",
                },
            }
        )
        with patch.dict(
            os.environ,
            {"URL": f"{self.base}/hooks/agent", "TOKEN": "dedicated-test-bearer"},
            clear=False,
        ):
            result = deliver_outbox_item(item, route, now=NOW)
        self.assertTrue(result.accepted)
        message = json.loads(self.server.captured[0][2])["message"]
        self.assertIn("Verify the identity-bound delivered item", message)
        self.assertNotIn("Fetch the authoritative object", message)
        self.assertIn("receipt as completed", message)

    def test_thread_done_wake_uses_terminal_notification_contract(self) -> None:
        route = AgentRoute("amir", "hermes-webhook", "URL", "TOKEN")
        item = self._item()
        item = OutboxItem(
            **{
                **item.to_dict(),
                "subject_id": "thread_1",
                "payload": {
                    **item.payload,
                    "source_event_type": "thread.done",
                    "subject_id": "thread_1",
                    "delivery_mode": "notification",
                },
            }
        )
        with patch.dict(
            os.environ,
            {"URL": f"{self.base}/webhooks/v2-agent-push", "TOKEN": "route-hmac-secret"},
            clear=False,
        ):
            result = deliver_outbox_item(item, route, now=NOW)
        self.assertTrue(result.accepted)
        payload = json.loads(self.server.captured[0][2])
        contract = payload["response_contract"]
        self.assertIn("lifecycle notification", contract)
        self.assertIn("delivery receipt", contract)
        self.assertIn("receipt as completed", contract)
        self.assertIn("do not mutate or reply", contract)

    def test_child_done_wake_requires_exact_parent_continuation(self) -> None:
        route = AgentRoute("amir", "hermes-webhook", "URL", "TOKEN")
        item = self._item()
        item = OutboxItem(
            **{
                **item.to_dict(),
                "subject_id": "thread_child",
                "payload": {
                    **item.payload,
                    "source_event_type": "thread.done",
                    "subject_id": "thread_child",
                    "delivery_mode": "notification",
                    "continuation_thread_id": "thread_parent",
                },
            }
        )
        with patch.dict(
            os.environ,
            {"URL": f"{self.base}/webhooks/v2-agent-push", "TOKEN": "route-hmac-secret"},
            clear=False,
        ):
            result = deliver_outbox_item(item, route, now=NOW)
        self.assertTrue(result.accepted)
        contract = json.loads(self.server.captured[0][2])["response_contract"]
        self.assertIn("thread_parent", contract)
        self.assertIn("control.thread_get", contract)
        self.assertIn("notification is not an execution lease", contract)
        self.assertIn("independent execution worker", contract)
        self.assertIn("do not run, delegate, ACK, or complete parent work", contract)
        self.assertNotIn("resume the exact parent", contract)

    def test_direct_wake_names_machine_enforced_completion_contract(self) -> None:
        route = AgentRoute("amir", "hermes-webhook", "URL", "TOKEN")
        item = self._item()
        item = OutboxItem(
            **{
                **item.to_dict(),
                "payload": {
                    **item.payload,
                    "completion_artifact": "/home/operator/.hermes/memories/USER.md",
                    "completion_anchor": "0bserverx",
                },
            }
        )
        with patch.dict(
            os.environ,
            {"URL": f"{self.base}/webhooks/v2-agent-push", "TOKEN": "route-hmac-secret"},
            clear=False,
        ):
            result = deliver_outbox_item(item, route, now=NOW)
        self.assertTrue(result.accepted)
        payload = json.loads(self.server.captured[0][2])
        contract = payload["response_contract"]
        self.assertIn("/home/operator/.hermes/memories/USER.md", contract)
        self.assertIn("0bserverx", contract)
        self.assertIn("evidence_artifact", contract)
        self.assertIn("evidence_method", contract)

    def test_session_return_receipt_wake_uses_normal_route_and_names_readback_contract(self) -> None:
        route = AgentRoute(
            "amir", "hermes-webhook", "URL", "TOKEN",
            return_url_env="RETURN_URL", return_credential_env="RETURN_TOKEN",
        )
        item = self._item()
        item = OutboxItem(
            **{
                **item.to_dict(),
                "payload": {
                    **item.payload,
                    "source_event_type": "outbox.session_return.delivered",
                    "delivery_mode": "session_return_receipt",
                    "session_return_request_id": "session_return_abc123def456",
                    "execution_id": "execution_x",
                    "attempt_id": "attempt_y",
                },
            }
        )
        with patch.dict(
            os.environ,
            {
                "URL": f"{self.base}/webhooks/v2-agent-push",
                "TOKEN": "route-hmac-secret",
                "RETURN_URL": f"{self.base}/webhooks/session-return-must-not-be-called",
                "RETURN_TOKEN": "return-route-secret",
            },
            clear=False,
        ):
            result = deliver_outbox_item(item, route, now=NOW)
        self.assertTrue(result.accepted)
        # Exactly one request, and it went to the normal wake route - the
        # fixed human-visible return route is never touched.
        self.assertEqual(len(self.server.captured), 1)
        path, _headers, body = self.server.captured[0]
        self.assertEqual(path, "/webhooks/v2-agent-push")
        payload = json.loads(body)
        contract = payload["response_contract"]
        self.assertIn("session return receipt", contract)
        self.assertIn("session_return_abc123def456", contract)
        self.assertIn("control.execution_session_return_get", contract)
        self.assertIn("do not request another session return", contract)
        self.assertIn("do not resend the message", contract)
        # The wake carries identifiers only - never the message or receipt.
        self.assertNotIn("message", payload["payload"])
        self.assertNotIn("provider_receipt", payload["payload"])

    def test_http_failures_are_classified_without_leaking_credentials(self) -> None:
        route = AgentRoute(
            agent_id="amir",
            runtime="hermes-webhook",
            url_env="ARVYX_TEST_AGENT_URL",
            credential_env="ARVYX_TEST_AGENT_SECRET",
        )
        env = {
            "ARVYX_TEST_AGENT_URL": f"{self.base}/webhooks/v2-agent-push",
            "ARVYX_TEST_AGENT_SECRET": "route-hmac-secret",
        }
        for status, expected in (
            (301, "transient"),
            (401, "transient"),
            (403, "transient"),
            (429, "transient"),
            (503, "transient"),
            (400, "permanent"),
        ):
            with self.subTest(status=status):
                self.server.response_status = status
                self.server.response_payload = {"error": "rejected"}
                with patch.dict(os.environ, env, clear=False):
                    result = deliver_outbox_item(self._item(), route, now=NOW)
                self.assertFalse(result.accepted)
                self.assertEqual(result.classification, expected)
                self.assertNotIn("route-hmac-secret", result.detail)

    def test_redirect_is_not_followed_and_credentials_never_reach_second_host(self) -> None:
        thief = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thief.captured = []
        thief.response_status = 202
        thief.response_payload = {"status": "stolen"}
        thief.redirect_location = ""
        thread = threading.Thread(target=thief.serve_forever, daemon=True)
        thread.start()
        try:
            self.server.response_status = 302
            self.server.redirect_location = f"http://127.0.0.1:{thief.server_address[1]}/steal"
            route = AgentRoute("odin", "openclaw-hook", "URL", "TOKEN")
            with patch.dict(
                os.environ,
                {"URL": f"{self.base}/hooks/agent", "TOKEN": "must-not-leak"},
                clear=False,
            ):
                result = deliver_outbox_item(
                    OutboxItem(**{**self._item().to_dict(), "target": "odin"}),
                    route,
                    now=NOW,
                )
            self.assertFalse(result.accepted)
            self.assertEqual(result.classification, "transient")
            self.assertEqual(thief.captured, [])
        finally:
            thief.shutdown()
            thief.server_close()
            thread.join(timeout=2)

    def test_route_rejects_non_loopback_plain_http_but_allows_loopback_and_https(self) -> None:
        route = AgentRoute("esme", "openclaw-hook", "URL", "TOKEN")
        base = {"TOKEN": "dedicated-test-bearer"}
        self.assertIsNone(validate_agent_route(route, environ={**base, "URL": "http://127.0.0.1:8080/hooks/agent"}))
        self.assertIsNone(validate_agent_route(route, environ={**base, "URL": "https://agent.internal/hooks/agent"}))
        error = validate_agent_route(route, environ={**base, "URL": "http://100.64.0.8:8080/hooks/agent"})
        self.assertIn("https unless loopback", error or "")

    def test_route_validation_happens_before_network(self) -> None:
        route = AgentRoute(
            agent_id="amir",
            runtime="hermes-webhook",
            url_env="ARVYX_MISSING_URL",
            credential_env="ARVYX_MISSING_SECRET",
        )
        with patch.dict(os.environ, {}, clear=True):
            result = deliver_outbox_item(self._item(), route, now=NOW)
        self.assertFalse(result.accepted)
        self.assertEqual(result.classification, "configuration")
        self.assertEqual(self.server.captured, [])


if __name__ == "__main__":
    unittest.main()
