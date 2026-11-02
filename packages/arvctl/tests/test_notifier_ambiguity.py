"""Static-authored regressions for 05-02; execution requires separate approval."""
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
from email.message import Message
from http.client import IncompleteRead
from io import BytesIO
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from arvyx_control.control import (
    THREAD_NOTIFICATION_FAILED_EVENT, post_thread,
    project_thread_notifications, read_events,
)
from arvyx_control.notifiers import _post_json, _TelegramNotifier, notify_and_deliver
from arvyx_control.replica_authority import authority_context


class NotifierAmbiguityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name) / "events.jsonl"
        vault = Path(temporary.name) / "vault"
        vault.mkdir()
        self.vault = vault
        self.authority = self.enterContext(ExitStack())
        self.authority.enter_context(authority_context(vault, self.state))
        self.thread = post_thread(
            state=self.state, title="Check delivery", thread_type="ask",
            target="vesper", actor="demobot",
        ).thread.id
        self.enterContext(patch.dict(os.environ, {"AMBIGUITY_WEBHOOK": "https://example.test/hook"}))

    def notify(self, **kwargs):
        return notify_and_deliver(
            state=self.state, adapter="webhook", webhook_url_env="AMBIGUITY_WEBHOOK", **kwargs,
        )

    def assert_retained(self, opener):
        with patch("arvyx_control.notifiers.urlopen", side_effect=opener) as transport:
            first = self.notify()
            claimed = project_thread_notifications(self.state)
            second = self.notify()
        self.assertEqual(first.deliveries[0].status, "ambiguous")
        self.assertFalse(first.ok)
        self.assertIn("notification", claimed[self.thread])
        self.assertEqual(project_thread_notifications(self.state), claimed)
        self.assertEqual(second.deliveries, [])
        self.assertEqual(second.suppressed, [self.thread])
        self.assertEqual(transport.call_count, 1)
        self.assertFalse(any(event.type == THREAD_NOTIFICATION_FAILED_EVENT for event in read_events(self.state)))

    def test_consumed_post_then_disconnect_retains_claim(self):
        consumed = []

        @contextmanager
        def opener(request, **kwargs):
            consumed.append(request.data)
            raise URLError("peer closed after POST")
            yield  # pragma: no cover - contextmanager raises before response

        self.assert_retained(opener)
        self.assertEqual(len(consumed), 1)
        self.assertIn(b'"thread_id"', consumed[0])

    def test_body_timeout_incomplete_read_and_oversize_retain_claim(self):
        # Each subtest uses a new state because retained claims are intentional.
        # Authority binds one exact state path and cannot be re-bound while
        # nested, so release the setUp binding and bind each fresh state alone.
        self.authority.close()
        for error in (TimeoutError("read deadline"), IncompleteRead(b"partial"), "oversize"):
            with self.subTest(error=error):
                fresh_state = self.state.with_name(f"events-{type(error).__name__}.jsonl")
                with patch.object(self, "state", fresh_state), authority_context(self.vault, fresh_state):
                    self.thread = post_thread(
                        state=self.state, title="Body uncertainty", thread_type="ask",
                        target="vesper", actor="demobot",
                    ).thread.id

                    class Response:
                        status = 200

                        def read(self, limit):
                            if error == "oversize":
                                return b"x" * limit
                            assert isinstance(error, BaseException)
                            raise error

                    @contextmanager
                    def opener(request, **kwargs):
                        self.assertIsNotNone(request.data)
                        yield Response()

                    self.assert_retained(opener)

    def test_context_exit_framing_failure_retains_claim(self):
        class Response:
            status = 200

            def read(self, limit):
                return b"{}"

        @contextmanager
        def opener(request, **kwargs):
            yield Response()
            raise ValueError("incomplete HTTP response; nothing retried")

        self.assert_retained(opener)

    def test_local_refusal_never_opens_and_releases_claim(self):
        with patch("arvyx_control.notifiers.urlopen") as transport:
            first = self.notify(timeout=float("nan"))
            second = self.notify(timeout=float("nan"))
        transport.assert_not_called()
        self.assertEqual([first.deliveries[0].status, second.deliveries[0].status], ["failed", "failed"])
        self.assertEqual(project_thread_notifications(self.state)[self.thread], {})
        self.assertEqual(sum(e.type == THREAD_NOTIFICATION_FAILED_EVENT for e in read_events(self.state)), 2)

    def test_http_rejection_is_structured_failure(self):
        body = BytesIO(b"rejected")
        with patch("arvyx_control.notifiers.urlopen", side_effect=HTTPError(
            "https://example.test/hook", 403, "Forbidden", Message(), body,
        )):
            result = self.notify()
        self.assertEqual(result.deliveries[0].status, "failed")
        self.assertEqual(result.deliveries[0].detail, "HTTP 403")
        self.assertTrue(body.closed)
        self.assertEqual(project_thread_notifications(self.state)[self.thread], {})

    def test_telegram_unknown_transport_is_structured_and_scrubbed(self):
        token = "123:TESTAMBIGUITY"
        with patch("arvyx_control.notifiers.urlopen", side_effect=URLError(f"lost /bot{token}/sendMessage")):
            delivery = _TelegramNotifier("https://api.telegram.org", token, "123", 1).deliver(
                {"text": "Check delivery", "thread_id": self.thread}, dry_run=False,
            )
        self.assertEqual(delivery.status, "ambiguous")
        self.assertNotIn(token, delivery.detail)

    def test_normal_claim_expiry_allows_resend_but_escalation_stays_claimed(self):
        # Demonstrates the documented limitation, not exactly-once delivery.
        now = datetime.now(timezone.utc)

        @contextmanager
        def opener(request, **kwargs):
            raise URLError("acceptance unknown")
            yield

        with patch("arvyx_control.notifiers.urlopen", side_effect=opener) as transport:
            with patch("arvyx_control.health_ops._utcnow", return_value=now + timedelta(minutes=61)):
                first = self.notify(dedupe_window_minutes=240)
                repeated = self.notify(dedupe_window_minutes=240)
            with patch("arvyx_control.health_ops._utcnow", return_value=now + timedelta(minutes=301)):
                expired = self.notify(dedupe_window_minutes=240)
        self.assertEqual({d.kind for d in first.deliveries}, {"notification", "escalation"})
        self.assertEqual(repeated.deliveries, [])
        self.assertEqual([d.kind for d in expired.deliveries], ["notification"])
        self.assertEqual(transport.call_count, 3)

    def test_local_sink_exception_still_releases_claim(self):
        with patch("arvyx_control.notifiers._StdoutNotifier.deliver", side_effect=OSError("sink failed")):
            first = notify_and_deliver(self.state, adapter="stdout")
            second = notify_and_deliver(self.state, adapter="stdout")
        self.assertEqual([first.deliveries[0].status, second.deliveries[0].status], ["failed", "failed"])
        self.assertEqual(project_thread_notifications(self.state)[self.thread], {})

    def test_bad_request_returns_definite_refusal(self):
        with patch("arvyx_control.notifiers.urlopen") as transport:
            outcome = _post_json("https://example.test:bad/hook", {}, 1)
        self.assertEqual(outcome.status, "failed")
        transport.assert_not_called()
