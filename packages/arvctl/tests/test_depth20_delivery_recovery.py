"""Delivery recovery regression sources. Not executed in the Deep20 fix round."""
from datetime import timedelta
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from arvyx_control import http_bounds, notifiers
from arvyx_control.control import complete_thread, post_thread, read_events
from arvyx_control.outbox import (
    claim_due, mark_delivery_ambiguous, project_outbox,
    reconcile_ambiguous_delivery,
)
from arvyx_control.replica_authority import authority_context
import test_session_return as returns_fixture
import test_watchdog as watchdog_fixture


class DeliveryRecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.state = Path(tmp) / "events.jsonl"
        vault = Path(tmp) / "vault"
        vault.mkdir()
        self.enterContext(authority_context(vault, self.state))

    def test_receipt_enqueue_exception_recovers_without_resending(self):
        fixture = returns_fixture.SessionReturnContinuationTests()
        _, execution, requested, sent, tick = fixture._requested(self.state)
        with patch("arvyx_control.dispatcher.enqueue_session_return_continuation",
                   side_effect=OSError("injected enqueue failure")):
            tick()
        self.assertEqual(fixture._continuations(self.state), [])
        self.assertEqual(returns_fixture.get_session_return(
            self.state, request_id=requested.request_id, actor="amir").status, "delivered")
        tick()
        tick()
        wakes = fixture._continuations(self.state)
        self.assertEqual(len(wakes), 1)
        self.assertEqual(wakes[0].payload["attempt_id"], execution.attempt_id)
        self.assertEqual(wakes[0].target, execution.target)
        self.assertNotIn("message", wakes[0].payload)
        self.assertNotIn("provider_receipt", wakes[0].payload)
        self.assertEqual([mode for mode, _ in sent].count("session_return"), 1)
        self.assertEqual([mode for mode, _ in sent].count("session_return_receipt"), 1)
        events = read_events(self.state)
        receipt_index = next(i for i, e in enumerate(events)
                             if e.type == "outbox.delivered"
                             and e.payload.get("payload", {}).get("delivery_mode") == "session_return")
        wake_index = next(i for i, e in enumerate(events)
                          if e.type == "outbox.enqueued" and e.task_id == wakes[0].id)
        self.assertLess(receipt_index, wake_index)

    def test_process_interruption_after_receipt_recovers_on_new_tick(self):
        fixture = returns_fixture.SessionReturnContinuationTests()
        _, _, _, sent, tick = fixture._requested(self.state)
        # BaseException models process interruption: dispatcher must not turn it
        # into a retry or undo the already durable delivered receipt.
        with patch("arvyx_control.dispatcher.enqueue_session_return_continuation",
                   side_effect=SystemExit("injected interruption")):
            with self.assertRaises(SystemExit):
                tick()
        self.assertEqual(fixture._continuations(self.state), [])
        tick()
        tick()
        self.assertEqual(len(fixture._continuations(self.state)), 1)
        self.assertEqual([mode for mode, _ in sent].count("session_return"), 1)

    def test_terminal_subject_skips_missing_wake(self):
        fixture = returns_fixture.SessionReturnContinuationTests()
        thread_id, _, _, sent, tick = fixture._requested(self.state)
        with patch("arvyx_control.dispatcher.enqueue_session_return_continuation",
                   side_effect=OSError("injected")):
            tick()
        complete_thread(self.state, thread_id, actor="amir", actor_identity_bound=True)
        tick()
        self.assertEqual(fixture._continuations(self.state), [])
        self.assertEqual([mode for mode, _ in sent].count("session_return"), 1)

    def test_ambiguous_readback_receipt_gap_recovers(self):
        fixture = returns_fixture.SessionReturnContinuationTests()
        _, _, requested, sent, tick = fixture._requested(self.state)
        leased = claim_due(self.state, worker="readback", now=returns_fixture.T0,
                           deliver_after="2026-08-20T11:00:00Z", targets={"amir"}, limit=10)
        original = next(i for i in leased if i.subject_id == requested.request_id)
        mark_delivery_ambiguous(self.state, outbox_id=original.id, worker="readback", claim_attempts=next(c.attempts for c in leased if c.id == original.id),
                                detail="acceptance unknown", now=returns_fixture.T0)
        with patch("arvyx_control.session_return.enqueue_session_return_continuation",
                   side_effect=SystemExit("receipt durable, process exits")):
            with self.assertRaises(SystemExit):
                reconcile_ambiguous_delivery(
                    self.state, outbox_id=original.id, resolved_by="operator",
                    outcome="delivered", provider_receipt="provider-readback-1",
                    now=returns_fixture.T0)
        tick()
        tick()
        self.assertEqual(len(fixture._continuations(self.state)), 1)
        self.assertEqual([mode for mode, _ in sent].count("session_return"), 0)
        self.assertEqual(project_outbox(self.state)[original.id].status, "delivered")

    def test_broadcast_progresses_with_one_item_budget(self):
        with patch("arvyx_control.control._now", return_value="2026-08-20T12:00:00Z"):
            broadcast = post_thread(self.state, title="broadcast", actor="esme",
                                    target="all", thread_type="status").thread.id
            later = post_thread(self.state, title="later", actor="esme", target="amir").thread.id
        for _ in range(5):
            claim_due(self.state, worker="bounded", now=returns_fixture.T0,
                      deliver_after="2026-08-20T11:00:00Z", targets={"amir", "vesper"},
                      materialization_limit=1, limit=1)
        items = list(project_outbox(self.state).values())
        self.assertEqual(sorted(i.target for i in items if i.subject_id == broadcast),
                         ["amir", "vesper"])
        self.assertEqual(len([i for i in items if i.subject_id == later]), 1)

    def test_no_escalate_hold_is_paged_on_later_tick_once(self):
        fixture = watchdog_fixture.WatchdogTests()
        execution_id = fixture._dead_letter(self.state)
        first = fixture._dead_letter_twice_then_watch(self.state, execution_id, escalate=False)
        self.assertEqual(first["held"], [execution_id])
        self.assertEqual(first["escalated"], [])
        result = watchdog_fixture.run_watchdog(
            self.state, routes=watchdog_fixture.ROUTES, environ=watchdog_fixture.ENV_OK,
            now=watchdog_fixture.T0 + timedelta(seconds=100))
        self.assertEqual(result["escalated"], [execution_id])
        again = watchdog_fixture.run_watchdog(
            self.state, routes=watchdog_fixture.ROUTES, environ=watchdog_fixture.ENV_OK,
            now=watchdog_fixture.T0 + timedelta(seconds=110))
        self.assertEqual(again["escalated"], [])

    def test_hold_interrupted_before_page_recovers_once(self):
        fixture = watchdog_fixture.WatchdogTests()
        execution_id = fixture._dead_letter(self.state)
        # Drive replay first, then fail the page after hold persistence.
        watchdog_fixture.run_watchdog(
            self.state, routes=watchdog_fixture.ROUTES, environ=watchdog_fixture.ENV_OK,
            now=watchdog_fixture.T0 + timedelta(seconds=17), escalate=False)
        for seconds in (20, 37):
            watchdog_fixture.claim_execution(
                self.state, worker="prod", execution_capable_targets={"amir"},
                now=watchdog_fixture.T0 + timedelta(seconds=seconds),
                lease_seconds=1, max_attempts=1)
        with patch("arvyx_control.watchdog.post_thread", side_effect=SystemExit("interrupted")):
            with self.assertRaises(SystemExit):
                watchdog_fixture.run_watchdog(
                    self.state, routes=watchdog_fixture.ROUTES, environ=watchdog_fixture.ENV_OK,
                    now=watchdog_fixture.T0 + timedelta(seconds=40))
        self.assertEqual(watchdog_fixture.project_executions(self.state)[execution_id].status, "held")
        for seconds, expected in ((100, [execution_id]), (110, [])):
            result = watchdog_fixture.run_watchdog(
                self.state, routes=watchdog_fixture.ROUTES, environ=watchdog_fixture.ENV_OK,
                now=watchdog_fixture.T0 + timedelta(seconds=seconds))
            self.assertEqual(result["escalated"], expected)

    def test_dry_run_and_exact_manifest_do_not_recover(self):
        fixture = returns_fixture.SessionReturnContinuationTests()
        fixture_data = fixture._requested(self.state)
        tick = fixture_data[-1]
        with patch("arvyx_control.dispatcher.enqueue_session_return_continuation",
                   side_effect=OSError("injected")):
            tick()
        before = list(read_events(self.state))
        claim_due(self.state, worker="dry", now=returns_fixture.T0, dry_run=True)
        with self.assertRaises(ValueError):
            claim_due(self.state, worker="exact", now=returns_fixture.T0, exact_allowlist=[])
        self.assertEqual(read_events(self.state), before)
        self.assertEqual(fixture._continuations(self.state), [])

    def test_local_exception_releases_each_preclaimed_candidate(self):
        # A preclaimed (non-dry-run) candidate always carries the exact claim
        # event that health_ops.notify_check appended; release is fenced on it.
        candidates = [dict(thread_id=f"thread-{i}", kind=kind, text="notice",
                           claim_event_id=f"event_synthetic_claim_{i}")
                      for i, kind in enumerate(("notification", "notification", "escalation"))]
        result = Mock(candidates=candidates, suppressed=[])
        notifier = Mock()
        notifier.deliver.side_effect = PermissionError("must not expose destination")
        with patch.object(notifiers, "notify_check", return_value=result), \
                patch.object(notifiers, "_build_notifier", return_value=notifier), \
                patch.object(notifiers, "record_thread_notification_failure") as release:
            actual = notifiers.notify_and_deliver(self.state, adapter="file")
        self.assertEqual(notifier.deliver.call_count, 3)
        self.assertEqual(release.call_count, 3)
        self.assertEqual([call.kwargs["claim_event_id"] for call in release.call_args_list],
                         [candidate["claim_event_id"] for candidate in candidates])
        self.assertEqual([(call.kwargs["thread_id"], call.kwargs["kind"]) for call in release.call_args_list],
                         [(candidate["thread_id"], candidate["kind"]) for candidate in candidates])
        self.assertFalse(actual.ok)
        self.assertTrue(all(d.status == "failed" for d in actual.deliveries))
        self.assertTrue(all("destination" not in d.detail for d in actual.deliveries))

    def test_real_notification_claims_retry_after_local_failure(self):
        with patch("arvyx_control.control._now", return_value="2026-08-20T10:00:00Z"):
            for index in range(2):
                post_thread(self.state, title=f"pending {index}", actor="esme", target="amir")
        destination = self.state.parent / "deliveries.jsonl"
        with patch("arvyx_control.health_ops._utcnow", return_value=returns_fixture.T0):
            with patch.object(notifiers._FileNotifier, "deliver", side_effect=PermissionError("denied")):
                failed = notifiers.notify_and_deliver(
                    self.state, adapter="file", deliveries_path=destination, escalate_after_minutes=60)
            self.assertEqual(len(failed.deliveries), 4)
            self.assertTrue(all(d.status == "failed" for d in failed.deliveries))
            recovered = notifiers.notify_and_deliver(
                self.state, adapter="file", deliveries_path=destination, escalate_after_minutes=60)
            self.assertEqual(len(recovered.deliveries), 4)
            self.assertTrue(recovered.ok)
            self.assertEqual(sum(d.kind == "escalation" for d in recovered.deliveries), 2)
            deduped = notifiers.notify_and_deliver(
                self.state, adapter="file", deliveries_path=destination, escalate_after_minutes=60)
            self.assertEqual(deduped.deliveries, [])

    def test_outbound_unexpected_exception_does_not_release_ambiguous_claim(self):
        result = Mock(candidates=[dict(thread_id="t", kind="escalation", text="notice")], suppressed=[])
        notifier = Mock()
        notifier.deliver.side_effect = OSError("unknown acceptance")
        with patch.object(notifiers, "notify_check", return_value=result), \
                patch.object(notifiers, "_build_notifier", return_value=notifier), \
                patch.object(notifiers, "record_thread_notification_failure") as release:
            actual = notifiers.notify_and_deliver(self.state, adapter="webhook")
        release.assert_not_called()
        self.assertFalse(actual.ok)
        self.assertEqual(actual.deliveries[0].status, "ambiguous")


class TotalTcpDeadlineTests(unittest.TestCase):
    def test_dns_and_all_addresses_share_one_deadline(self):
        clock = [0.0]
        timeouts = []
        sockets = []

        def resolve(host, port, deadline):
            self.assertEqual(deadline, 3.0)
            clock[0] += 1.0
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", port))] * 3

        def new_socket(*args):
            sock = Mock()
            sock.settimeout.side_effect = lambda value: None
            def connect(address):
                timeouts.append(sock.settimeout.call_args.args[0])
                clock[0] += 1.1
                raise OSError("unreachable")
            sock.connect.side_effect = connect
            sockets.append(sock)
            return sock

        with patch.object(http_bounds.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(http_bounds, "_resolve", side_effect=resolve), \
                patch.object(http_bounds.socket, "socket", side_effect=new_socket):
            with self.assertRaises(TimeoutError):
                http_bounds.bounded_tcp_connection(("example.invalid", 443), 3)
        self.assertEqual(len(sockets), 2)
        self.assertEqual(timeouts[0], 2.0)
        self.assertAlmostEqual(timeouts[1], 0.9)
        for sock in sockets:
            sock.close.assert_called_once()

    def test_stalled_resolver_capacity_is_retained_until_worker_exits(self):
        entered, release = threading.Event(), threading.Event()
        slots = threading.BoundedSemaphore(1)
        def stalled(*args):
            entered.set()
            release.wait(2)
            return []
        with patch.object(http_bounds, "_DNS_SLOTS", slots), \
                patch.object(http_bounds.socket, "getaddrinfo", side_effect=stalled) as resolve:
            try:
                with self.assertRaises(TimeoutError):
                    http_bounds.bounded_tcp_connection(("example.invalid", 443), 0.02)
                self.assertTrue(entered.is_set())
                with self.assertRaises(TimeoutError):
                    http_bounds.bounded_tcp_connection(("example.invalid", 443), 0.02)
                self.assertEqual(resolve.call_count, 1)
            finally:
                release.set()
            # Wait for worker ownership to be returned before removing mocks.
            self.assertTrue(slots.acquire(timeout=2))
            slots.release()
