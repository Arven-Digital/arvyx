"""Depth10 execution regression specifications; runtime execution not authorized."""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
from contextlib import contextmanager
import os

from arvyx_control import control, execution, store
from arvyx_control.replica_authority import authority_context

NOW = datetime(2026, 10, 28, tzinfo=timezone.utc)
STAMP = "2026-10-28T00:00:00Z"


@contextmanager
def state_barriers(state, *, error=None):
    """Observe the exact log barriers, not unrelated authority lock fsyncs."""
    original = os.fsync
    log_barrier = Mock(wraps=original)
    def synchronize(fd):
        actual, expected = os.fstat(fd), state.stat()
        if (actual.st_dev,actual.st_ino)==(expected.st_dev,expected.st_ino):
            if error is not None:
                raise OSError(error)
            return log_barrier(fd)
        return original(fd)
    with patch.object(control.os, "fsync", side_effect=synchronize), patch.object(
            control, "fsync_directory", wraps=control.fsync_directory) as directory:
        yield log_barrier, directory


class ExecutionStateRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "events.jsonl"
        self.vault = self.root / "vault"
        self.vault.mkdir()
        self.enterContext(authority_context(self.vault, self.state))

    def seed(self, status="pending", attempts=0):
        item = execution.Execution(
            id="execution_test", subject_id="thread_test", subject_type="thread",
            target="amir", source_event_id="assignment_test", source_event_type="thread.created",
            status=status, attempts=attempts, created_at=STAMP, updated_at=STAMP,
        )
        self.append(item, "execution.created")
        return item

    def append(self, item, kind):
        event = control._event(kind, item.id, STAMP, item.to_dict())
        control._append_event(self.state, event)
        return event

    def test_visible_stop_retries_repair_both_barriers_without_duplicate(self):
        for kind in ("cancel", "hold", "close"):
            with self.subTest(kind=kind):
                self.state.unlink(missing_ok=True)
                item = self.seed("held" if kind == "close" else "pending")
                if kind == "cancel":
                    invoke = lambda: execution.cancel_execution(self.state, execution_id=item.id, reason="stop", cancelled_by="op", now=NOW)
                elif kind == "hold":
                    invoke = lambda: execution.hold_execution(self.state, execution_id=item.id, reason="stop", held_by="op", now=NOW)
                else:
                    invoke = lambda: execution.close_execution(self.state, execution_id=item.id, resolution_category="obsolete", reason="stop", closed_by="op", now=NOW)
                with state_barriers(self.state, error="uncertain"):
                    with self.assertRaises(OSError):
                        invoke()
                before = self.state.read_bytes()
                with state_barriers(self.state, error="still uncertain"):
                    with self.assertRaises(OSError):
                        invoke()
                with state_barriers(self.state) as (file_barrier, directory_barrier):
                    invoke()
                    file_barrier.assert_called_once()
                    directory_barrier.assert_called_once_with(self.state.parent)
                self.assertEqual(before, self.state.read_bytes())

    def test_steer_request_and_ack_retry_repair_durability(self):
        item = self.seed()
        item = replace(item, status="leased", attempts=1, attempt_id="attempt_test", lease_owner="worker", lease_expires_at="2026-10-29T00:00:00Z")
        self.append(item, "execution.attempt.started")
        request = lambda: execution.request_execution_steer(self.state, execution_id=item.id, attempt_id=item.attempt_id, message="inspect", requested_by="op", idempotency_key="synthetic-steer-request", now=NOW)
        with state_barriers(self.state, error="uncertain"):
            with self.assertRaises(OSError):
                request()
        with state_barriers(self.state, error="still uncertain"):
            with self.assertRaises(OSError):
                request()
        before = self.state.read_bytes()
        with state_barriers(self.state) as (barrier, directory):
            result = request()
            barrier.assert_called_once()
            directory.assert_called_once()
        self.assertEqual(before, self.state.read_bytes())
        ack = lambda: execution.acknowledge_execution_steer(self.state, execution_id=item.id, attempt_id=item.attempt_id, request_id=result["request_id"], actor="amir", message="received", idempotency_key="synthetic-steer-acknowledgement", now=NOW)
        with state_barriers(self.state, error="uncertain"):
            with self.assertRaises(OSError):
                ack()
        with state_barriers(self.state, error="still uncertain"):
            with self.assertRaises(OSError):
                ack()
        before = self.state.read_bytes()
        with state_barriers(self.state) as (barrier, directory):
            ack()
            barrier.assert_called_once()
            directory.assert_called_once()
        self.assertEqual(before, self.state.read_bytes())

    def remediate(self, item, revision, budget=1):
        return execution.remediate_dead_letter(self.state, item.id, expected_event_id=revision.id, actor="watchdog", max_replays=budget, hold_reason="budget exhausted", now=NOW)

    def test_atomic_remediation_uses_current_budget_and_rejects_old_revision(self):
        item = self.seed("dead_lettered", 3)
        revision = control.read_events(self.state)[-1]
        action, pending = self.remediate(item, revision)
        self.assertEqual(action, "replayed")
        self.assertEqual(pending.attempts, 0)
        leased = replace(pending, status="leased", attempts=1, attempt_id="fresh", lease_owner="new-worker", lease_expires_at="2026-10-29T00:00:00Z")
        self.append(leased, "execution.attempt.started")
        before = self.state.read_bytes()
        self.assertEqual(self.remediate(item, revision), ("changed", leased))
        self.assertEqual(before, self.state.read_bytes())
        dead = replace(leased, status="dead_lettered", lease_owner="", lease_expires_at="")
        latest = self.append(dead, "execution.dead_lettered")
        action, held = self.remediate(dead, latest)
        self.assertEqual(action, "held")
        self.assertEqual(held.status, "held")

    def test_terminal_and_quarantined_observation_are_benign_skips(self):
        item = self.seed("dead_lettered")
        revision = control.read_events(self.state)[-1]
        for status, kind in (("completed", "execution.completed"), ("closed", "execution.closed")):
            current = replace(item, status=status)
            self.append(current, kind)
            before = self.state.read_bytes()
            self.assertEqual(self.remediate(item, revision), ("changed", current))
            self.assertEqual(before, self.state.read_bytes())
        self.append(replace(item, attempts=-1), "execution.dead_lettered")
        self.assertEqual(self.remediate(item, revision), ("changed", None))

    def test_subject_terminal_after_observation_blocks_replay_and_hold(self):
        item = self.seed("dead_lettered")
        revision = control.read_events(self.state)[-1]
        terminal = control._event("thread.done", item.subject_id, STAMP,
                                  {"done_by": item.target, "actor_identity_bound": True})
        control._append_event(self.state, terminal)
        before = self.state.read_bytes()
        for budget in (0, 1):
            with self.subTest(budget=budget):
                self.assertEqual(self.remediate(item, revision, budget), ("changed", item))
                self.assertEqual(before, self.state.read_bytes())

    def test_remediation_does_not_hide_durability_failure(self):
        item = self.seed("dead_lettered")
        revision = control.read_events(self.state)[-1]
        with state_barriers(self.state, error="uncertain"):
            with self.assertRaises(OSError):
                self.remediate(item, revision)

    def test_quarantined_assignment_never_recreates_and_reports_diagnostic(self):
        thread = control.post_thread(self.state, title="work", actor="op", target="amir", thread_type="ask", actor_identity_bound=True)
        root_id = execution._execution_id("thread", thread.thread.id, "amir")
        malformed = control._event("execution.created", root_id, STAMP, {"id": root_id, "attempts": -1})
        control._append_event(self.state, malformed)
        before = self.state.read_bytes()
        for _ in range(3):
            diagnostics = []
            self.assertEqual(execution.materialize_executions(self.state, execution_capable_targets={"amir"}, quarantined=diagnostics, now=NOW), [])
            self.assertIn(root_id, diagnostics)
            self.assertIsNone(execution.claim_execution(self.state, worker="worker", execution_capable_targets={"amir"}, now=NOW))
        self.assertEqual(before, self.state.read_bytes())
        events = control.read_events(self.state)
        seed = execution._executions_seed(events)
        assignment_seed = execution._assignments_seed(events)
        def checkpoint_source(state, projection):
            return (assignment_seed if projection == "assignments" else seed, [], "checkpoint")
        with patch.object(execution.projection_cache, "projection_source", side_effect=checkpoint_source):
            for _ in range(3):
                diagnostics = []
                self.assertEqual(execution.materialize_executions(self.state, execution_capable_targets={"amir"}, quarantined=diagnostics, now=NOW), [])
                self.assertIn(root_id, diagnostics)
        self.assertEqual(before, self.state.read_bytes())

    def test_manifest_never_rereads_metadata_from_newer_generation(self):
        item = self.seed()
        before = self.state.read_bytes()
        original = Path.read_bytes
        def read_then_append(path):
            raw = original(path)
            if path == self.state:
                self.append(replace(item, status="held"), "execution.held")
            return raw
        with patch.object(Path, "read_bytes", read_then_append), patch.object(store, "read_events", side_effect=AssertionError("manifest must not reread")):
            receipt = store.manifest_state(self.state)
        self.assertEqual(receipt.sha256, hashlib.sha256(before).hexdigest())
        self.assertEqual(receipt.events, 1)
        self.assertEqual(receipt.event_types, {"execution.created": 1})
        self.assertEqual(receipt.first_timestamp, STAMP)
        self.assertEqual(receipt.last_timestamp, STAMP)
