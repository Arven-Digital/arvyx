from arvyx_control.replica_authority import authority_context
"""Capability-scoped historical claims. Execution status: NOT_EXECUTED."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.control import complete_thread, post_thread, read_events
from arvyx_control.execution import (
    claim_execution, materialize_executions, project_executions,
    reconcile_executions, record_execution_failure,
)

T0 = datetime(2026, 8, 20, 12, tzinfo=timezone.utc)


class ClaimCapabilityTests(unittest.TestCase):
    def assignment(self, state, target):
        return post_thread(
            state, title="capability regression", actor="operator", target=target,
            thread_type="ask", actor_identity_bound=True,
        ).thread.id

    def test_foreign_history_is_untouched_before_every_claim_mutation(self):
        for history in ("pending", "expired", "failed", "exhausted", "blocked", "terminal"):
            with self.subTest(history=history), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / "events.jsonl"
                vault = Path(tmp) / "authority-vault"
                vault.mkdir(exist_ok=True)
                with authority_context(vault, state):
                    subject = self.assignment(state, "amir")
                    materialize_executions(state, execution_capable_targets={"amir"}, now=T0)
                    foreign = next(iter(project_executions(state).values()))
                    if history in {"expired", "failed", "exhausted", "blocked"}:
                        foreign = claim_execution(
                            state, worker="original", execution_capable_targets={"amir"},
                            now=T0, lease_seconds=1,
                        )
                    if history == "failed":
                        record_execution_failure(
                            state, execution_id=foreign.id, attempt_id=foreign.attempt_id,
                            worker="original", detail="delivery failed", now=T0,
                        )
                    if history == "terminal":
                        complete_thread(state, subject, actor="amir", actor_identity_bound=True)
                    self.assignment(state, "kiran")
                    materialize_executions(state, execution_capable_targets={"kiran"}, now=T0)
                    before = project_executions(state)[foreign.id]
                    foreign_events = [e for e in read_events(state) if e.task_id == foreign.id]
                    streaks = {foreign.id: (2, "BLOCKED: missing authority")} if history == "blocked" else {}
                    with patch("arvyx_control.execution._blocked_streaks", return_value=streaks):
                        selected = claim_execution(
                            state, worker="current", execution_capable_targets=iter([" KIRAN ", ""]),
                            now=T0 + timedelta(minutes=10), max_attempts=1,
                        )
                    self.assertIsNotNone(selected)
                    self.assertEqual(selected.target, "kiran")
                    self.assertEqual(selected.attempts, 1)
                    self.assertEqual(selected.lease_owner, "current")
                    self.assertEqual(project_executions(state)[foreign.id], before)
                    self.assertEqual([e for e in read_events(state) if e.task_id == foreign.id], foreign_events)
                    if history == "terminal":
                        # Explicit global reconciliation retains its existing scope.
                        reconcile_executions(state, now=T0 + timedelta(minutes=11))
                        self.assertEqual(project_executions(state)[foreign.id].status, "completed")

    def test_retry_uses_time_after_final_claim_lock(self):
        # NOT_EXECUTED: two preparatory acquisitions must not pin final authority.
        from contextlib import contextmanager
        from arvyx_control import execution as lifecycle

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self.assignment(state, "amir")
                first = claim_execution(state, worker="old", execution_capable_targets={"amir"},
                                        now=T0, lease_seconds=60)
                moment = [T0 + timedelta(seconds=59)]
                locks = [0]
                real_lock = lifecycle._locked_state
                @contextmanager
                def delayed_lock(path):
                    with real_lock(path):
                        locks[0] += 1
                        if locks[0] == 3:
                            moment[0] = T0 + timedelta(seconds=61)
                        yield
                class Clock(datetime):
                    @classmethod
                    def now(cls, tz=None):
                        return moment[0]
                with patch.object(lifecycle, "datetime", Clock), patch.object(lifecycle, "_locked_state", delayed_lock):
                    retried = claim_execution(state, worker="new", execution_capable_targets={"amir"},
                                              retry_backoff_seconds=0)
                self.assertIsNotNone(retried)
                self.assertEqual(retried.attempts, first.attempts + 1)
                self.assertEqual(retried.lease_owner, "new")
                self.assertEqual(retried.updated_at, "2026-08-20T12:01:01Z")

    def test_generator_materializes_and_claims_with_same_normalized_capabilities(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self.assignment(state, "amir")
                claimed = claim_execution(
                    state, worker="current", execution_capable_targets=(s for s in [" AMIR ", ""]), now=T0,
                )
                self.assertEqual(claimed.target, "amir")
                self.assertEqual(claimed.attempts, 1)

    def test_empty_and_none_never_grant_historical_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self.assignment(state, "amir")
                materialize_executions(state, execution_capable_targets={"amir"}, now=T0)
                before = read_events(state)
                for capabilities in (set(), iter(()), [" "]):
                    self.assertIsNone(claim_execution(
                        state, worker="current", execution_capable_targets=capabilities, now=T0,
                    ))
                with self.assertRaises(TypeError):
                    claim_execution(state, worker="current", execution_capable_targets=None, now=T0)
                self.assertEqual(read_events(state), before)

    def test_exact_selection_still_requires_canonical_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self.assignment(state, "amir")
                before = read_events(state)
                with self.assertRaises(ValueError):
                    claim_execution(
                        state, worker="current", execution_capable_targets=iter(["kiran"]),
                        subject_id=subject, target="amir", now=T0,
                    )
                self.assertEqual(read_events(state), before)
                claimed = claim_execution(
                    state, worker="current", execution_capable_targets=iter([" AMIR "]),
                    subject_id=subject, target="amir", now=T0,
                )
                self.assertEqual(claimed.subject_id, subject)
                self.assertEqual(claimed.target, "amir")
