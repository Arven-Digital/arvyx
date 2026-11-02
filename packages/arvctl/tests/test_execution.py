from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.replica_authority import authority_context
from arvyx_control.agent_delivery import AgentDeliveryResult, AgentRoute
from arvyx_control.cli import main
from arvyx_control.control import (
    ControlEvent, _append_event, accept_handoff, acknowledge_thread, complete_handoff,
    complete_thread, create_handoff, post_thread, read_events,
)
from arvyx_control.execution import (
    cancel_execution,
    claim_execution,
    close_execution,
    deliver_execution_attempt,
    heartbeat_execution,
    heartbeat_execution_as_target,
    hold_execution,
    materialize_executions,
    project_executions,
    queue_health,
    record_execution_failure,
    reconcile_executions,
    replay_execution,
)

UTC = timezone.utc
T0 = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)


class DurableExecutionTests(unittest.TestCase):
    def _acked(self, state: Path, *, target: str = "amir", actor: str = "amir", type: str = "ask"):
        with patch("arvyx_control.control._now", side_effect=["2026-08-20T11:59:00Z", "2026-08-20T12:00:00Z"]):
            thread = post_thread(
                state, title="durable work", actor="esme", target=target,
                thread_type=type, actor_identity_bound=True,
            )
            acknowledge_thread(
                state, thread.thread.id, actor=actor, actor_identity_bound=True,
            )
        return thread.thread.id

    def test_parent_execution_waits_without_retry_while_continuation_child_is_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                parent_id = self._acked(state)
                first = claim_execution(
                    state,
                    worker="worker-a",
                    execution_capable_targets={"amir"},
                    now=T0,
                    lease_seconds=1,
                )
                self.assertIsNotNone(first)
                child = post_thread(
                    state,
                    title="delegated dependency",
                    actor="amir",
                    target="kiran",
                    continuation_thread_id=parent_id,
                    actor_identity_bound=True,
                )
                acknowledge_thread(
                    state,
                    child.thread.id,
                    actor="kiran",
                    actor_identity_bound=True,
                )

                self.assertIsNone(
                    claim_execution(
                        state,
                        worker="worker-b",
                        execution_capable_targets={"amir"},
                        now=T0 + timedelta(seconds=20),
                        lease_seconds=1,
                    )
                )
                self.assertEqual(project_executions(state)[first.id].attempts, 1)

                complete_thread(
                    state,
                    child.thread.id,
                    actor="kiran",
                    actor_identity_bound=True,
                )
                resumed = claim_execution(
                    state,
                    worker="worker-b",
                    execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=20),
                    lease_seconds=1,
                )
                self.assertIsNotNone(resumed)
                self.assertEqual(resumed.id, first.id)
                self.assertEqual(resumed.attempts, 2)

    def test_actionable_assignment_for_capable_target_materializes_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                eligible = self._acked(state)
                self._acked(state, target="odin", actor="esme")
                with patch("arvyx_control.control._now", side_effect=["2026-08-20T12:01:00Z"]):
                    post_thread(state, title="broadcast", actor="esme", target="all", thread_type="update")

                first = materialize_executions(state, execution_capable_targets={"amir"}, now=T0)
                second = materialize_executions(state, execution_capable_targets={"amir"}, now=T0)

                self.assertEqual(len(first), 1)
                self.assertEqual(second, [])
                execution = next(iter(project_executions(state).values()))
                self.assertEqual(execution.subject_id, eligible)
                self.assertEqual(execution.subject_type, "thread")
                self.assertEqual(execution.target, "amir")
                self.assertEqual(execution.source_event_type, "thread.created")

    def test_handoff_requires_target_authored_acceptance_to_materialize(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with patch("arvyx_control.control._now", side_effect=["2026-08-20T11:59:00Z", "2026-08-20T12:00:00Z"]):
                    handoff = create_handoff(
                        state, "durable handoff", from_agent="esme", to_agent="amir",
                        actor_identity_bound=True,
                    )
                accepted = accept_handoff(state, handoff.handoff.id, actor="amir", actor_identity_bound=True)
                self.assertEqual(accepted.event.payload["accepted_by"], "amir")
                created = materialize_executions(state, execution_capable_targets={"amir"}, now=T0)
                self.assertEqual(len(created), 1)
                self.assertEqual(created[0].subject_type, "handoff")
                self.assertEqual(created[0].subject_id, handoff.handoff.id)

    def test_expired_lease_reclaims_same_id_and_max_attempts_dead_letters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                first = claim_execution(state, worker="one", execution_capable_targets={"amir"}, now=T0, lease_seconds=10, max_attempts=2)
                blocked = claim_execution(state, worker="two", execution_capable_targets={"amir"}, now=T0 + timedelta(seconds=9), max_attempts=2)
                # Expired at +10s, but the re-wake backoff (15s after expiry for
                # attempt one) holds the reclaim so a stalled target is not
                # re-woken on the very next tick.
                backoff_blocked = claim_execution(state, worker="two", execution_capable_targets={"amir"}, now=T0 + timedelta(seconds=10), max_attempts=2)
                reclaimed = claim_execution(state, worker="two", execution_capable_targets={"amir"}, now=T0 + timedelta(seconds=25), max_attempts=2)
                # Second lease (default 60s) expires at +85s; backoff(2)=30s.
                dead = claim_execution(state, worker="three", execution_capable_targets={"amir"}, now=T0 + timedelta(seconds=115), max_attempts=2)

                self.assertEqual(blocked, None)
                self.assertEqual(backoff_blocked, None)
                self.assertEqual(reclaimed.id, first.id)
                self.assertEqual(reclaimed.attempts, 2)
                self.assertEqual(dead, None)
                projected = project_executions(state)[first.id]
                self.assertEqual(projected.status, "dead_lettered")
                self.assertEqual(projected.last_failure, "lease expired before heartbeat or finalization")

    def test_heartbeat_extends_bounded_lease_and_records_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self._acked(state)
                execution = claim_execution(state, worker="one", execution_capable_targets={"amir"}, now=T0, lease_seconds=10)
                beat = heartbeat_execution(state, execution_id=execution.id, attempt_id=execution.attempt_id, worker="one", now=T0 + timedelta(seconds=5), lease_seconds=10)
                self.assertEqual(beat.subject_id, subject)
                self.assertEqual(beat.heartbeat_at, "2026-08-20T12:00:05Z")
                self.assertEqual(beat.lease_expires_at, "2026-08-20T12:00:15Z")

    def test_heartbeat_projects_explicit_runtime_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"}, now=T0,
                )

                beat = heartbeat_execution_as_target(
                    state,
                    execution_id=execution.id,
                    attempt_id=execution.attempt_id,
                    actor="amir",
                    now=T0,
                    runtime_outcome="waiting_human",
                    detail="approval required",
                )

                self.assertEqual(beat.runtime_outcome, "waiting_human")
                self.assertEqual(project_executions(state)[execution.id].runtime_outcome, "waiting_human")

    def test_heartbeat_rejects_unknown_runtime_outcome_without_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"}, now=T0,
                )
                before = len(read_events(state))

                with self.assertRaisesRegex(ValueError, "runtime outcome"):
                    heartbeat_execution_as_target(
                        state,
                        execution_id=execution.id,
                        attempt_id=execution.attempt_id,
                        actor="amir",
                        now=T0,
                        runtime_outcome="probably_done",
                    )

                self.assertEqual(len(read_events(state)), before)

    def test_new_attempt_clears_prior_runtime_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                first = claim_execution(
                    state,
                    worker="one",
                    execution_capable_targets={"amir"},
                    now=T0,
                    lease_seconds=10,
                )
                heartbeat_execution_as_target(
                    state,
                    execution_id=first.id,
                    attempt_id=first.attempt_id,
                    actor="amir",
                    now=T0,
                    lease_seconds=10,
                    runtime_outcome="runtime_exited",
                )

                second = claim_execution(
                    state,
                    worker="two",
                    execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=25),
                    lease_seconds=10,
                )

                self.assertIsNotNone(second)
                self.assertEqual(second.runtime_outcome, "")

    def test_fractional_claim_preserves_full_lease_duration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                claimed_at = T0 + timedelta(microseconds=900_000)
                execution = claim_execution(
                    state, worker="fractional", execution_capable_targets={"amir"},
                    now=claimed_at, lease_seconds=1,
                )
                beat = heartbeat_execution(
                    state, execution_id=execution.id, attempt_id=execution.attempt_id,
                    worker="fractional", now=claimed_at + timedelta(milliseconds=101), lease_seconds=1,
                )
                self.assertEqual(execution.lease_expires_at, "2026-08-20T12:00:01.900000Z")
                self.assertEqual(beat.heartbeat_at, "2026-08-20T12:00:01.001000Z")

    def test_failure_finalization_honors_terminal_event_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self._acked(state)
                execution = claim_execution(
                    state, worker="racing", execution_capable_targets={"amir"}, now=T0,
                )
                with patch("arvyx_control.control._now", return_value="2026-08-20T12:00:01Z"):
                    terminal = complete_thread(state, subject, actor="amir", actor_identity_bound=True)
                finalized = record_execution_failure(
                    state, execution_id=execution.id, attempt_id=execution.attempt_id,
                    worker="racing", detail="provider timeout", now=T0 + timedelta(seconds=1),
                )
                events = read_events(state)
                self.assertEqual(finalized.status, "completed")
                self.assertEqual(finalized.terminal_event_id, terminal.event.id)
                self.assertFalse(any(event.type == "execution.attempt.failed" for event in events))
                self.assertEqual(events[-1].type, "execution.completed")

    def test_unbound_assignment_cannot_materialize_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with patch(
                    "arvyx_control.control._now",
                    side_effect=["2026-08-20T11:59:00Z", "2026-08-20T12:00:00Z"],
                ):
                    thread = post_thread(
                        state, title="forged ack", actor="esme", target="amir", thread_type="ask",
                    )
                    forged = acknowledge_thread(state, thread.thread.id, actor="amir")
                self.assertIs(forged.event.payload["actor_identity_bound"], False)
                self.assertEqual(
                    materialize_executions(
                        state, execution_capable_targets={"amir"}, now=T0,
                    ),
                    [],
                )

    def test_unbound_target_actor_cannot_complete_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self._acked(state)
                execution = claim_execution(
                    state, worker="authority", execution_capable_targets={"amir"}, now=T0,
                )
                with patch("arvyx_control.control._now", return_value="2026-08-20T12:00:01Z"):
                    forged = complete_thread(state, subject, actor="amir")
                self.assertIs(forged.event.payload["actor_identity_bound"], False)
                self.assertEqual(reconcile_executions(state, now=T0 + timedelta(seconds=1)), [])
                self.assertEqual(project_executions(state)[execution.id].status, "leased")

    def test_non_target_thread_terminal_cannot_complete_execution(self) -> None:
        for actor in ("operator", "esme", "kiran", "amır"):
            with self.subTest(actor=actor), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / "events.jsonl"
                vault = Path(tmp) / "vault"
                vault.mkdir(exist_ok=True)
                with authority_context(vault, state):
                    subject = self._acked(state)
                    execution = claim_execution(
                        state, worker="authority", execution_capable_targets={"amir"}, now=T0,
                    )
                    with patch("arvyx_control.control._now", return_value="2026-08-20T12:00:01Z"):
                        complete_thread(state, subject, actor=actor)
                    self.assertEqual(reconcile_executions(state, now=T0 + timedelta(seconds=1)), [])
                    self.assertEqual(project_executions(state)[execution.id].status, "leased")

    def test_handoff_source_terminal_cannot_complete_target_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with patch(
                    "arvyx_control.control._now",
                    side_effect=["2026-08-20T11:59:00Z", "2026-08-20T12:00:00Z"],
                ):
                    handoff = create_handoff(
                        state, "target-owned work", from_agent="esme", to_agent="amir",
                        actor_identity_bound=True,
                    )
                    accept_handoff(state, handoff.handoff.id, actor="amir", actor_identity_bound=True)
                execution = claim_execution(
                    state, worker="authority", execution_capable_targets={"amir"}, now=T0,
                )
                with patch("arvyx_control.control._now", return_value="2026-08-20T12:00:01Z"):
                    complete_handoff(state, handoff.handoff.id, actor="esme")
                self.assertEqual(reconcile_executions(state, now=T0 + timedelta(seconds=1)), [])
                self.assertEqual(project_executions(state)[execution.id].status, "leased")
                with patch("arvyx_control.control._now", return_value="2026-08-20T12:00:02Z"):
                    completed = complete_handoff(
                        state,
                        handoff.handoff.id,
                        actor="amir",
                        actor_identity_bound=True,
                    )
                self.assertIs(completed.event.payload["actor_identity_bound"], True)
                reconciled = reconcile_executions(state, now=T0 + timedelta(seconds=2))
                self.assertEqual([item.id for item in reconciled], [execution.id])
                self.assertEqual(project_executions(state)[execution.id].status, "completed")

    def test_non_target_terminal_racing_failure_requeues_instead_of_completing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self._acked(state)
                execution = claim_execution(
                    state, worker="racing", execution_capable_targets={"amir"}, now=T0,
                )
                with patch("arvyx_control.control._now", return_value="2026-08-20T12:00:01Z"):
                    complete_thread(state, subject, actor="operator")
                finalized = record_execution_failure(
                    state, execution_id=execution.id, attempt_id=execution.attempt_id,
                    worker="racing", detail="transport failed", now=T0 + timedelta(seconds=1),
                )
                self.assertEqual(finalized.status, "pending")
                self.assertEqual(read_events(state)[-1].type, "execution.attempt.failed")

    def test_authoritative_terminal_completes_dead_lettered_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self._acked(state)
                first = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"},
                    now=T0, lease_seconds=1, max_attempts=1,
                )
                self.assertIsNotNone(first)
                self.assertIsNone(claim_execution(
                    state, worker="two", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=16), lease_seconds=1, max_attempts=1,
                ))
                self.assertEqual(project_executions(state)[first.id].status, "dead_lettered")
                with patch("arvyx_control.control._now", return_value="2026-08-20T12:00:17Z"):
                    complete_thread(state, subject, actor="amir", actor_identity_bound=True)
                reconciled = reconcile_executions(state, now=T0 + timedelta(seconds=17))
                self.assertEqual([item.id for item in reconciled], [first.id])
                self.assertEqual(project_executions(state)[first.id].status, "completed")

    def test_replay_resets_budget_and_preserves_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                first = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"},
                    now=T0, lease_seconds=1, max_attempts=1,
                )
                claim_execution(
                    state, worker="one", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=16), lease_seconds=1, max_attempts=1,
                )
                self.assertEqual(project_executions(state)[first.id].status, "dead_lettered")
                replayed = replay_execution(state, execution_id=first.id, replayed_by="watchdog")
                self.assertEqual(replayed.id, first.id)
                self.assertEqual(replayed.status, "pending")
                self.assertEqual(replayed.attempts, 0)
                self.assertEqual(replayed.attempt_id, "")
                # The dead-letter evidence stays in the append-only log.
                self.assertTrue(any(event.type == "execution.dead_lettered" for event in read_events(state)))
                with self.assertRaisesRegex(ValueError, "not dead-lettered or held"):
                    replay_execution(state, execution_id=first.id)
                fresh = claim_execution(
                    state, worker="two", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=20), lease_seconds=10,
                )
                self.assertEqual(fresh.id, first.id)
                self.assertEqual(fresh.attempts, 1)

    def test_a_replayed_attempt_never_reuses_its_predecessors_identity(self) -> None:
        """Regression (2026-09-24): a replay resets the attempt number, and the attempt id
        was derived from it alone. The resumed attempt got the very first attempt's id, so
        its wake reused the old delivery id (the gateway dropped it as a duplicate) and a
        heartbeat from the superseded attempt would have fenced as current."""
        from arvyx_control.execution import execution_wake_item
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                first = claim_execution(state, worker="one", execution_capable_targets={"amir"},
                                        now=T0, lease_seconds=1, max_attempts=1)
                claim_execution(state, worker="one", execution_capable_targets={"amir"},
                                now=T0 + timedelta(seconds=16), lease_seconds=1, max_attempts=1)
                replay_execution(state, execution_id=first.id, replayed_by="watchdog")
                fresh = claim_execution(state, worker="two", execution_capable_targets={"amir"},
                                        now=T0 + timedelta(seconds=20), lease_seconds=60)
                self.assertEqual((fresh.id, fresh.attempts), (first.id, first.attempts))
                self.assertNotEqual(fresh.attempt_id, first.attempt_id)
                self.assertNotEqual(execution_wake_item(fresh).id, execution_wake_item(first).id)
                with self.assertRaises(ValueError):
                    heartbeat_execution(state, execution_id=fresh.id, attempt_id=first.attempt_id, worker="two",
                                        now=T0 + timedelta(seconds=21), lease_seconds=60)
                beat = heartbeat_execution(state, execution_id=fresh.id, attempt_id=fresh.attempt_id, worker="two",
                                           now=T0 + timedelta(seconds=21), lease_seconds=60)
                self.assertEqual(beat.attempt_id, fresh.attempt_id)

    def test_hold_is_idempotent_and_inert_to_claims_until_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"}, now=T0,
                )
                held = hold_execution(
                    state, execution_id=execution.id, reason="manual triage", held_by="operator",
                )
                self.assertEqual(held.status, "held")
                self.assertEqual(held.hold_reason, "manual triage")
                again = hold_execution(
                    state, execution_id=execution.id, reason="different reason", held_by="operator",
                )
                self.assertEqual(again.hold_reason, "manual triage")
                self.assertIsNone(claim_execution(
                    state, worker="two", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=600),
                ))
                replayed = replay_execution(state, execution_id=execution.id)
                self.assertEqual(replayed.status, "pending")
                self.assertEqual(replayed.hold_reason, "")

    def test_held_execution_closes_terminally_with_operator_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"}, now=T0,
                )
                hold_execution(
                    state, execution_id=execution.id, reason="superseded canary",
                    held_by="operator",
                )
                closed = close_execution(
                    state,
                    execution_id=execution.id,
                    resolution_category="superseded",
                    reason="superseded by a fresh canary after rollout",
                    closed_by="operator",
                )
                self.assertEqual(closed.status, "closed")
                self.assertEqual(closed.resolution_category, "superseded")
                self.assertEqual(closed.closed_by, "operator")
                # Append-only: the hold evidence stays in the log next to the close.
                self.assertTrue(
                    any(event.type == "execution.held" for event in read_events(state))
                )
                self.assertTrue(
                    any(event.type == "execution.closed" for event in read_events(state))
                )
                # Idempotent for the same category: a retried close never rewrites
                # the recorded resolution.
                again = close_execution(
                    state,
                    execution_id=execution.id,
                    resolution_category="superseded",
                    reason="second close attempt",
                    closed_by="operator",
                )
                self.assertEqual(again.resolution_category, "superseded")
                self.assertEqual(again.close_reason, "superseded by a fresh canary after rollout")
                # Terminal: no claim, no replay, and the queue no longer counts it.
                self.assertIsNone(claim_execution(
                    state, worker="two", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=3600),
                ))
                with self.assertRaisesRegex(ValueError, "not dead-lettered or held"):
                    replay_execution(state, execution_id=execution.id)
                health = queue_health(
                    state, execution_capable_targets={"amir"}, now=T0 + timedelta(seconds=3600),
                )
                self.assertEqual(health["held_count"], 0)
                self.assertEqual(health["assigned_without_live_execution_count"], 0)
                self.assertEqual(health["assigned_without_live_execution"], [])
                self.assertEqual(health["closed_count"], 1)

    def test_close_requires_a_known_resolution_and_refuses_unheld_executions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self._acked(state)
                execution = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"}, now=T0,
                )
                # A live execution must be held (or terminal) before it can be closed.
                with self.assertRaisesRegex(ValueError, "live execution cannot be closed"):
                    close_execution(
                        state,
                        execution_id=execution.id,
                        resolution_category="obsolete",
                        reason="too early",
                        closed_by="operator",
                    )
                held = hold_execution(
                    state, execution_id=execution.id, reason="triage", held_by="operator",
                )
                self.assertEqual(held.status, "held")
                with self.assertRaisesRegex(ValueError, "unknown resolution category"):
                    close_execution(
                        state,
                        execution_id=execution.id,
                        resolution_category="because-i-said-so",
                        reason="bad category",
                        closed_by="operator",
                    )
                with self.assertRaisesRegex(ValueError, "resolution category must not be empty"):
                    close_execution(
                        state,
                        execution_id=execution.id,
                        resolution_category="",
                        reason="",
                        closed_by="operator",
                    )
                with self.assertRaisesRegex(ValueError, "reason must not be empty"):
                    close_execution(
                        state,
                        execution_id=execution.id,
                        resolution_category="obsolete",
                        reason="   ",
                        closed_by="operator",
                    )
                with self.assertRaisesRegex(ValueError, "closed_by must not be empty"):
                    close_execution(
                        state,
                        execution_id=execution.id,
                        resolution_category="obsolete",
                        reason="no actor",
                        closed_by="",
                    )
                with self.assertRaisesRegex(ValueError, "unknown execution"):
                    close_execution(
                        state,
                        execution_id="execution_does_not_exist",
                        resolution_category="obsolete",
                        reason="missing",
                        closed_by="operator",
                    )
                # A completed execution is already terminal; closure must not
                # overwrite real completion evidence.
                with patch("arvyx_control.control._now", return_value="2026-08-20T12:00:01Z"):
                    complete_thread(state, subject, actor="amir", actor_identity_bound=True)
                reconcile_executions(state, now=T0 + timedelta(seconds=1))
                with self.assertRaisesRegex(ValueError, "completed execution cannot be closed"):
                    close_execution(
                        state,
                        execution_id=execution.id,
                        resolution_category="obsolete",
                        reason="too late",
                        closed_by="operator",
                    )

    def test_close_conflicting_category_is_refused_not_silently_kept(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"}, now=T0,
                )
                hold_execution(
                    state, execution_id=execution.id, reason="superseded canary",
                    held_by="operator",
                )
                close_execution(
                    state,
                    execution_id=execution.id,
                    resolution_category="superseded",
                    reason="superseded by a fresh canary after rollout",
                    closed_by="operator",
                )
                # A repeat that names a different category must fail closed: a
                # silent success would report a resolution the operator never
                # actually recorded.
                with self.assertRaisesRegex(ValueError, "already closed as superseded"):
                    close_execution(
                        state,
                        execution_id=execution.id,
                        resolution_category="obsolete",
                        reason="reclassification attempt",
                        closed_by="operator",
                    )
                projected = project_executions(state)[execution.id]
                self.assertEqual(projected.status, "closed")
                self.assertEqual(projected.resolution_category, "superseded")
                self.assertEqual(
                    len([event for event in read_events(state) if event.type == "execution.closed"]),
                    1,
                )

    def test_closed_execution_refuses_cancel_and_hold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"}, now=T0,
                )
                hold_execution(
                    state, execution_id=execution.id, reason="superseded canary",
                    held_by="operator",
                )
                close_execution(
                    state,
                    execution_id=execution.id,
                    resolution_category="superseded",
                    reason="superseded by a fresh canary",
                    closed_by="operator",
                )
                # Terminal means terminal: the other status writers must not be able
                # to reverse a closure and make the reported fields dishonest.
                with self.assertRaisesRegex(ValueError, "terminal execution cannot be cancelled"):
                    cancel_execution(
                        state, execution_id=execution.id, reason="changed my mind",
                        cancelled_by="operator",
                    )
                with self.assertRaisesRegex(ValueError, "closed execution cannot be held"):
                    hold_execution(
                        state, execution_id=execution.id, reason="changed my mind",
                        held_by="operator",
                    )
                projected = project_executions(state)[execution.id]
                self.assertEqual(projected.status, "closed")
                self.assertEqual(projected.resolution_category, "superseded")

    def test_dead_lettered_execution_closes_terminally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                first = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"},
                    now=T0, lease_seconds=1, max_attempts=1,
                )
                claim_execution(
                    state, worker="two", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=16), lease_seconds=1, max_attempts=1,
                )
                self.assertEqual(project_executions(state)[first.id].status, "dead_lettered")
                closed = close_execution(
                    state,
                    execution_id=first.id,
                    resolution_category="no_longer_actionable",
                    reason="subject retired; no further attempt is wanted",
                    closed_by="operator",
                )
                self.assertEqual(closed.status, "closed")
                self.assertEqual(closed.resolution_category, "no_longer_actionable")
                # The dead-letter evidence stays in the append-only log.
                self.assertTrue(
                    any(event.type == "execution.dead_lettered" for event in read_events(state))
                )
                health = queue_health(
                    state, execution_capable_targets={"amir"}, now=T0 + timedelta(seconds=20),
                )
                self.assertEqual(health["dead_lettered_count"], 0)
                self.assertEqual(health["closed_count"], 1)

    def test_closed_execution_still_reconciles_to_completed_on_a_real_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self._acked(state)
                execution = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"}, now=T0,
                )
                hold_execution(
                    state, execution_id=execution.id, reason="superseded canary",
                    held_by="operator",
                )
                close_execution(
                    state,
                    execution_id=execution.id,
                    resolution_category="terminal_elsewhere",
                    reason="reported complete through another route",
                    closed_by="operator",
                )
                with patch("arvyx_control.control._now", return_value="2026-08-20T12:00:01Z"):
                    complete_thread(state, subject, actor="amir", actor_identity_bound=True)
                reconciled = reconcile_executions(state, now=T0 + timedelta(seconds=1))
                self.assertEqual([item.id for item in reconciled], [execution.id])
                projected = project_executions(state)[execution.id]
                self.assertEqual(projected.status, "completed")
                self.assertEqual(projected.terminal_event_type, "thread.done")

    def test_paused_execution_accounts_for_its_own_status_not_live_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"}, now=T0,
                )
                cancel_execution(
                    state, execution_id=execution.id, reason="operator pause",
                    cancelled_by="operator",
                )
                self.assertEqual(project_executions(state)[execution.id].status, "paused")
                with self.assertRaisesRegex(ValueError, "paused execution cannot be closed"):
                    close_execution(
                        state,
                        execution_id=execution.id,
                        resolution_category="obsolete",
                        reason="too early",
                        closed_by="operator",
                    )

    def test_cli_close_reports_the_resolution_and_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"}, now=T0,
                )
                hold_execution(
                    state, execution_id=execution.id, reason="superseded canary",
                    held_by="operator",
                )
                output = io.StringIO()
                with redirect_stdout(output):
                    code = main([
                        "--authority-vault", str(vault), "execution", "close", "--state", str(state),
                        "--execution-id", execution.id,
                        "--resolution-category", "superseded",
                        "--reason", "superseded by a fresh post-rollout canary",
                        "--closed-by", "operator", "--json",
                    ])
                receipt = json.loads(output.getvalue())
                self.assertEqual(code, 0)
                self.assertEqual(receipt["status"], "closed")
                self.assertEqual(receipt["resolution_category"], "superseded")
                self.assertEqual(receipt["closed_by"], "operator")
                # A rejected close exits non-zero and explains itself on stderr.
                errors = io.StringIO()
                with redirect_stderr(errors):
                    bad = main([
                        "--authority-vault", str(vault), "execution", "close", "--state", str(state),
                        "--execution-id", execution.id,
                        "--resolution-category", "obsolete",
                        "--reason", "   ", "--json",
                    ])
                self.assertEqual(bad, 1)
                self.assertIn("reason must not be empty", errors.getvalue())
                # A conflicting repeat is visible on the CLI too: non-zero exit with
                # the recorded resolution named, and no success receipt.
                conflicting_output = io.StringIO()
                conflicting_errors = io.StringIO()
                with redirect_stdout(conflicting_output), redirect_stderr(conflicting_errors):
                    conflicting = main([
                        "--authority-vault", str(vault), "execution", "close", "--state", str(state),
                        "--execution-id", execution.id,
                        "--resolution-category", "obsolete",
                        "--reason", "reclassification attempt", "--json",
                    ])
                self.assertEqual(conflicting, 1)
                self.assertIn("already closed as superseded", conflicting_errors.getvalue())
                self.assertEqual(conflicting_output.getvalue(), "")
                projected = project_executions(state)[execution.id]
                self.assertEqual(projected.status, "closed")
                self.assertEqual(projected.resolution_category, "superseded")

    def test_completed_execution_cannot_be_held(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self._acked(state)
                execution = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"}, now=T0,
                )
                with patch("arvyx_control.control._now", return_value="2026-08-20T12:00:01Z"):
                    complete_thread(state, subject, actor="amir", actor_identity_bound=True)
                reconcile_executions(state, now=T0 + timedelta(seconds=1))
                with self.assertRaisesRegex(ValueError, "completed execution cannot be held"):
                    hold_execution(
                        state, execution_id=execution.id, reason="too late", held_by="operator",
                    )

    def test_queue_health_reports_held_and_stale_heartbeats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"},
                    now=T0, lease_seconds=900,
                )
                health = queue_health(
                    state, execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=400), heartbeat_stale_seconds=300,
                )
                self.assertEqual(health["leased_without_recent_heartbeat"], [execution.id])
                heartbeat_execution_as_target(
                    state, execution_id=execution.id, attempt_id=execution.attempt_id,
                    actor="amir", now=T0 + timedelta(seconds=401),
                )
                fresh = queue_health(
                    state, execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=500), heartbeat_stale_seconds=300,
                )
                self.assertEqual(fresh["leased_without_recent_heartbeat_count"], 0)
                hold_execution(
                    state, execution_id=execution.id, reason="triage", held_by="operator",
                )
                held_health = queue_health(
                    state, execution_capable_targets={"amir"}, now=T0 + timedelta(seconds=501),
                )
                self.assertEqual(held_health["held_count"], 1)

    def test_projection_isolates_leased_legacy_execution_without_attempt_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(
                    state, worker="legacy", execution_capable_targets={"amir"}, now=T0,
                )
                events = [json.loads(line) for line in state.read_text().splitlines()]
                for event in events:
                    if event["type"].startswith("execution."):
                        event["payload"].pop("attempt_id", None)
                state.write_text("".join(json.dumps(event) + "\n" for event in events))
                self.assertNotIn(execution.id, project_executions(state))

    def test_projection_isolates_malformed_legacy_execution_snapshots(self) -> None:
        malformed_cases = (
            ("attempts-none", {"attempts": None}),
            ("attempts-string", {"attempts": "two"}),
            ("created-at-invalid", {"created_at": "not-a-timestamp"}),
            ("updated-at-none", {"updated_at": None}),
            ("lease-expiry-invalid", {"lease_expires_at": "not-a-timestamp"}),
            ("lease-expiry-naive", {"lease_expires_at": "2026-08-20T12:01:00"}),
            ("lease-fields-empty", {"lease_owner": "", "lease_expires_at": ""}),
            ("lease-owner-none", {"lease_owner": None}),
            ("attempts-zero", {"attempts": 0}),
            ("attempt-id-empty", {"attempt_id": ""}),
        )
        for label, mutation in malformed_cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / "events.jsonl"
                vault = Path(tmp) / "vault"
                vault.mkdir(exist_ok=True)
                with authority_context(vault, state):
                    self._acked(state)
                    healthy = claim_execution(
                        state, worker="healthy", execution_capable_targets={"amir"}, now=T0,
                    )
                    assert healthy is not None
                    payload = healthy.to_dict()
                    payload["id"] = "execution_malformed"
                    payload.update(mutation)
                    _append_event(state, ControlEvent(
                        id=f"bad-{label}", type="execution.heartbeat",
                        task_id="execution_malformed", timestamp="2026-08-20T12:00:01Z",
                        payload=payload,
                    ))

                    projected = project_executions(state)

                    self.assertEqual(projected[healthy.id], healthy)
                    self.assertNotIn("execution_malformed", projected)
                    health = queue_health(
                        state, execution_capable_targets={"amir"}, now=T0,
                    )
                    self.assertEqual(health["live_execution_count"], 1)
                    self.assertEqual(
                        health["leased_without_recent_heartbeat"], [healthy.id],
                    )

    def test_expired_unreclaimed_attempt_can_record_failure_but_stale_attempt_cannot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                first = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"},
                    now=T0, lease_seconds=1,
                )
                failed = record_execution_failure(
                    state, execution_id=first.id, attempt_id=first.attempt_id,
                    worker="one", detail="cleanup exceeded lease", now=T0 + timedelta(seconds=2),
                )
                self.assertEqual(failed.status, "pending")
                # Failure at +2s with attempts=1 retries after the 15s backoff;
                # the second lease (1s) expires at +18s and reclaims after
                # backoff(2)=30s.
                second = claim_execution(
                    state, worker="one", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=17), lease_seconds=1,
                )
                third = claim_execution(
                    state, worker="two", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=48), lease_seconds=1,
                )
                self.assertNotEqual(second.attempt_id, third.attempt_id)
                with self.assertRaisesRegex(ValueError, "not leased|stale"):
                    record_execution_failure(
                        state, execution_id=second.id, attempt_id=second.attempt_id,
                        worker="one", detail="late stale cleanup", now=T0 + timedelta(seconds=48),
                    )

    def test_stale_attempt_cannot_heartbeat_reclaimed_lease(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                first = claim_execution(
                    state, worker="same-worker", execution_capable_targets={"amir"},
                    now=T0, lease_seconds=10,
                )
                second = claim_execution(
                    state, worker="same-worker", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=25), lease_seconds=10,
                )
                self.assertEqual(second.id, first.id)
                self.assertNotEqual(second.attempt_id, first.attempt_id)
                with self.assertRaisesRegex(ValueError, "attempt is stale"):
                    heartbeat_execution(
                        state, execution_id=first.id, attempt_id=first.attempt_id,
                        worker="same-worker", now=T0 + timedelta(seconds=25),
                    )
                current = project_executions(state)[first.id]
                self.assertEqual(current.attempt_id, second.attempt_id)
                self.assertEqual(current.attempts, 2)

    def test_target_heartbeat_sustains_lease_past_interval_until_target_done(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self._acked(state)
                execution = claim_execution(
                    state, worker="prod", execution_capable_targets={"amir"}, now=T0, lease_seconds=60,
                )
                # The bound target renews across two full lease intervals; the
                # worker never reclaims and no duplicate attempt starts.
                for offset in (50, 100, 150):
                    beat = heartbeat_execution_as_target(
                        state, execution_id=execution.id, attempt_id=execution.attempt_id,
                        actor="amir", now=T0 + timedelta(seconds=offset), lease_seconds=60,
                    )
                    self.assertEqual(beat.attempt_id, execution.attempt_id)
                idle = claim_execution(
                    state, worker="prod", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=170), lease_seconds=60,
                )
                self.assertIsNone(idle)
                current = project_executions(state)[execution.id]
                self.assertEqual(current.attempts, 1)
                self.assertEqual(current.heartbeat_at, "2026-08-20T12:02:30Z")
                with patch("arvyx_control.control._now", return_value="2026-08-20T12:03:00Z"):
                    complete_thread(state, subject, actor="amir", actor_identity_bound=True)
                reconcile_executions(state, now=T0 + timedelta(seconds=180))
                self.assertEqual(project_executions(state)[execution.id].status, "completed")

    def test_execution_wake_envelope_carries_continuation_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(
                    state, worker="bound", execution_capable_targets={"amir"}, now=T0,
                )
                route = AgentRoute("amir", "hermes-webhook", "URL", "SECRET")
                accepted = AgentDeliveryResult(True, "accepted", 202, "accepted")
                with patch("arvyx_control.execution.deliver_outbox_item", return_value=accepted) as deliver:
                    deliver_execution_attempt(
                        execution, route, now=T0,
                        environ={"URL": "https://runtime.invalid", "SECRET": "secret"},
                        lease_seconds=120,
                    )
                payload = deliver.call_args.args[0].payload
                self.assertEqual(payload["target"], "amir")
                self.assertEqual(payload["origin_event_type"], "thread.created")
                self.assertEqual(payload["lease_seconds"], 120)
                self.assertEqual(payload["execution_id"], execution.id)
                self.assertEqual(payload["attempt_id"], execution.attempt_id)

    def test_runtime_success_claim_cannot_terminally_complete_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self._acked(state)
                execution = claim_execution(state, worker="one", execution_capable_targets={"amir"}, now=T0)
                heartbeat_execution(state, execution_id=execution.id, attempt_id=execution.attempt_id, worker="one", now=T0, detail='{"status":"done"}')
                reconcile_executions(state, now=T0)
                self.assertEqual(project_executions(state)[execution.id].status, "leased")

                with patch("arvyx_control.control._now", return_value="2026-08-20T12:00:30Z"):
                    complete_thread(state, subject, actor="amir", actor_identity_bound=True)
                reconcile_executions(state, now=T0 + timedelta(seconds=30))
                completed = project_executions(state)[execution.id]
                self.assertEqual(completed.status, "completed")
                self.assertEqual(completed.terminal_event_type, "thread.done")

    def test_queue_health_does_not_treat_non_target_terminal_as_done(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self._acked(state)
                claim_execution(
                    state, worker="health", execution_capable_targets={"amir"},
                    now=T0, lease_seconds=1,
                )
                with patch("arvyx_control.control._now", return_value="2026-08-20T12:00:01Z"):
                    complete_thread(state, subject, actor="operator")
                health = queue_health(
                    state, execution_capable_targets={"amir"}, now=T0 + timedelta(seconds=2),
                )
                self.assertEqual(health["acked_without_live_execution"], [subject])

    def test_failure_is_recorded_and_requeued_without_changing_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(state, worker="one", execution_capable_targets={"amir"}, now=T0)
                failed = record_execution_failure(state, execution_id=execution.id, attempt_id=execution.attempt_id, worker="one", detail="provider exited 7", now=T0)
                backoff_blocked = claim_execution(state, worker="two", execution_capable_targets={"amir"}, now=T0)
                retry = claim_execution(state, worker="two", execution_capable_targets={"amir"}, now=T0 + timedelta(seconds=15))
                self.assertEqual(failed.last_failure, "provider exited 7")
                self.assertEqual(backoff_blocked, None)
                self.assertEqual(retry.id, execution.id)

    def test_queue_health_ignores_ineligible_ack_and_reports_eligible_handoff_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state, target="odin")
                with patch(
                    "arvyx_control.control._now",
                    side_effect=["2026-08-20T11:59:10Z", "2026-08-20T11:59:20Z"],
                ):
                    handoff = create_handoff(
                        state, "durable handoff", from_agent="esme", to_agent="amir",
                        actor_identity_bound=True,
                    )
                    accept_handoff(state, handoff.handoff.id, actor="amir", actor_identity_bound=True)
                health = queue_health(state, execution_capable_targets={"amir"}, now=T0)
                self.assertEqual(health["acked_without_live_execution_count"], 1)
                self.assertEqual(health["acked_without_live_execution"], [handoff.handoff.id])

    def _route_file(
        self, root: str, *, timeout_seconds: int = 1, target: str = "amir",
    ) -> Path:
        path = Path(root) / "routes.json"
        path.write_text(json.dumps({
            "routes": {
                target: {
                    "runtime": "hermes-webhook",
                    "url_env": "ARVYX_EXEC_URL",
                    "credential_env": "ARVYX_EXEC_SECRET",
                    "timeout_seconds": timeout_seconds,
                }
            }
        }), encoding="utf-8")
        return path

    def test_cli_worker_route_contract_and_crash_recovery_keep_execution_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                routes = self._route_file(tmp)
                self._acked(state)
                crashed = claim_execution(
                    state, worker="crashed", execution_capable_targets={"amir"},
                    now=T0, lease_seconds=1,
                )
                accepted = AgentDeliveryResult(True, "accepted", 202, "runtime accepted")
                output = io.StringIO()
                with patch.dict(
                    os.environ,
                    {"ARVYX_EXEC_URL": "https://runtime.invalid/hook", "ARVYX_EXEC_SECRET": "secret-material"},
                    clear=False,
                ), patch("arvyx_control.cli.deliver_execution_attempt", return_value=accepted) as deliver:
                    with redirect_stdout(output):
                        code = main(["--authority-vault", str(vault), *[
                            "execution", "worker", "--state", str(state), "--worker", "recovery",
                            "--routes", str(routes), "--now", "2026-08-20T12:00:16Z",
                            "--lease-seconds", "10", "--json",
                        ]])
                receipt = json.loads(output.getvalue())
                delivered_execution = deliver.call_args.args[0]
                self.assertEqual(code, 0)
                self.assertEqual(receipt["execution_id"], crashed.id)
                self.assertEqual(delivered_execution.id, crashed.id)
                self.assertEqual(receipt["attempt_id"], delivered_execution.attempt_id)
                self.assertEqual(project_executions(state)[crashed.id].status, "leased")

    def test_cli_worker_json_reports_loaded_route_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                routes = Path(tmp) / "routes.json"
                routes.write_text(json.dumps({
                    "schema": "v2.agent-delivery-routes/1",
                    "revision": "2026-08-29-r1",
                    "approved_at": "2026-08-29T12:00:00Z",
                    "owner": "elin",
                    "routes": {
                        "amir": {
                            "runtime": "hermes-webhook",
                            "url_env": "ARVYX_EXEC_URL",
                            "credential_env": "ARVYX_EXEC_SECRET",
                            "timeout_seconds": 1,
                        }
                    },
                }, sort_keys=True), encoding="utf-8")
                expected_sha = hashlib.sha256(routes.read_bytes()).hexdigest()
                self._acked(state)
                accepted = AgentDeliveryResult(True, "accepted", 202, "runtime accepted")
                environ = {"ARVYX_EXEC_URL": "https://runtime.invalid/hook", "ARVYX_EXEC_SECRET": "secret-material"}
                output = io.StringIO()
                with patch.dict(os.environ, environ, clear=False), patch(
                    "arvyx_control.cli.deliver_execution_attempt", return_value=accepted
                ):
                    with redirect_stdout(output):
                        code = main(["--authority-vault", str(vault), *[
                            "execution", "worker", "--state", str(state), "--worker", "attested",
                            "--routes", str(routes), "--now", "2026-08-20T12:00:02Z",
                            "--lease-seconds", "10", "--json",
                        ]])
                    idle_output = io.StringIO()
                    with redirect_stdout(idle_output):
                        idle_code = main(["--authority-vault", str(vault), *[
                            "execution", "worker", "--state", str(state), "--worker", "idle-check",
                            "--routes", str(routes), "--now", "2026-08-20T12:00:03Z",
                            "--lease-seconds", "10", "--json",
                        ]])
                receipt = json.loads(output.getvalue())
                idle = json.loads(idle_output.getvalue())
                self.assertEqual(code, 0)
                self.assertEqual(receipt["status"], "leased")
                self.assertEqual(receipt["route_revision"], "2026-08-29-r1")
                self.assertEqual(receipt["route_sha256"], expected_sha)
                self.assertEqual(idle_code, 0)
                self.assertEqual(idle["status"], "idle")
                self.assertEqual(idle["route_revision"], "2026-08-29-r1")
                self.assertEqual(idle["route_sha256"], expected_sha)
                self.assertNotIn("secret-material", output.getvalue())
                self.assertNotIn("secret-material", idle_output.getvalue())

    def test_execution_delivery_envelope_is_deterministic_and_non_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(
                    state, worker="bound", execution_capable_targets={"amir"}, now=T0,
                )
                route = AgentRoute("amir", "hermes-webhook", "URL", "SECRET")
                accepted = AgentDeliveryResult(True, "accepted", 202, "accepted")
                with patch("arvyx_control.execution.deliver_outbox_item", return_value=accepted) as deliver:
                    first = deliver_execution_attempt(execution, route, now=T0, environ={"URL": "https://runtime.invalid", "SECRET": "secret"})
                    second = deliver_execution_attempt(execution, route, now=T0, environ={"URL": "https://runtime.invalid", "SECRET": "secret"})
                first_item = deliver.call_args_list[0].args[0]
                second_item = deliver.call_args_list[1].args[0]
                self.assertTrue(first.accepted and second.accepted)
                self.assertEqual(first_item.id, second_item.id)
                self.assertEqual(first_item.payload["delivery_mode"], "execution")
                self.assertEqual(first_item.payload["execution_id"], execution.id)
                self.assertEqual(first_item.payload["attempt_id"], execution.attempt_id)
                self.assertNotIn("completed", first_item.payload)

    def test_cli_worker_delivery_rejection_requeues_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                routes = self._route_file(tmp)
                self._acked(state)
                rejected = AgentDeliveryResult(False, "transient", 503, "runtime unavailable")
                with patch.dict(
                    os.environ,
                    {"ARVYX_EXEC_URL": "https://runtime.invalid/hook", "ARVYX_EXEC_SECRET": "secret-material"},
                    clear=False,
                ), patch("arvyx_control.cli.deliver_execution_attempt", return_value=rejected):
                    code = main([
                        "--authority-vault", str(vault), "execution", "worker", "--state", str(state), "--worker", "bounded",
                        "--routes", str(routes), "--now", "2026-08-20T12:00:00Z",
                        "--lease-seconds", "10", "--json",
                    ])
                execution = next(iter(project_executions(state).values()))
                self.assertEqual(code, 1)
                self.assertEqual(execution.status, "pending")
                self.assertEqual(execution.lease_owner, "")
                self.assertIn("runtime unavailable", execution.last_failure)

    def test_cli_worker_noncanonical_route_key_fails_before_claim(self) -> None:
        for target in ("Amir", " amir", "amir "):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / "events.jsonl"
                vault = Path(tmp) / "vault"
                vault.mkdir(exist_ok=True)
                with authority_context(vault, state):
                    routes = self._route_file(tmp, target=target)
                    self._acked(state)
                    with patch.dict(
                        os.environ,
                        {"ARVYX_EXEC_URL": "https://runtime.invalid/hook", "ARVYX_EXEC_SECRET": "secret-material"},
                        clear=False,
                    ):
                        code = main(["--authority-vault", str(vault), *[
                            "execution", "worker", "--state", str(state), "--worker", "bounded",
                            "--routes", str(routes), "--lease-seconds", "10", "--json",
                        ]])
                    self.assertEqual(code, 2)
                    self.assertEqual(project_executions(state), {})

    def test_cli_worker_invalid_route_fails_before_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                routes = self._route_file(tmp)
                self._acked(state)
                with patch.dict(os.environ, {}, clear=True):
                    code = main([
                        "--authority-vault", str(vault), "execution", "worker", "--state", str(state), "--worker", "bounded",
                        "--routes", str(routes), "--lease-seconds", "10", "--json",
                    ])
                self.assertEqual(code, 2)
                self.assertTrue(all(item.status == "pending" for item in project_executions(state).values()))

    def test_cli_worker_rejects_unsafe_lease_budget_before_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                routes = self._route_file(tmp, timeout_seconds=10)
                self._acked(state)
                with patch.dict(
                    os.environ,
                    {"ARVYX_EXEC_URL": "https://runtime.invalid/hook", "ARVYX_EXEC_SECRET": "secret-material"},
                    clear=False,
                ):
                    code = main([
                        "--authority-vault", str(vault), "execution", "worker", "--state", str(state), "--worker", "bounded",
                        "--routes", str(routes), "--lease-seconds", "10", "--json",
                    ])
                self.assertEqual(code, 2)
                self.assertTrue(all(item.status == "pending" for item in project_executions(state).values()))


class BlockedRewakeTests(unittest.TestCase):
    """A target that reports BLOCKED gets a bounded re-wake, then HOLD.

    Regression for thread_7e1f30377bb1_47f5d9: an identity-bound target that
    cannot act (the subject asks for another identity's fenced execution) was
    re-woken after every lease expiry and wrote BLOCKED 12 times in 72 minutes.
    """

    LEASE = 60

    def _assigned(self, state: Path) -> str:
        thread = post_thread(
            state, title="inspect odin session return", actor="odin", target="amir",
            thread_type="blocker", actor_identity_bound=True,
        )
        return thread.thread.id

    def _claim(self, state: Path, at: datetime):
        return claim_execution(
            state, worker="worker", execution_capable_targets={"amir"}, now=at,
            lease_seconds=self.LEASE, max_attempts=8,
        )

    def _reply(self, state: Path, thread_id: str, text: str, actor: str = "amir") -> None:
        from arvyx_control.control import post_thread_message

        post_thread_message(state, thread_id, text, actor=actor)

    def test_repeated_blocked_report_without_new_input_holds_instead_of_rewaking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                thread_id = self._assigned(state)
                first = self._claim(state, T0)
                self._reply(state, thread_id, "BLOCKED: execution_x belongs to odin; I cannot inspect it.")
                # One bounded retry: the blocker might have been transient.
                second = self._claim(state, T0 + timedelta(seconds=self.LEASE + 20))
                self.assertIsNotNone(second)
                self.assertEqual(second.id, first.id)
                self.assertEqual(second.attempts, 2)
                self._reply(state, thread_id, "**Blocked** - still no authority over odin's attempt.")

                again = self._claim(state, T0 + timedelta(seconds=2 * self.LEASE + 60))
                self.assertIsNone(again)
                held = project_executions(state)[first.id]
                self.assertEqual(held.status, "held")
                self.assertEqual(held.held_by, "worker")
                self.assertTrue(held.hold_reason.startswith("target reported BLOCKED"), held.hold_reason)
                self.assertIn("2 consecutive attempts", held.hold_reason)
                self.assertIn("still no authority", held.hold_reason)
                # HOLD is inert: no later tick re-wakes it, and the queue says so.
                self.assertIsNone(self._claim(state, T0 + timedelta(hours=6)))
                self.assertEqual(project_executions(state)[first.id].attempts, 2)
                health = queue_health(
                    state, execution_capable_targets={"amir"}, now=T0 + timedelta(hours=6),
                )
                self.assertEqual(health["held_count"], 1)
                self.assertEqual(health["live_execution_count"], 0)
                # Append-only: the hold is one new event; no prior event was rewritten.
                held_events = [event for event in read_events(state) if event.type == "execution.held"]
                self.assertEqual(len(held_events), 1)

    def test_new_input_between_blocked_reports_resets_the_retry_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                thread_id = self._assigned(state)
                self._claim(state, T0)
                self._reply(state, thread_id, "BLOCKED: need the odin delivery id")
                self._reply(state, thread_id, "Here it is: outbox_123, try again.", actor="odin")
                second = self._claim(state, T0 + timedelta(seconds=self.LEASE + 20))
                self.assertEqual(second.attempts, 2)
                self._reply(state, thread_id, "BLOCKED: need the odin delivery id")
                # Only one BLOCKED since the last outside input: still a bounded retry.
                third = self._claim(state, T0 + timedelta(seconds=2 * self.LEASE + 60))
                self.assertIsNotNone(third)
                self.assertEqual(third.attempts, 3)

    def test_progress_after_blocked_and_foreign_blocked_text_do_not_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                thread_id = self._assigned(state)
                self._claim(state, T0)
                self._reply(state, thread_id, "BLOCKED: waiting on a credential")
                self._reply(state, thread_id, "Unblocked, the credential arrived; working.")
                self._claim(state, T0 + timedelta(seconds=self.LEASE + 20))
                # A non-target participant quoting BLOCKED is input, not a target report.
                self._reply(state, thread_id, "BLOCKED is not an answer, please retry", actor="odin")
                third = self._claim(state, T0 + timedelta(seconds=2 * self.LEASE + 60))
                self.assertIsNotNone(third)
                self.assertEqual(third.attempts, 3)

    def test_a_silent_attempt_between_blocked_reports_is_neutral(self) -> None:
        """Audit 2026-09-11: BLOCKED / no reply / BLOCKED used to reset the
        streak on the silent attempt, so the bound never triggered."""
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                thread_id = self._assigned(state)
                first = self._claim(state, T0)
                self._reply(state, thread_id, "BLOCKED: no authority over odin's attempt")
                second = self._claim(state, T0 + timedelta(seconds=80))
                self.assertEqual(second.attempts, 2)  # silent attempt: no reply at all
                third = self._claim(state, T0 + timedelta(seconds=200))
                self.assertEqual(third.attempts, 3)
                self._reply(state, thread_id, "BLOCKED: no authority over odin's attempt")
                self.assertIsNone(self._claim(state, T0 + timedelta(seconds=340)))
                self.assertEqual(project_executions(state)[first.id].status, "held")

    def test_blocked_report_recognition(self) -> None:
        from arvyx_control.execution import is_blocked_report

        reports = [
            "BLOCKED", "BLOCKED: need key", "blocked:", "**Blocked** by X", "- BLOCKED waiting",
            "# BLOCKED", "BLOCKED.", "BLOCKED \u2014 waiting", "\u200bBLOCKED: hidden prefix",
        ]
        not_reports = [
            '"BLOCKED" earlier, now done', "> BLOCKED? no", "'BLOCKED' is what I said",
            "BLOCKED_BY_X", "Unblocked", "Not blocked", "BLOCKED? no", "blockedness",
        ]
        for text in reports:
            self.assertTrue(is_blocked_report(text), text)
        for text in not_reports:
            self.assertFalse(is_blocked_report(text), text)

    def test_operator_replay_of_a_blocked_hold_grants_a_fresh_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                thread_id = self._assigned(state)
                first = self._claim(state, T0)
                self._reply(state, thread_id, "BLOCKED: no authority")
                self._claim(state, T0 + timedelta(seconds=self.LEASE + 20))
                self._reply(state, thread_id, "BLOCKED: no authority")
                self.assertIsNone(self._claim(state, T0 + timedelta(seconds=2 * self.LEASE + 60)))
                replay_execution(state, execution_id=first.id, replayed_by="operator")
                resumed = self._claim(state, T0 + timedelta(seconds=2 * self.LEASE + 61))
                self.assertIsNotNone(resumed)
                self.assertEqual(resumed.id, first.id)
                self.assertEqual(resumed.attempts, 1)


class ExecutionWakeDeliveryRecordTests(unittest.TestCase):
    """The delivery ID an execution wake names must resolve in the outbox
    projection, and the record must exist before the wake is sent."""

    ROUTE = AgentRoute("amir", "hermes-webhook", "URL", "SECRET")
    ENV = {"URL": "https://runtime.invalid", "SECRET": "secret"}

    def _leased(self, state: Path):
        post_thread(
            state, title="durable work", actor="esme", target="amir",
            thread_type="ask", actor_identity_bound=True,
        )
        return claim_execution(
            state, worker="bound", execution_capable_targets={"amir"}, now=T0, lease_seconds=60,
        )

    def test_wake_record_exists_before_network_io_and_resolves_after_acceptance(self) -> None:
        from arvyx_control.outbox import project_outbox

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                seen_before_send: list[str] = []

                def deliver(item, _route, **_kwargs):
                    persisted = project_outbox(state).get(item.id)
                    self.assertIsNotNone(persisted, "wake was sent before its delivery record existed")
                    seen_before_send.append(persisted.status)
                    self.assertEqual(persisted.payload, item.payload)
                    self.assertEqual((item.lease_owner, item.attempts),
                                     (persisted.lease_owner, persisted.attempts))
                    return AgentDeliveryResult(True, "accepted", 202, "accepted")

                with patch("arvyx_control.execution.deliver_outbox_item", side_effect=deliver) as sent:
                    result = deliver_execution_attempt(
                        execution, self.ROUTE, now=T0, environ=self.ENV, lease_seconds=60, state=state,
                    )
                    # A duplicate wake for the same attempt reuses the same record.
                    deliver_execution_attempt(
                        execution, self.ROUTE, now=T0, environ=self.ENV, lease_seconds=60, state=state,
                    )
                self.assertTrue(result.accepted)
                self.assertEqual(seen_before_send, ["leased", "delivered"])
                wake_id = sent.call_args_list[0].args[0].id
                record = project_outbox(state)[wake_id]
                self.assertEqual(record.status, "delivered")
                self.assertEqual(record.target, "amir")
                self.assertEqual(record.subject_id, execution.subject_id)
                self.assertEqual(record.payload["delivery_mode"], "execution")
                self.assertEqual(record.payload["execution_id"], execution.id)
                self.assertEqual(record.payload["attempt_id"], execution.attempt_id)
                self.assertEqual(
                    [item.id for item in project_outbox(state).values()
                     if item.payload.get("delivery_mode") == "execution"],
                    [wake_id],
                )

    def test_rejected_wake_is_classified_superseded_and_never_replayed_or_reclaimed(self) -> None:
        from arvyx_control.outbox import claim_due, project_outbox, replay

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)
                rejected = AgentDeliveryResult(False, "transient", 503, "runtime unavailable")
                with patch("arvyx_control.execution.deliver_outbox_item", return_value=rejected):
                    result = deliver_execution_attempt(
                        execution, self.ROUTE, now=T0, environ=self.ENV, lease_seconds=60, state=state,
                    )
                self.assertFalse(result.accepted)
                record = next(
                    item for item in project_outbox(state).values()
                    if item.payload.get("delivery_mode") == "execution"
                )
                self.assertEqual(record.status, "dead_lettered")
                self.assertEqual(record.resolution_category, "superseded")
                self.assertIn("runtime unavailable", record.failure_detail)
                with self.assertRaisesRegex(ValueError, "execution lineage"):
                    replay(state, outbox_id=record.id, now=T0)
                from arvyx_control.api import _dead_letter_summary

                summary = _dead_letter_summary(record, configured_targets={"amir"})
                self.assertFalse(summary["replayable"])
                self.assertIn("execution lineage", summary["replay_blocked_reason"])
                # The outbox dispatcher never claims execution-owned wake records.
                self.assertEqual(
                    claim_due(state, worker="dispatcher", now=T0 + timedelta(hours=1), targets={"amir"}, limit=10),
                    [],
                )

    def test_crashed_worker_wake_record_is_finalized_not_redelivered_by_dispatcher(self) -> None:
        from arvyx_control.outbox import claim_due, project_outbox

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._leased(state)

                def crash(*_args, **_kwargs):
                    raise KeyboardInterrupt  # worker dies between record and finalization

                with patch("arvyx_control.execution.deliver_outbox_item", side_effect=crash):
                    with self.assertRaises(KeyboardInterrupt):
                        deliver_execution_attempt(
                            execution, self.ROUTE, now=T0, environ=self.ENV, lease_seconds=60, state=state,
                        )
                record = next(
                    item for item in project_outbox(state).values()
                    if item.payload.get("delivery_mode") == "execution"
                )
                self.assertEqual(record.status, "leased")
                claimed = claim_due(
                    state, worker="dispatcher", now=T0 + timedelta(seconds=120), targets={"amir"}, limit=10,
                )
                self.assertEqual(claimed, [])
                finalized = project_outbox(state)[record.id]
                self.assertEqual(finalized.status, "dead_lettered")
                self.assertEqual(finalized.resolution_category, "superseded")

    def _crash_after_record(self, state: Path):
        from arvyx_control.outbox import project_outbox

        execution = self._leased(state)

        def crash(*_args, **_kwargs):
            raise KeyboardInterrupt  # worker dies between record and finalization

        with patch("arvyx_control.execution.deliver_outbox_item", side_effect=crash):
            with self.assertRaises(KeyboardInterrupt):
                deliver_execution_attempt(
                    execution, self.ROUTE, now=T0, environ=self.ENV, lease_seconds=60, state=state,
                )
        record = next(
            item for item in project_outbox(state).values()
            if item.payload.get("delivery_mode") == "execution"
        )
        return execution, record

    def test_orphan_wake_with_a_target_heartbeat_on_its_attempt_is_finalized_delivered(self) -> None:
        """Audit 2026-09-11: an unfinalized wake whose target is alive and
        heartbeating on the same fenced attempt was dead-lettered, so the
        target read its own delivery as dead through control.delivery_get."""
        from arvyx_control.outbox import claim_due, project_outbox

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution, record = self._crash_after_record(state)
                heartbeat_execution_as_target(
                    state, execution_id=execution.id, attempt_id=execution.attempt_id, actor="amir",
                    now=T0 + timedelta(seconds=30), lease_seconds=60,
                )
                self.assertEqual(
                    claim_due(state, worker="dispatcher", now=T0 + timedelta(seconds=45), targets={"amir"}, limit=10),
                    [],
                )
                settled = project_outbox(state)[record.id]
                self.assertEqual(settled.status, "delivered")
                self.assertEqual(settled.resolution_category, "")
                self.assertTrue(settled.delivered_at)
                # Settled once: later dispatcher passes never regress it.
                claim_due(state, worker="dispatcher", now=T0 + timedelta(hours=1), targets={"amir"}, limit=10)
                self.assertEqual(project_outbox(state)[record.id].status, "delivered")
                self.assertEqual(project_executions(state)[execution.id].status, "leased")

    def test_orphan_wake_is_left_alone_while_its_attempt_is_still_live(self) -> None:
        from arvyx_control.outbox import claim_due, project_outbox

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution, record = self._crash_after_record(state)
                # The attempt's lease outlives the record's (e.g. a first-heartbeat
                # window opened by the worker): the wake is not yet provably lost.
                heartbeat_execution(
                    state, execution_id=execution.id, attempt_id=execution.attempt_id, worker="bound",
                    now=T0 + timedelta(seconds=10), lease_seconds=60, first_heartbeat_seconds=300,
                )
                claim_due(state, worker="dispatcher", now=T0 + timedelta(seconds=120), targets={"amir"}, limit=10)
                self.assertEqual(project_outbox(state)[record.id].status, "leased")
                claim_due(state, worker="dispatcher", now=T0 + timedelta(seconds=400), targets={"amir"}, limit=10)
                settled = project_outbox(state)[record.id]
                self.assertEqual(settled.status, "dead_lettered")
                self.assertEqual(settled.resolution_category, "superseded")

    def test_foreign_or_worker_heartbeats_do_not_prove_wake_receipt(self) -> None:
        from arvyx_control.outbox import claim_due, project_outbox

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution, record = self._crash_after_record(state)
                # Only the worker heartbeats (no identity-bound target): no receipt.
                heartbeat_execution(
                    state, execution_id=execution.id, attempt_id=execution.attempt_id, worker="bound",
                    now=T0 + timedelta(seconds=10), lease_seconds=60,
                )
                claim_due(state, worker="dispatcher", now=T0 + timedelta(seconds=200), targets={"amir"}, limit=10)
                self.assertEqual(project_outbox(state)[record.id].status, "dead_lettered")

    def test_cli_worker_persists_the_wake_it_sends(self) -> None:
        from arvyx_control.outbox import project_outbox

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                routes = Path(tmp) / "routes.json"
                routes.write_text(json.dumps({"routes": {"amir": {
                    "runtime": "hermes-webhook", "url_env": "ARVYX_EXEC_URL",
                    "credential_env": "ARVYX_EXEC_SECRET", "timeout_seconds": 1,
                }}}), encoding="utf-8")
                post_thread(
                    state, title="durable work", actor="esme", target="amir",
                    thread_type="ask", actor_identity_bound=True,
                )
                accepted = AgentDeliveryResult(True, "accepted", 202, "accepted")
                output = io.StringIO()
                with patch.dict(
                    os.environ,
                    {"ARVYX_EXEC_URL": "https://runtime.invalid/hook", "ARVYX_EXEC_SECRET": "secret-material"},
                    clear=False,
                ), patch("arvyx_control.execution.deliver_outbox_item", return_value=accepted) as sent:
                    with redirect_stdout(output):
                        code = main(["--authority-vault", str(vault), *[
                            "execution", "worker", "--state", str(state), "--worker", "persisting",
                            "--routes", str(routes), "--now", "2026-08-20T12:00:00Z",
                            "--lease-seconds", "10", "--json",
                        ]])
                self.assertEqual(code, 0)
                wake_id = sent.call_args.args[0].id
                self.assertEqual(project_outbox(state)[wake_id].status, "delivered")
                self.assertNotIn("secret-material", output.getvalue())


class FirstHeartbeatWindowTests(unittest.TestCase):
    """B6: an accepted wake opens a first-heartbeat window, separate from the
    renewal lease.

    Production evidence: LLM runtimes need time to start, one healthy target
    took 71 s to its first heartbeat against a 120 s lease, and four items
    dead-lettered as "120s lease insufficient". The first identity-bound target
    heartbeat must arrive within ``first_heartbeat_seconds`` of the accepted
    wake; from then on each target heartbeat renews by ``lease_seconds``.
    """

    LEASE = 120
    WINDOW = 300

    def _assigned(self, state: Path) -> str:
        thread = post_thread(
            state, title="durable work", actor="esme", target="amir",
            thread_type="ask", actor_identity_bound=True,
        )
        return thread.thread.id

    def _claim(self, state: Path, at: datetime):
        return claim_execution(
            state, worker="prod", execution_capable_targets={"amir"}, now=at,
            lease_seconds=self.LEASE, max_attempts=8,
        )

    def _accept_wake(self, state: Path, execution, at: datetime, *, window: int | None = WINDOW):
        """The worker's post-delivery heartbeat, as `arvyx execution worker` writes it."""
        return heartbeat_execution(
            state, execution_id=execution.id, attempt_id=execution.attempt_id,
            worker="prod", now=at, lease_seconds=self.LEASE,
            first_heartbeat_seconds=window, detail='{"accepted": true}',
        )

    def _accepted(self, state: Path, at: datetime = T0):
        self._assigned(state)
        execution = self._claim(state, at)
        self._accept_wake(state, execution, at)
        return execution

    def _target_beat(self, state: Path, execution, offset: int, *, actor: str = "amir"):
        return heartbeat_execution_as_target(
            state, execution_id=execution.id, attempt_id=execution.attempt_id,
            actor=actor, now=T0 + timedelta(seconds=offset), lease_seconds=self.LEASE,
        )

    def _attempts_started(self, state: Path) -> int:
        return sum(event.type == "execution.attempt.started" for event in read_events(state))

    def test_accepted_wake_opens_the_window_and_records_it_in_the_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._accepted(state)
                projected = project_executions(state)[execution.id]
                self.assertEqual(projected.first_heartbeat_deadline, "2026-08-20T12:05:00Z")
                self.assertEqual(projected.lease_expires_at, "2026-08-20T12:05:00Z")
                self.assertEqual(projected.first_target_heartbeat_at, "")
                beat = [event for event in read_events(state) if event.type == "execution.heartbeat"][-1]
                # Projection is deterministic from the event alone, never from config.
                self.assertEqual(beat.payload["first_heartbeat_deadline"], "2026-08-20T12:05:00Z")
                self.assertEqual(beat.payload["first_heartbeat_seconds"], self.WINDOW)
                self.assertNotIn("actor_identity_bound", beat.payload)

    def test_first_target_heartbeat_inside_the_window_keeps_the_attempt_alive(self) -> None:
        for first_beat in (71, 200):
            with self.subTest(first_beat=first_beat), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / "events.jsonl"
                vault = Path(tmp) / "vault"
                vault.mkdir(exist_ok=True)
                with authority_context(vault, state):
                    execution = self._accepted(state)
                    # The old 120 s lease plus its 15 s backoff would have re-woken
                    # the target at +135 s; the window keeps the attempt live.
                    probes = [probe for probe in (121, 136) if probe < first_beat] + [first_beat - 1]
                    for probe in probes:
                        self.assertIsNone(self._claim(state, T0 + timedelta(seconds=probe)))
                    beat = self._target_beat(state, execution, first_beat)
                    self.assertEqual(beat.attempt_id, execution.attempt_id)
                    self.assertEqual(
                        beat.first_target_heartbeat_at,
                        _ts(T0 + timedelta(seconds=first_beat)),
                    )
                    # From the first target heartbeat on, the renewal lease applies.
                    self.assertEqual(
                        beat.lease_expires_at, _ts(T0 + timedelta(seconds=first_beat + self.LEASE)),
                    )
                    self.assertIsNone(
                        self._claim(state, T0 + timedelta(seconds=first_beat + self.LEASE - 1))
                    )
                    renewed = self._target_beat(state, execution, first_beat + 100)
                    self.assertEqual(renewed.first_target_heartbeat_at, beat.first_target_heartbeat_at)
                    self.assertIsNone(
                        self._claim(state, T0 + timedelta(seconds=first_beat + 100 + self.LEASE - 1))
                    )
                    current = project_executions(state)[execution.id]
                    self.assertEqual(current.status, "leased")
                    self.assertEqual(current.attempts, 1)
                    self.assertEqual(self._attempts_started(state), 1)

    def test_no_target_heartbeat_expires_at_the_window_with_a_distinct_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._accepted(state)
                for probe in (120, 136, 299):
                    self.assertIsNone(self._claim(state, T0 + timedelta(seconds=probe)))
                self.assertEqual(self._attempts_started(state), 1)
                # Expired at +300 s; the 15 s re-wake backoff runs from that expiry.
                self.assertIsNone(self._claim(state, T0 + timedelta(seconds=314)))
                retry = self._claim(state, T0 + timedelta(seconds=315))
                self.assertIsNotNone(retry)
                self.assertEqual(retry.id, execution.id)
                self.assertEqual(retry.attempts, 2)
                self.assertEqual(
                    retry.last_failure,
                    "no target heartbeat within first-heartbeat window (300s) after accepted wake",
                )
                # The new attempt starts clean: its own window opens on its own wake.
                self.assertEqual(retry.first_heartbeat_deadline, "")
                self.assertEqual(retry.first_target_heartbeat_at, "")

    def test_lapse_after_the_first_target_heartbeat_expires_with_the_renewal_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._accepted(state)
                self._target_beat(state, execution, 71)
                # Renewal lease: 71 + 120 = 191 s, not the 300 s window.
                self.assertIsNone(self._claim(state, T0 + timedelta(seconds=190)))
                self.assertIsNone(self._claim(state, T0 + timedelta(seconds=205)))
                retry = self._claim(state, T0 + timedelta(seconds=206))
                self.assertIsNotNone(retry)
                self.assertEqual(retry.attempts, 2)
                self.assertTrue(
                    retry.last_failure.startswith("target heartbeat lapsed"), retry.last_failure,
                )
                self.assertIn("120s", retry.last_failure)
                self.assertNotIn("first-heartbeat window", retry.last_failure)

    def test_dead_letter_keeps_the_distinct_window_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._assigned(state)
                execution = claim_execution(
                    state, worker="prod", execution_capable_targets={"amir"}, now=T0,
                    lease_seconds=self.LEASE, max_attempts=1,
                )
                self._accept_wake(state, execution, T0)
                dead = claim_execution(
                    state, worker="prod", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=315), lease_seconds=self.LEASE, max_attempts=1,
                )
                self.assertIsNone(dead)
                projected = project_executions(state)[execution.id]
                self.assertEqual(projected.status, "dead_lettered")
                self.assertTrue(projected.last_failure.startswith(
                    "no target heartbeat within first-heartbeat window (300s)"
                ))

    def test_only_an_identity_bound_target_heartbeat_counts_as_the_first_heartbeat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._accepted(state)
                with self.assertRaisesRegex(ValueError, "identity-bound target"):
                    self._target_beat(state, execution, 50, actor="odin")
                with self.assertRaisesRegex(ValueError, "not identity-bound"):
                    heartbeat_execution(
                        state, execution_id=execution.id, attempt_id=execution.attempt_id,
                        worker="prod", now=T0 + timedelta(seconds=60), heartbeat_by="amir",
                    )
                # A plain worker heartbeat is not a target heartbeat: it records
                # none, and it can neither end, erase nor slide the established
                # window within this exact attempt (fix-reviews #43: a retried
                # first heartbeat must not reset the window).
                worker_beat = heartbeat_execution(
                    state, execution_id=execution.id, attempt_id=execution.attempt_id,
                    worker="prod", now=T0 + timedelta(seconds=60), lease_seconds=self.LEASE,
                )
                self.assertEqual(worker_beat.first_target_heartbeat_at, "")
                self.assertEqual(worker_beat.first_heartbeat_deadline, "2026-08-20T12:05:00Z")
                self.assertEqual(worker_beat.lease_expires_at, "2026-08-20T12:05:00Z")
                # The target cannot open (or reopen) a window for itself.
                with self.assertRaisesRegex(ValueError, "first-heartbeat window"):
                    heartbeat_execution(
                        state, execution_id=execution.id, attempt_id=execution.attempt_id,
                        worker="prod", now=T0 + timedelta(seconds=61), lease_seconds=self.LEASE,
                        heartbeat_by="amir", actor_identity_bound=True, first_heartbeat_seconds=600,
                    )
                self.assertEqual(
                    project_executions(state)[execution.id].lease_expires_at, "2026-08-20T12:05:00Z",
                )
                # The window still ends only on the identity-bound target heartbeat.
                beat = self._target_beat(state, execution, 62)
                self.assertEqual(beat.first_target_heartbeat_at, "2026-08-20T12:01:02Z")
                self.assertEqual(beat.lease_expires_at, "2026-08-20T12:03:02Z")

    def test_worker_window_heartbeat_never_reopens_a_window_after_a_target_heartbeat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._assigned(state)
                execution = self._claim(state, T0)
                # A fast target heartbeats before the worker records the accepted wake.
                self._target_beat(state, execution, 1)
                late = self._accept_wake(state, execution, T0 + timedelta(seconds=2))
                self.assertEqual(late.first_heartbeat_deadline, "")
                self.assertEqual(late.first_target_heartbeat_at, "2026-08-20T12:00:01Z")
                self.assertEqual(late.lease_expires_at, "2026-08-20T12:02:02Z")

    def test_duplicate_accepted_wake_cannot_extend_first_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'events.jsonl'
            vault = Path(tmp) / 'vault'
            vault.mkdir()
            with authority_context(vault, state):
                self._assigned(state)
                execution = self._claim(state, T0)
                first = self._accept_wake(state, execution, T0)
                repeated = self._accept_wake(state, execution, T0 + timedelta(seconds=30))
                self.assertEqual(repeated.first_heartbeat_deadline, first.first_heartbeat_deadline)
                self.assertEqual(repeated.lease_expires_at, first.lease_expires_at)

    def test_first_heartbeat_window_must_cover_the_renewal_lease(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._assigned(state)
                execution = self._claim(state, T0)
                before = len(read_events(state))
                for window, message in ((119, "at least lease_seconds"), (3601, "at most 3600")):
                    with self.subTest(window=window), self.assertRaisesRegex(ValueError, message):
                        self._accept_wake(state, execution, T0, window=window)
                self.assertEqual(len(read_events(state)), before)
                # Equal to the lease is allowed: the window is then today's lease.
                same = self._accept_wake(state, execution, T0, window=self.LEASE)
                self.assertEqual(same.first_heartbeat_deadline, "2026-08-20T12:02:00Z")

    def test_queue_health_does_not_flag_an_attempt_inside_its_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution = self._accepted(state)
                inside = queue_health(
                    state, execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=299), heartbeat_stale_seconds=120,
                )
                self.assertEqual(inside["leased_without_recent_heartbeat_count"], 0)
                self.assertEqual(inside["live_execution_count"], 1)
                closed = queue_health(
                    state, execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=300), heartbeat_stale_seconds=120,
                )
                self.assertEqual(closed["leased_without_recent_heartbeat"], [execution.id])
                # After the first target heartbeat the ordinary staleness rule applies.
                self._target_beat(state, execution, 100)
                renewal = queue_health(
                    state, execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=220), heartbeat_stale_seconds=120,
                )
                self.assertEqual(renewal["leased_without_recent_heartbeat"], [execution.id])

    def test_old_event_log_without_window_fields_projects_and_expires_as_before(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._assigned(state)
                execution = self._claim(state, T0)
                # Pre-B6 worker: the post-delivery heartbeat renews by lease_seconds.
                self._accept_wake(state, execution, T0, window=None)
                self._target_beat(state, execution, 60)
                events = [json.loads(line) for line in state.read_text().splitlines()]
                new_fields = {"first_heartbeat_deadline", "first_target_heartbeat_at", "first_heartbeat_seconds"}
                for event in events:
                    if event["type"].startswith("execution."):
                        for field in new_fields:
                            event["payload"].pop(field, None)
                state.write_text("".join(json.dumps(event) + "\n" for event in events))

                legacy = project_executions(state)[execution.id]
                self.assertEqual(legacy.status, "leased")
                self.assertEqual(legacy.lease_expires_at, "2026-08-20T12:03:00Z")
                self.assertEqual(legacy.heartbeat_at, "2026-08-20T12:01:00Z")
                self.assertEqual(legacy.first_heartbeat_deadline, "")
                self.assertEqual(legacy.first_target_heartbeat_at, "")
                health = queue_health(
                    state, execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=179), heartbeat_stale_seconds=100,
                )
                self.assertEqual(health["leased_without_recent_heartbeat"], [execution.id])
                self.assertIsNone(self._claim(state, T0 + timedelta(seconds=194)))
                retry = self._claim(state, T0 + timedelta(seconds=195))
                self.assertEqual(retry.attempts, 2)
                self.assertEqual(retry.last_failure, "lease expired before heartbeat or finalization")

    def test_repeated_blocked_reports_still_hold_under_the_window(self) -> None:
        from arvyx_control.control import post_thread_message

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                thread_id = self._assigned(state)
                first = self._claim(state, T0)
                self._accept_wake(state, first, T0)
                self._target_beat(state, first, 70)
                post_thread_message(state, thread_id, "BLOCKED: no authority over odin's attempt", actor="amir")
                # Renewal lapse at 190 s plus 15 s backoff: one bounded re-wake.
                second = self._claim(state, T0 + timedelta(seconds=205))
                self.assertEqual(second.attempts, 2)
                self._accept_wake(state, second, T0 + timedelta(seconds=205))
                post_thread_message(state, thread_id, "BLOCKED: still no authority", actor="amir")
                # No target heartbeat this time: the window (not the lease) closes
                # the attempt, and the second BLOCKED then parks it in HOLD.
                self.assertIsNone(self._claim(state, T0 + timedelta(seconds=205 + 299)))
                self.assertEqual(project_executions(state)[first.id].status, "leased")
                self.assertIsNone(self._claim(state, T0 + timedelta(seconds=205 + 300)))
                held = project_executions(state)[first.id]
                self.assertEqual(held.status, "held")
                self.assertTrue(held.hold_reason.startswith("target reported BLOCKED"), held.hold_reason)
                self.assertIn("2 consecutive attempts", held.hold_reason)
                self.assertEqual(held.attempts, 2)

    def test_cli_worker_opens_the_default_window_and_rejects_a_short_one(self) -> None:
        cases = (
            ([], 300, 0),
            (["--first-heartbeat-seconds", "600"], 600, 0),
            (["--first-heartbeat-seconds", "119"], None, 2),
        )
        for extra, window, expected_code in cases:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / "events.jsonl"
                vault = Path(tmp) / "vault"
                vault.mkdir(exist_ok=True)
                with authority_context(vault, state):
                    routes = Path(tmp) / "routes.json"
                    routes.write_text(json.dumps({"routes": {"amir": {
                        "runtime": "hermes-webhook", "url_env": "ARVYX_EXEC_URL",
                        "credential_env": "ARVYX_EXEC_SECRET", "timeout_seconds": 1,
                    }}}), encoding="utf-8")
                    self._assigned(state)
                    accepted = AgentDeliveryResult(True, "accepted", 202, "accepted")
                    stderr = io.StringIO()
                    with patch.dict(
                        os.environ,
                        {"ARVYX_EXEC_URL": "https://runtime.invalid/hook", "ARVYX_EXEC_SECRET": "secret-material"},
                        clear=False,
                    ), patch("arvyx_control.execution.deliver_outbox_item", return_value=accepted) as sent:
                        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                            code = main(["--authority-vault", str(vault), *[
                                "execution", "worker", "--state", str(state), "--worker", "prod",
                                "--routes", str(routes), "--now", "2026-08-20T12:00:00Z",
                                "--lease-seconds", "120", "--max-attempts", "8", *extra, "--json",
                            ]])
                    self.assertEqual(code, expected_code, stderr.getvalue())
                    if window is None:
                        self.assertIn("first_heartbeat_seconds must be at least lease_seconds", stderr.getvalue())
                        self.assertFalse(sent.called)
                        self.assertTrue(all(
                            item.status == "pending" for item in project_executions(state).values()
                        ))
                        continue
                    execution = next(iter(project_executions(state).values()))
                    self.assertEqual(
                        execution.first_heartbeat_deadline, _ts(T0 + timedelta(seconds=window)),
                    )
                    self.assertEqual(execution.lease_expires_at, execution.first_heartbeat_deadline)
                    payload = sent.call_args.args[0].payload
                    self.assertEqual(payload["lease_seconds"], 120)
                    self.assertEqual(payload["first_heartbeat_seconds"], window)

    def test_cli_worker_default_window_never_undercuts_a_longer_lease(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                routes = Path(tmp) / "routes.json"
                routes.write_text(json.dumps({"routes": {"amir": {
                    "runtime": "hermes-webhook", "url_env": "ARVYX_EXEC_URL",
                    "credential_env": "ARVYX_EXEC_SECRET", "timeout_seconds": 1,
                }}}), encoding="utf-8")
                self._assigned(state)
                accepted = AgentDeliveryResult(True, "accepted", 202, "accepted")
                with patch.dict(
                    os.environ,
                    {"ARVYX_EXEC_URL": "https://runtime.invalid/hook", "ARVYX_EXEC_SECRET": "secret-material"},
                    clear=False,
                ), patch("arvyx_control.execution.deliver_outbox_item", return_value=accepted):
                    with redirect_stdout(io.StringIO()):
                        code = main(["--authority-vault", str(vault), *[
                            "execution", "worker", "--state", str(state), "--worker", "prod",
                            "--routes", str(routes), "--now", "2026-08-20T12:00:00Z",
                            "--lease-seconds", "400", "--json",
                        ]])
                self.assertEqual(code, 0)
                execution = next(iter(project_executions(state).values()))
                self.assertEqual(execution.first_heartbeat_deadline, "2026-08-20T12:06:40Z")


def _ts(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    unittest.main()
