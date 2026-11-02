from __future__ import annotations

from datetime import datetime, timedelta, timezone
from contextlib import closing, redirect_stdout
import hashlib
import io
import json
import multiprocessing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.replica_authority import authority_context
from arvyx_control.cli import main
from arvyx_control.control import (
    _append_event_unlocked,
    _event,
    accept_handoff,
    acknowledge_thread,
    complete_handoff,
    complete_thread,
    create_handoff,
    create_task,
    post_thread,
    read_events,
    recover_torn_final_event,
    review_handoff,
)
from arvyx_control.outbox import (
    MATERIALIZATION_CHECKPOINT_EVENT,
    cancel_unroutable,
    claim_due,
    enqueue,
    last_dispatcher_tick_timestamp,
    last_dispatcher_tick_record,
    mark_delivered,
    mark_delivery_ambiguous,
    project_outbox,
    record_dispatcher_tick,
    record_failure,
    record_receipt,
    reconcile_ambiguous_delivery,
    replay,
    should_record_dispatcher_tick,
)
from arvyx_control.store import SCHEMA, sync_sqlite


UTC = timezone.utc
T0 = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)


def _race_claim(vault: str, state: str, worker: str, barrier, results) -> None:
    # Spawned processes do not inherit ContextVars; bind the parent's explicit
    # fixture domain independently for the entire claim/lock lifecycle.
    with authority_context(Path(vault), Path(state)):
        barrier.wait(timeout=10)
        claimed = claim_due(Path(state), worker=worker, now=T0, lease_seconds=30)
        results.put([item.id for item in claimed])


class OutboxTests(unittest.TestCase):
    def test_enqueue_is_idempotent_for_thread_target_payload_hash_and_epoch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                payload = {"subject_id": "thread_1", "kind": "handoff"}

                first = enqueue(state, subject_id="thread_1", target="amir", payload=payload, now=T0)
                duplicate = enqueue(state, subject_id="thread_1", target="amir", payload=payload, now=T0)

                self.assertEqual(first.id, duplicate.id)
                self.assertEqual(first.payload_hash, hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
                self.assertEqual(first.epoch, 0)
                self.assertEqual([event.type for event in read_events(state)], ["outbox.enqueued"])
                self.assertEqual(list(project_outbox(state)), [first.id])

    def test_claim_due_leases_once_and_reclaims_after_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="thread_1", target="amir", payload={"kind": "ask"}, now=T0)

                claimed = claim_due(state, worker="worker-a", now=T0, lease_seconds=30)
                blocked = claim_due(state, worker="worker-b", now=T0 + timedelta(seconds=29), lease_seconds=30)
                reclaimed = claim_due(state, worker="worker-b", now=T0 + timedelta(seconds=30), lease_seconds=30)

                self.assertEqual([entry.id for entry in claimed], [item.id])
                self.assertEqual(blocked, [])
                self.assertEqual([entry.id for entry in reclaimed], [item.id])
                self.assertEqual(reclaimed[0].attempts, 2)
                self.assertEqual(reclaimed[0].lease_owner, "worker-b")
                self.assertEqual(
                    [event.type for event in read_events(state)],
                    ["outbox.enqueued", "outbox.attempt.started", "outbox.attempt.started"],
                )

    def test_claim_due_is_atomic_across_processes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="thread_1", target="amir", payload={"kind": "ask"}, now=T0)
                context = multiprocessing.get_context("spawn")
                barrier = context.Barrier(2)
                results = context.Queue()
                processes = [
                    context.Process(target=_race_claim, args=(str(vault), str(state), worker, barrier, results))
                    for worker in ("worker-a", "worker-b")
                ]
                started = []
                try:
                    for process in processes:
                        process.start()
                        started.append(process)
                    claims = [results.get(timeout=10) for _ in processes]
                    for process in processes:
                        process.join(timeout=10)
                        self.assertEqual(process.exitcode, 0)
                finally:
                    # Reap workers before deleting their owned vault/state, even
                    # when startup, the queue timeout, or an assertion fails.
                    for process in started:
                        if process.is_alive():
                            process.terminate()
                        process.join(timeout=10)
                        if process.is_alive():
                            process.kill()
                            process.join(timeout=10)
                        process.close()
                    results.close()
                    results.join_thread()

                self.assertEqual(sum(len(result) for result in claims), 1)
                self.assertEqual([claimed_id for result in claims for claimed_id in result], [item.id])
                attempts = [event for event in read_events(state) if event.type == "outbox.attempt.started"]
                self.assertEqual(len(attempts), 1)
                self.assertEqual(attempts[0].task_id, item.id)

    def test_transient_failure_uses_bounded_exponential_backoff_and_redacts_detail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="thread_1", target="amir", payload={"kind": "ask"}, now=T0)
                leased = claim_due(state, worker="worker-a", now=T0)[0]

                failed = record_failure(
                    state,
                    outbox_id=item.id,
                    worker="worker-a", claim_attempts=leased.attempts,
                    detail="upstream " + "Bearer " + ("a" * 26) + " failed",
                    transient=True,
                    now=T0,
                    base_backoff_seconds=10,
                    max_backoff_seconds=15,
                    jitter=lambda upper: upper,
                )

                self.assertEqual(failed.status, "pending")
                self.assertEqual(failed.attempts, leased.attempts)
                self.assertEqual(failed.next_attempt_at, "2026-08-10T12:00:11Z")
                self.assertEqual(failed.failure_detail, "upstream [REDACTED-SECRET] failed")
                self.assertEqual(claim_due(state, worker="worker-b", now=T0 + timedelta(seconds=10)), [])
                self.assertEqual(len(claim_due(state, worker="worker-b", now=T0 + timedelta(seconds=11))), 1)

    def test_permanent_failure_dead_letters_without_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="thread_1", target="amir", payload={"kind": "ask"}, now=T0)
                delivery_claims = claim_due(state, worker="worker-a", now=T0)

                failed = record_failure(
                    state,
                    outbox_id=item.id,
                    worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id),
                    detail="invalid payload",
                    transient=False,
                    now=T0,
                )

                self.assertEqual(failed.status, "dead_lettered")
                self.assertEqual(claim_due(state, worker="worker-b", now=T0 + timedelta(days=1)), [])
                self.assertEqual(read_events(state)[-1].type, "outbox.dead_lettered")

    def test_delivered_is_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="thread_1", target="amir", payload={"kind": "ask"}, now=T0)
                delivery_claims = claim_due(state, worker="worker-a", now=T0)

                delivered = mark_delivered(state, outbox_id=item.id, worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), now=T0)

                self.assertEqual(delivered.status, "delivered")
                self.assertEqual(delivered.delivered_at, "2026-08-10T12:00:00Z")
                self.assertEqual(claim_due(state, worker="worker-b", now=T0 + timedelta(days=1)), [])
                with self.assertRaisesRegex(ValueError, "not leased"):
                    record_failure(state, outbox_id=item.id, worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), detail="late", transient=True, now=T0)

    def test_ambiguous_delivery_is_terminal_and_never_auto_retries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(
                    state,
                    subject_id="session_return_1",
                    target="odin",
                    payload={"delivery_mode": "session_return"},
                    now=T0,
                )
                delivery_claims = claim_due(state, worker="worker-a", now=T0)

                ambiguous = mark_delivery_ambiguous(
                    state,
                    outbox_id=item.id,
                    worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id),
                    detail="provider may have accepted but no receipt was returned",
                    now=T0,
                )

                self.assertEqual(ambiguous.status, "ambiguous_delivery")
                self.assertEqual(ambiguous.ambiguous_at, "2026-08-10T12:00:00Z")
                self.assertIn("no receipt", ambiguous.ambiguity_detail)
                self.assertEqual(
                    claim_due(state, worker="worker-b", now=T0 + timedelta(days=1)),
                    [],
                )
                self.assertEqual(read_events(state)[-1].type, "outbox.dead_lettered")
                self.assertEqual(read_events(state)[-1].payload["status"], "ambiguous_delivery")

    def test_ambiguous_delivery_requires_explicit_receipt_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(
                    state,
                    subject_id="session_return_1",
                    target="odin",
                    payload={"delivery_mode": "session_return"},
                    now=T0,
                )
                delivery_claims = claim_due(state, worker="worker-a", now=T0)
                mark_delivery_ambiguous(
                    state,
                    outbox_id=item.id,
                    worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id),
                    detail="provider response was lost",
                    now=T0,
                )

                reconciled = reconcile_ambiguous_delivery(
                    state,
                    outbox_id=item.id,
                    resolved_by="operator",
                    outcome="delivered",
                    provider_receipt="telegram-message-42",
                    detail="read back from provider",
                    now=T0 + timedelta(seconds=1),
                )
                duplicate = reconcile_ambiguous_delivery(
                    state,
                    outbox_id=item.id,
                    resolved_by="operator",
                    outcome="delivered",
                    provider_receipt="telegram-message-42",
                    detail="read back from provider",
                    now=T0 + timedelta(seconds=2),
                )

                self.assertEqual(reconciled.status, "delivered")
                self.assertEqual(reconciled.provider_receipt, "telegram-message-42")
                self.assertEqual(reconciled.resolution_category, "ambiguous_delivered")
                self.assertEqual(duplicate, reconciled)
                self.assertEqual(
                    len([
                        e for e in read_events(state)
                        if e.task_id == item.id
                        and e.payload.get("resolution_category") == "ambiguous_delivered"
                    ]),
                    1,
                )

    def test_reconciliation_cannot_erase_or_replace_retained_provider_receipt(self) -> None:
        for outcome, receipt in (("not_delivered", ""), ("delivered", "telegram-message-other")):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / "events.jsonl"
                vault = Path(tmp) / "vault"
                vault.mkdir(exist_ok=True)
                with authority_context(vault, state):
                    item = enqueue(state, subject_id="session_return_1", target="odin",
                                   payload={"delivery_mode": "session_return"}, now=T0)
                    delivery_claims = claim_due(state, worker="worker-a", now=T0)
                    accepted = mark_delivered(state, outbox_id=item.id, worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id),
                                              provider_receipt="telegram-message-42", now=T0)
                    self.assertEqual(accepted.status, "ambiguous_delivery")
                    before = state.read_bytes()
                    with self.assertRaisesRegex(ValueError, "retained provider receipt"):
                        reconcile_ambiguous_delivery(
                            state, outbox_id=item.id, resolved_by="operator", outcome=outcome,
                            provider_receipt=receipt, now=T0 + timedelta(seconds=1),
                        )
                    self.assertEqual(state.read_bytes(), before)
                    self.assertEqual(project_outbox(state)[item.id].provider_receipt, "telegram-message-42")
                    resolved = reconcile_ambiguous_delivery(
                        state, outbox_id=item.id, resolved_by="operator", outcome="delivered",
                        provider_receipt="telegram-message-42", now=T0 + timedelta(seconds=2),
                    )
                    self.assertEqual(resolved.status, "delivered")
                    self.assertEqual(resolved.provider_receipt, "telegram-message-42")

    def test_ambiguous_pre_receipt_send_can_close_as_unverifiable_only_after_its_execution_ends(self) -> None:
        from types import SimpleNamespace
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="session_return_1", target="odin",
                               payload={"delivery_mode": "session_return", "execution_id": "execution_x"}, now=T0)
                delivery_claims = claim_due(state, worker="worker-a", now=T0)
                mark_delivery_ambiguous(state, outbox_id=item.id, worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), detail="no receipt", now=T0)
                reason = "Sent before provider receipts existed; gateway accepted it but kept no message id."

                def attempt(status: str, **overrides):
                    kwargs = dict(outbox_id=item.id, resolved_by="operator", outcome="unverifiable",
                                  provider_receipt="", detail=reason, now=T0 + timedelta(seconds=1))
                    kwargs.update(overrides)
                    with patch("arvyx_control.execution.project_executions",
                               return_value={"execution_x": SimpleNamespace(status=status)}):
                        return reconcile_ambiguous_delivery(state, **kwargs)

                before = state.read_bytes()
                with self.assertRaisesRegex(ValueError, "execution to be terminal"):
                    attempt("leased")
                with self.assertRaisesRegex(ValueError, "needs a reason"):
                    attempt("closed", detail="")
                with self.assertRaisesRegex(ValueError, "must not include a provider receipt"):
                    attempt("closed", provider_receipt="telegram-message-42")
                self.assertEqual(state.read_bytes(), before)

                resolved = attempt("closed")
                self.assertEqual(resolved.status, "dead_lettered")
                self.assertEqual(resolved.resolution_category, "ambiguous_unverifiable")
                self.assertEqual(resolved.provider_receipt, "")
                self.assertEqual(resolved.resolution_detail, reason)
                # Never claims delivery, so no session-return continuation is queued.
                self.assertEqual([i.id for i in project_outbox(state).values()], [item.id])

    def test_ambiguous_delivery_can_be_reconciled_as_not_delivered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(
                    state,
                    subject_id="session_return_1",
                    target="odin",
                    payload={"delivery_mode": "session_return"},
                    now=T0,
                )
                delivery_claims = claim_due(state, worker="worker-a", now=T0)
                mark_delivery_ambiguous(
                    state, outbox_id=item.id, worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), detail="unknown", now=T0,
                )

                resolved = reconcile_ambiguous_delivery(
                    state,
                    outbox_id=item.id,
                    resolved_by="operator",
                    outcome="not_delivered",
                    provider_receipt="",
                    detail="provider readback found no message",
                    now=T0 + timedelta(seconds=1),
                )

                self.assertEqual(resolved.status, "dead_lettered")
                self.assertEqual(resolved.resolution_category, "ambiguous_not_delivered")
                self.assertEqual(resolved.provider_receipt, "")

    def test_operator_cli_reconciles_ambiguous_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(
                    state,
                    subject_id="session_return_1",
                    target="odin",
                    payload={"delivery_mode": "session_return"},
                    now=T0,
                )
                delivery_claims = claim_due(state, worker="worker-a", now=T0)
                mark_delivery_ambiguous(
                    state, outbox_id=item.id, worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id),
                    detail="receipt lost", now=T0,
                )
                output = io.StringIO()

                with redirect_stdout(output):
                    status = main(["--authority-vault", str(vault), *[
                        "execution", "reconcile-delivery",
                        "--state", str(state),
                        "--outbox-id", item.id,
                        "--outcome", "delivered",
                        "--provider-receipt", "telegram-message-42",
                        "--detail", "provider readback",
                        "--json",
                    ]])

                self.assertEqual(status, 0)
                self.assertEqual(json.loads(output.getvalue())["status"], "delivered")

    def test_target_receipts_are_monotonic_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="handoff_1", target="amir", payload={"kind": "handoff"}, now=T0)
                delivery_claims = claim_due(state, worker="worker-a", now=T0)
                mark_delivered(state, outbox_id=item.id, worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), now=T0)

                seen = record_receipt(state, outbox_id=item.id, actor="amir", status="seen", now=T0)
                duplicate = record_receipt(state, outbox_id=item.id, actor="amir", status="seen", now=T0)
                accepted = record_receipt(state, outbox_id=item.id, actor="amir", status="accepted", now=T0)
                completed = record_receipt(
                    state,
                    outbox_id=item.id,
                    actor="amir",
                    status="completed",
                    detail="work completed",
                    now=T0,
                )

                self.assertEqual(seen.receipt_status, "seen")
                self.assertEqual(duplicate, seen)
                self.assertEqual(accepted.receipt_status, "accepted")
                self.assertEqual(completed.receipt_status, "completed")
                self.assertEqual(completed.receipt_detail, "work completed")
                self.assertEqual(len([event for event in read_events(state) if event.type == "outbox.receipt"]), 3)
                with self.assertRaisesRegex(ValueError, "actor does not match"):
                    record_receipt(state, outbox_id=item.id, actor="esme", status="completed", now=T0)
                with self.assertRaisesRegex(ValueError, "already terminal"):
                    record_receipt(state, outbox_id=item.id, actor="amir", status="failed", now=T0)

    def test_receipt_detail_rejects_secret_shaped_input_without_writing_an_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="handoff_1", target="amir", payload={"kind": "handoff"}, now=T0)
                delivery_claims = claim_due(state, worker="worker-a", now=T0)
                mark_delivered(state, outbox_id=item.id, worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), now=T0)
                before = len(read_events(state))

                with self.assertRaisesRegex(ValueError, "detail contains a secret-shaped string"):
                    record_receipt(
                        state, outbox_id=item.id, actor="amir", status="completed",
                        detail="receipt " + "Bearer " + ("a" * 26), now=T0,
                    )

                self.assertEqual(len(read_events(state)), before)
                self.assertEqual(project_outbox(state)[item.id].receipt_status, "")

    def test_receipt_detail_has_an_explicit_4096_character_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="handoff_1", target="amir", payload={"kind": "handoff"}, now=T0)
                delivery_claims = claim_due(state, worker="worker-a", now=T0)
                mark_delivered(state, outbox_id=item.id, worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), now=T0)

                with self.assertRaisesRegex(ValueError, "detail must not exceed 4096 characters"):
                    record_receipt(
                        state, outbox_id=item.id, actor="amir", status="completed",
                        detail="x" * 4097, now=T0,
                    )
                accepted = record_receipt(
                    state, outbox_id=item.id, actor="amir", status="completed",
                    detail="x" * 4096, now=T0,
                )
                self.assertEqual(len(accepted.receipt_detail), 4096)

    def test_receipt_detail_redaction_remains_defense_in_depth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="handoff_1", target="amir", payload={"kind": "handoff"}, now=T0)
                delivery_claims = claim_due(state, worker="worker-a", now=T0)
                mark_delivered(state, outbox_id=item.id, worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), now=T0)
                detail = "receipt " + "Bearer " + ("a" * 26)

                with patch("arvyx_control.outbox.contains_literal_secret", return_value=False):
                    completed = record_receipt(
                        state, outbox_id=item.id, actor="amir", status="completed",
                        detail=detail, now=T0,
                    )

                self.assertEqual(completed.receipt_detail, "receipt [REDACTED-SECRET]")

    def test_receipt_requires_delivered_transport_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="task_1", target="amir", payload={"kind": "task"}, now=T0)
                with self.assertRaisesRegex(ValueError, "not delivered"):
                    record_receipt(state, outbox_id=item.id, actor="amir", status="seen", now=T0)

    def test_replay_increments_epoch_and_is_not_swallowed_by_old_dedupe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                original = enqueue(state, subject_id="thread_1", target="amir", payload={"kind": "ask"}, now=T0)
                delivery_claims = claim_due(state, worker="worker-a", now=T0)
                record_failure(
                    state,
                    outbox_id=original.id,
                    worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == original.id),
                    detail="invalid payload",
                    transient=False,
                    now=T0,
                )

                replayed = replay(state, outbox_id=original.id, now=T0 + timedelta(minutes=1))
                duplicate = enqueue(
                    state,
                    subject_id="thread_1",
                    target="amir",
                    payload={"kind": "ask"},
                    epoch=1,
                    now=T0 + timedelta(minutes=1),
                )

                self.assertNotEqual(replayed.id, original.id)
                self.assertEqual(replayed.epoch, 1)
                self.assertEqual(duplicate.id, replayed.id)
                self.assertEqual(read_events(state)[-1].type, "outbox.replayed")

    def test_self_created_task_is_suppressed_but_operator_assignment_is_delivered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                create_task(state, "Self follow-up", owner="amir", created_by="amir")
                self.assertEqual(
                    claim_due(state, worker="worker-a", now=T0, deliver_after="2000-01-01T00:00:00Z"),
                    [],
                )
                create_task(state, "Assigned work", owner="amir", created_by="operator")
                claimed = claim_due(state, worker="worker-a", now=T0, deliver_after="2000-01-01T00:00:00Z")
                self.assertEqual(len(claimed), 1)
                self.assertEqual(claimed[0].target, "amir")

    def test_source_events_materialize_once_after_rollout_watermark(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                task = create_task(state, "Task", owner="amir")
                handoff = create_handoff(state, "Handoff", from_agent="esme", to_agent="kiran")
                thread = post_thread(state, "Ask", actor="kiran", target="odin")

                claimed = claim_due(
                    state,
                    worker="worker-a",
                    now=T0,
                    limit=10,
                    deliver_after="2000-01-01T00:00:00Z",
                )
                repeated = claim_due(
                    state,
                    worker="worker-b",
                    now=T0,
                    limit=10,
                    deliver_after="2000-01-01T00:00:00Z",
                )

                self.assertEqual({item.target for item in claimed}, {"amir", "kiran", "odin"})
                self.assertEqual(
                    {item.subject_id for item in claimed},
                    {task.task.id, handoff.handoff.id, thread.thread.id},
                )
                self.assertEqual(repeated, [])
                self.assertEqual(
                    len([event for event in read_events(state) if event.type == "outbox.enqueued"]),
                    3,
                )

    def test_contracted_thread_materialization_preserves_wake_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                created = post_thread(
                    state,
                    "Update canonical memory",
                    actor="operator",
                    target="amir",
                    completion_artifact="/home/operator/.hermes/memories/USER.md",
                    completion_anchor="0bserverx",
                )
                claimed = claim_due(
                    state, worker="worker-a", now=T0, limit=10,
                    deliver_after="2000-01-01T00:00:00Z",
                )
                item = next(entry for entry in claimed if entry.subject_id == created.thread.id)
                self.assertEqual(item.payload["completion_artifact"], "/home/operator/.hermes/memories/USER.md")
                self.assertEqual(item.payload["completion_anchor"], "0bserverx")

    def test_thread_acknowledgement_does_not_materialize_a_second_wake(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                created = post_thread(state, "Execute once", actor="amir", target="esme")
                acknowledge_thread(state, created.thread.id, actor="esme")

                claimed = claim_due(
                    state, worker="worker-a", now=T0, limit=10,
                    deliver_after="2000-01-01T00:00:00Z",
                )

                subject_items = [item for item in claimed if item.subject_id == created.thread.id]
                self.assertEqual(len(subject_items), 1)
                self.assertEqual(subject_items[0].target, "esme")
                self.assertEqual(subject_items[0].payload["source_event_type"], "thread.created")
                self.assertNotIn("execution_mode", subject_items[0].payload)
                self.assertNotIn("execution_action", subject_items[0].payload)
                self.assertNotIn("delivery_mode", subject_items[0].payload)

    def test_thread_done_materializes_as_originator_notification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                created = post_thread(state, "Curate truth", actor="amir", target="kiran")
                complete_thread(state, created.thread.id, actor="kiran")

                claimed = claim_due(
                    state, worker="worker-a", now=T0, limit=10,
                    deliver_after="2000-01-01T00:00:00Z",
                )
                item = next(
                    entry for entry in claimed
                    if entry.payload["source_event_type"] == "thread.done"
                )
                self.assertEqual(item.target, "amir")
                self.assertEqual(item.subject_id, created.thread.id)
                self.assertEqual(item.payload["delivery_mode"], "notification")
                self.assertNotIn("completion_artifact", item.payload)
                self.assertNotIn("completion_anchor", item.payload)

                delivered = mark_delivered(
                    state, outbox_id=item.id, worker="worker-a", claim_attempts=next(c.attempts for c in claimed if c.id == item.id), now=T0,
                )
                receipt = record_receipt(
                    state, outbox_id=delivered.id, actor="amir", status="completed", now=T0,
                )
                self.assertEqual(receipt.receipt_status, "completed")
                self.assertEqual(receipt.receipt_by, "amir")

    def test_child_done_notification_carries_exact_continuation_thread(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                parent = post_thread(state, "Parent work", actor="odin", target="amir")
                acknowledge_thread(
                    state, parent.thread.id, actor="amir", actor_identity_bound=True
                )
                child = post_thread(
                    state,
                    "Child dependency",
                    actor="amir",
                    target="kiran",
                    continuation_thread_id=parent.thread.id,
                    actor_identity_bound=True,
                )
                complete_thread(state, child.thread.id, actor="kiran")

                claimed = claim_due(
                    state, worker="worker-a", now=T0, limit=10,
                    deliver_after="2000-01-01T00:00:00Z",
                )
                item = next(
                    entry for entry in claimed
                    if entry.payload["source_event_type"] == "thread.done"
                )
                self.assertEqual(item.target, "amir")
                self.assertEqual(item.payload["continuation_thread_id"], parent.thread.id)

    def test_thread_done_by_originator_is_self_suppressed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                created = post_thread(state, "Self close", actor="amir", target="kiran")
                complete_thread(state, created.thread.id, actor="amir")

                claimed = claim_due(
                    state, worker="worker-a", now=T0, limit=10,
                    deliver_after="2000-01-01T00:00:00Z",
                )
                self.assertFalse(any(
                    entry.payload["source_event_type"] == "thread.done"
                    for entry in claimed
                ))

    def test_handoff_review_and_completion_materialize_as_notifications(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                created = create_handoff(state, "Review delivery", from_agent="esme", to_agent="kiran")
                accept_handoff(state, created.handoff.id, actor="kiran")
                review_handoff(state, created.handoff.id, reviewer="kiran")
                complete_handoff(state, created.handoff.id, actor="kiran")

                claimed = claim_due(
                    state, worker="worker-a", now=T0, limit=10,
                    deliver_after="2000-01-01T00:00:00Z",
                )
                notices = [
                    entry for entry in claimed
                    if entry.payload["source_event_type"] in {"handoff.reviewed", "handoff.completed"}
                ]
                self.assertEqual(len(notices), 2)
                self.assertEqual({entry.target for entry in notices}, {"esme"})
                self.assertEqual({entry.payload["delivery_mode"] for entry in notices}, {"notification"})

    def test_direct_materialization_omits_delivery_mode_for_hash_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                created = post_thread(state, "Direct work", actor="esme", target="amir")
                claimed = claim_due(
                    state, worker="worker-a", now=T0, limit=10,
                    deliver_after="2000-01-01T00:00:00Z",
                )
                item = next(entry for entry in claimed if entry.subject_id == created.thread.id)
                self.assertNotIn("delivery_mode", item.payload)

    def test_source_event_materialization_is_bounded_per_claim_tick(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                for index in range(5):
                    create_task(state, f"Task {index}", owner="amir")

                first_report: dict[str, int | bool] = {}
                first = claim_due(
                    state, worker="worker-a", now=T0, limit=10,
                    deliver_after="2000-01-01T00:00:00Z", materialization_limit=2,
                    materialization_report=first_report,
                )
                second_report: dict[str, int | bool] = {}
                second = claim_due(
                    state, worker="worker-b", now=T0, limit=10,
                    deliver_after="2000-01-01T00:00:00Z", materialization_limit=2,
                    materialization_report=second_report,
                )

                self.assertEqual(len(first), 2)
                self.assertEqual(len(second), 2)
                self.assertEqual(first_report, {"materialized": 2, "remaining": True})
                self.assertEqual(second_report, {"materialized": 2, "remaining": True})
                self.assertEqual(len([event for event in read_events(state) if event.type == "outbox.enqueued"]), 4)

    def test_dry_run_reports_bounded_materialization_without_appending_or_claiming(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                for index in range(3):
                    create_task(state, f"Task {index}", owner="amir")
                before = state.read_bytes()
                report: dict[str, int | bool] = {}

                claimed = claim_due(
                    state, worker="worker-a", now=T0, limit=10,
                    deliver_after="2000-01-01T00:00:00Z", materialization_limit=2,
                    materialization_report=report, dry_run=True,
                )

                self.assertEqual(claimed, [])
                self.assertEqual(report, {"materialized": 2, "remaining": True})
                self.assertEqual(state.read_bytes(), before)

    def test_expired_bootstrap_watermark_does_not_block_an_enqueued_item(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                pending = enqueue(state, subject_id="task_pending", target="amir", payload={"kind": "task"}, now=T0)

                claimed = claim_due(
                    state, worker="worker-a", now=T0,
                    deliver_after="2026-08-08T12:00:00Z",
                    max_watermark_age_seconds=86400,
                )

                self.assertEqual([item.id for item in claimed], [pending.id])

    def test_checkpoint_materializes_new_events_after_bootstrap_is_24_hours_old(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                first = create_task(state, "First", owner="amir")
                initial = claim_due(
                    state, worker="worker-a", now=T0,
                    deliver_after="2026-08-10T11:59:00Z", max_watermark_age_seconds=86400,
                )
                mark_delivered(state, outbox_id=initial[0].id, worker="worker-a", claim_attempts=next(c.attempts for c in initial if c.id == initial[0].id), now=T0)
                later = T0 + timedelta(hours=25)
                second = create_task(state, "Second", owner="amir")

                claimed = claim_due(
                    state, worker="worker-b", now=later,
                    deliver_after="2026-08-10T11:59:00Z", max_watermark_age_seconds=86400,
                )

                self.assertEqual(initial[0].subject_id, first.task.id)
                self.assertEqual([item.subject_id for item in claimed], [second.task.id])

    def test_checkpoint_recovers_after_enqueue_batch_was_appended_before_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                tasks = [create_task(state, f"Task {index}", owner="amir") for index in range(2)]
                from arvyx_control import outbox as outbox_module
                real_append = outbox_module._append_event_unlocked

                def crash_on_checkpoint(state_path, event):
                    if event.type == "outbox.materialization.checkpoint":
                        raise RuntimeError("simulated crash")
                    return real_append(state_path, event)

                with patch("arvyx_control.outbox._append_event_unlocked", side_effect=crash_on_checkpoint):
                    with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                        claim_due(
                            state, worker="worker-a", now=T0,
                            deliver_after="2026-08-10T11:59:00Z", materialization_limit=2,
                        )

                recovered = claim_due(
                    state, worker="worker-b", now=T0,
                    deliver_after="2026-08-10T11:59:00Z", materialization_limit=2, limit=2,
                )
                self.assertEqual({item.subject_id for item in recovered}, {task.task.id for task in tasks})
                self.assertEqual(len([e for e in read_events(state) if e.type == "outbox.enqueued"]), 2)
                self.assertEqual(len([e for e in read_events(state) if e.type == "outbox.materialization.checkpoint"]), 1)

    def test_partial_final_materialization_write_is_explicitly_recoverable_and_deduplicates_on_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                tasks = [create_task(state, f"Task {index}", owner="amir") for index in range(2)]
                from arvyx_control import control as control_module
                real_write = control_module.os.write
                injected = False

                def partial_write(fd, data):
                    nonlocal injected
                    if not injected and b'\"type\": \"outbox.enqueued\"' in data:
                        injected = True
                        prefix = data[: len(data) // 2]
                        real_write(fd, prefix)
                        return len(prefix)
                    return real_write(fd, data)

                with patch("arvyx_control.control.os.write", side_effect=partial_write):
                    with self.assertRaisesRegex(OSError, "short event append"):
                        claim_due(
                            state, worker="worker-a", now=T0,
                            deliver_after="2026-08-10T11:59:00Z", materialization_limit=2,
                        )

                with self.assertRaisesRegex(ValueError, "invalid event JSON"):
                    read_events(state)
                receipt = recover_torn_final_event(state)
                self.assertGreater(receipt["removed_bytes"], 0)
                self.assertTrue(Path(str(receipt["quarantine_path"])).read_bytes())

                recovered = claim_due(
                    state, worker="worker-b", now=T0,
                    deliver_after="2026-08-10T11:59:00Z", materialization_limit=2, limit=2,
                )
                self.assertEqual({item.subject_id for item in recovered}, {task.task.id for task in tasks})
                self.assertEqual(len([e for e in read_events(state) if e.type == "outbox.enqueued"]), 2)
                self.assertEqual(len([e for e in read_events(state) if e.type == "outbox.materialization.checkpoint"]), 1)

    def test_torn_record_recovery_refuses_mid_file_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                create_task(state, "First", owner="amir")
                create_task(state, "Second", owner="amir")
                original = state.read_bytes()
                first_newline = original.index(b"\n")
                corrupted = original[: first_newline // 2] + b"BROKEN" + original[first_newline:] + b'{"torn":'
                state.write_bytes(corrupted)

                with self.assertRaisesRegex(ValueError, "mid-file corruption"):
                    recover_torn_final_event(state)
                self.assertEqual(state.read_bytes(), corrupted)

    def test_blind_writer_refuses_to_glue_a_new_event_to_a_torn_tail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                create_task(state, "Complete", owner="amir")
                state.write_bytes(state.read_bytes() + b'{"torn":')

                with self.assertRaisesRegex(ValueError, "torn final event; refusing append"):
                    post_thread(state, "Must not be glued", target="amir", actor="operator")

                receipt = recover_torn_final_event(state)
                self.assertGreater(receipt["removed_bytes"], 0)
                posted = post_thread(state, "After recovery", target="amir", actor="operator")
                self.assertEqual(posted.thread.title, "After recovery")
                self.assertEqual(len(read_events(state)), 2)

    def test_operator_cli_recovers_a_torn_final_record_with_a_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                create_task(state, "Complete", owner="amir")
                state.write_bytes(state.read_bytes() + b'{"torn":')
                output = io.StringIO()

                with redirect_stdout(output):
                    status = main(["--authority-vault", str(vault), *["control-log", "recover-torn-final", "--state", str(state), "--json"]])

                receipt = json.loads(output.getvalue())
                self.assertEqual(status, 0)
                self.assertGreater(receipt["removed_bytes"], 0)
                self.assertEqual(len(read_events(state)), 1)

    def test_torn_record_recovery_repairs_a_complete_record_missing_only_its_newline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                create_task(state, "Complete", owner="amir")
                state.write_bytes(state.read_bytes()[:-1])

                receipt = recover_torn_final_event(state)
                self.assertEqual(receipt["repair"], "missing_final_newline")
                self.assertEqual(receipt["removed_bytes"], 0)
                self.assertTrue(state.read_bytes().endswith(b"\n"))
                create_task(state, "Writable again", owner="amir")
                self.assertEqual(len(read_events(state)), 2)

    def test_partial_batch_checkpoint_does_not_skip_events_appended_between_ticks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                original = [create_task(state, f"Task {index}", owner="amir") for index in range(3)]
                first = claim_due(
                    state, worker="worker-a", now=T0, limit=10,
                    deliver_after="2026-08-10T11:59:00Z", materialization_limit=2,
                )
                appended = create_task(state, "Appended between ticks", owner="amir")
                second = claim_due(
                    state, worker="worker-b", now=T0, limit=10,
                    deliver_after="2026-08-10T11:59:00Z", materialization_limit=2,
                )

                self.assertEqual(len(first), 2)
                self.assertEqual(
                    {item.subject_id for item in first + second},
                    {task.task.id for task in original} | {appended.task.id},
                )
                checkpoints = [e for e in read_events(state) if e.type == "outbox.materialization.checkpoint"]
                self.assertEqual(len(checkpoints), 2)
                self.assertNotEqual(checkpoints[0].payload["source_event_id"], checkpoints[1].payload["source_event_id"])

    def test_idle_tick_does_not_append_checkpoint_churn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                create_task(state, "Task", owner="amir")
                claimed = claim_due(
                    state, worker="worker-a", now=T0,
                    deliver_after="2026-08-10T11:59:00Z",
                )
                mark_delivered(state, outbox_id=claimed[0].id, worker="worker-a", claim_attempts=next(c.attempts for c in claimed if c.id == claimed[0].id), now=T0)
                claim_due(
                    state, worker="worker-b", now=T0 + timedelta(seconds=1),
                    deliver_after="2026-08-10T11:59:00Z",
                )
                checkpoint_count = len([
                    event for event in read_events(state)
                    if event.type == "outbox.materialization.checkpoint"
                ])

                claim_due(
                    state, worker="worker-c", now=T0 + timedelta(seconds=2),
                    deliver_after="2026-08-10T11:59:00Z",
                )

                self.assertEqual(
                    len([event for event in read_events(state) if event.type == "outbox.materialization.checkpoint"]),
                    checkpoint_count,
                )

    def test_handoff_completion_materializes_reverse_delivery_to_origin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                handoff = create_handoff(state, "Review", from_agent="esme", to_agent="amir")
                first = claim_due(
                    state,
                    worker="worker-a",
                    now=T0,
                    limit=10,
                    deliver_after="2000-01-01T00:00:00Z",
                )[0]
                mark_delivered(state, outbox_id=first.id, worker="worker-a", claim_attempts=first.attempts, now=T0)
                accept_handoff(state, handoff.handoff.id)
                complete_handoff(state, handoff.handoff.id)

                reverse = claim_due(
                    state,
                    worker="worker-b",
                    now=T0,
                    limit=10,
                    deliver_after="2000-01-01T00:00:00Z",
                )

                self.assertEqual(len(reverse), 1)
                self.assertEqual(reverse[0].target, "esme")
                self.assertEqual(reverse[0].payload["source_event_type"], "handoff.completed")
                self.assertEqual(reverse[0].subject_id, handoff.handoff.id)

    def test_rollout_watermark_rejects_empty_malformed_and_timezone_naive_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                create_task(state, "Historical", owner="amir")
                before = len(read_events(state))
                for value in ("", "10/08/2026", "2026-08-10T12:00:00"):
                    with self.subTest(value=value):
                        with self.assertRaisesRegex(ValueError, "deliver_after must be a timezone-aware RFC3339 instant"):
                            claim_due(state, worker="worker-a", now=T0, deliver_after=value)
                        self.assertEqual(len(read_events(state)), before)

    def test_rollout_watermark_blocks_historical_source_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                create_handoff(state, "Historical", from_agent="esme", to_agent="amir")

                claimed = claim_due(
                    state,
                    worker="worker-a",
                    now=T0,
                    deliver_after="9999-01-01T00:00:00Z",
                )

                self.assertEqual(claimed, [])
                self.assertFalse(any(event.type == "outbox.enqueued" for event in read_events(state)))

    def test_expired_lease_reclaims_are_bounded_by_failure_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="task_1", target="amir", payload={"kind": "task"}, now=T0)
                claim_due(state, worker="worker-a", now=T0, lease_seconds=1, max_attempts=3)
                claim_due(state, worker="worker-b", now=T0 + timedelta(seconds=2), lease_seconds=1, max_attempts=3)
                claim_due(state, worker="worker-c", now=T0 + timedelta(seconds=4), lease_seconds=1, max_attempts=3)
                final = claim_due(
                    state,
                    worker="worker-d",
                    now=T0 + timedelta(seconds=6),
                    lease_seconds=1,
                    max_attempts=3,
                )
                projected = project_outbox(state)[item.id]
                self.assertEqual(final, [])
                self.assertEqual(projected.status, "dead_lettered")
                self.assertEqual(projected.failures, 3)
                self.assertEqual(
                    len([event for event in read_events(state) if event.type == "outbox.attempt.started"]),
                    3,
                )

    def test_expired_lease_reclaims_consume_failure_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="task_1", target="amir", payload={"kind": "task"}, now=T0)
                claim_due(state, worker="worker-a", now=T0, lease_seconds=1)
                claim_due(state, worker="worker-b", now=T0 + timedelta(seconds=2), lease_seconds=1)
                third = claim_due(state, worker="worker-c", now=T0 + timedelta(seconds=4), lease_seconds=1)[0]
                failed = record_failure(
                    state,
                    outbox_id=item.id,
                    worker="worker-c", claim_attempts=third.attempts,
                    detail="timeout",
                    transient=True,
                    max_attempts=4,
                    now=T0 + timedelta(seconds=4),
                    jitter=lambda _upper: 0,
                )
                self.assertEqual(third.attempts, 3)
                self.assertEqual(failed.failures, 3)
                self.assertEqual(failed.status, "pending")

    def test_transient_failure_dead_letters_at_max_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="task_1", target="amir", payload={"kind": "task"}, now=T0)
                delivery_claims = claim_due(state, worker="worker-a", now=T0)

                failed = record_failure(
                    state,
                    outbox_id=item.id,
                    worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id),
                    detail="still unavailable",
                    transient=True,
                    max_attempts=1,
                    now=T0,
                )

                self.assertEqual(failed.status, "dead_lettered")
                self.assertEqual(read_events(state)[-1].type, "outbox.dead_lettered")

    def test_projection_backfills_failures_from_legacy_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="task_1", target="amir", payload={"kind": "task"}, now=T0)
                delivery_claims = claim_due(state, worker="worker-a", now=T0)
                record_failure(
                    state,
                    outbox_id=item.id,
                    worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id),
                    detail="timeout",
                    transient=True,
                    now=T0,
                    jitter=lambda _upper: 0,
                )
                legacy_lines = []
                for line in state.read_text(encoding="utf-8").splitlines():
                    event = json.loads(line)
                    event["payload"].pop("failures", None)
                    legacy_lines.append(json.dumps(event, sort_keys=True))
                state.write_text("\n".join(legacy_lines) + "\n", encoding="utf-8")
                self.assertEqual(project_outbox(state)[item.id].failures, 1)

    def test_sqlite_projection_migrates_existing_outbox_failures_column(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                db = Path(tmp) / "projection.sqlite3"
                enqueue(state, subject_id="task_1", target="amir", payload={"kind": "task"}, now=T0)
                old_schema = SCHEMA.replace("  failures INTEGER NOT NULL,\n", "")
                with closing(sqlite3.connect(db)) as conn:
                    conn.executescript(old_schema)
                    conn.commit()
                sync_sqlite(state, db)
                with closing(sqlite3.connect(db)) as conn:
                    columns = {row[1] for row in conn.execute("PRAGMA table_info(outbox)")}
                    failures = conn.execute("SELECT failures FROM outbox").fetchone()[0]
                    version = conn.execute("PRAGMA user_version").fetchone()[0]
                self.assertIn("failures", columns)
                self.assertEqual(failures, 0)
                self.assertEqual(version, 2)

    def test_sqlite_projection_rebuild_and_repeated_sync_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                db = Path(tmp) / "control.sqlite"
                item = enqueue(state, subject_id="thread_1", target="amir", payload={"kind": "ask"}, now=T0)
                delivery_claims = claim_due(state, worker="worker-a", now=T0)
                mark_delivered(state, outbox_id=item.id, worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), now=T0)

                first = sync_sqlite(state, db)
                second = sync_sqlite(state, db)

                self.assertEqual(first.outbox, 1)
                self.assertEqual(second.outbox, 1)
                with closing(sqlite3.connect(db)) as conn:
                    row = conn.execute("SELECT id, status, attempts FROM outbox").fetchone()
                self.assertEqual(row, (item.id, "delivered", 1))

    def test_sqlite_projects_only_item_lifecycle_events_from_mixed_outbox_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                db = Path(tmp) / "control.sqlite"
                delivered = enqueue(state, subject_id="thread_1", target="amir", payload={"kind": "ask"}, now=T0)
                delivery_claims = claim_due(state, worker="worker-a", now=T0)
                mark_delivered(state, outbox_id=delivered.id, worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == delivered.id), now=T0)
                record_receipt(state, outbox_id=delivered.id, actor="amir", status="accepted", now=T0)
                cancelled = enqueue(state, subject_id="thread_2", target="missing", payload={"kind": "ask"}, now=T0)
                cancel_unroutable(
                    state,
                    outbox_id=cancelled.id,
                    configured_targets={"amir"},
                    reason_category="unroutable_target",
                    now=T0,
                )
                _append_event_unlocked(
                    state,
                    _event(
                        MATERIALIZATION_CHECKPOINT_EVENT,
                        "outbox_materialization",
                        T0.isoformat().replace("+00:00", "Z"),
                        {"source_event_id": "source-event-1"},
                    ),
                )
                record_dispatcher_tick(state, configured_targets={"amir"}, now=T0)

                result = sync_sqlite(state, db)

                self.assertEqual(
                    [event.type for event in read_events(state)],
                    [
                        "outbox.enqueued",
                        "outbox.attempt.started",
                        "outbox.delivered",
                        "outbox.receipt",
                        "outbox.enqueued",
                        "outbox.cancelled",
                        "outbox.materialization.checkpoint",
                        "outbox.dispatcher.tick",
                    ],
                )
                self.assertEqual(result.source_events, 8)
                self.assertEqual(result.events, 8)
                self.assertEqual(result.outbox, 2)
                with closing(sqlite3.connect(db)) as conn:
                    rows = conn.execute("SELECT id, status, receipt_status FROM outbox ORDER BY id").fetchall()
                self.assertEqual(
                    rows,
                    sorted([(delivered.id, "delivered", "accepted"), (cancelled.id, "cancelled", "")]),
                )


class DispatcherTickCoalescingTests(unittest.TestCase):
    """The tick record is the dispatcher's liveness authority, so coalescing must
    never hide a state change and never let the record age past the freshness
    windows other components read (300 seconds today)."""

    def _state(self, tmp: str) -> Path:
        return Path(tmp) / "events.jsonl"

    def test_last_tick_timestamp_reads_the_newest_tick(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                record_dispatcher_tick(state, configured_targets={"amir"}, now=T0)
                expected = T0.isoformat().replace("+00:00", "Z")
                self.assertEqual(last_dispatcher_tick_timestamp(state), expected)

    def test_last_tick_timestamp_is_empty_without_a_tick(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                enqueue(state, subject_id="s1", target="amir", payload={}, now=T0)
                self.assertEqual(last_dispatcher_tick_timestamp(state), "")

    def test_last_tick_timestamp_falls_back_when_the_tick_left_the_tail_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                record_dispatcher_tick(state, configured_targets={"amir"}, now=T0)
                expected = T0.isoformat().replace("+00:00", "Z")
                with open(state, "a", encoding="utf-8") as handle:
                    for index in range(40):
                        handle.write(
                            json.dumps(
                                {
                                    "id": f"filler_{index}",
                                    "type": "filler.event",
                                    "task_id": "filler",
                                    "timestamp": expected,
                                    "payload": {"pad": "x" * 8000},
                                }
                            )
                            + "\n"
                        )
                self.assertEqual(last_dispatcher_tick_timestamp(state, tail_bytes=1024), expected)

    def test_a_tick_that_did_something_is_always_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                record_dispatcher_tick(state, configured_targets={"amir"}, now=T0)
                self.assertTrue(
                    should_record_dispatcher_tick(state, has_work=True, now=T0 + timedelta(seconds=1))
                )

    def test_a_noop_tick_records_only_on_the_heartbeat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                record_dispatcher_tick(state, configured_targets={"amir"}, now=T0)
                self.assertFalse(
                    should_record_dispatcher_tick(state, has_work=False, now=T0 + timedelta(seconds=1))
                )
                self.assertFalse(
                    should_record_dispatcher_tick(state, has_work=False, now=T0 + timedelta(seconds=179))
                )
                self.assertTrue(
                    should_record_dispatcher_tick(state, has_work=False, now=T0 + timedelta(seconds=180))
                )

    def test_a_tick_is_recorded_when_no_previous_tick_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            self.assertTrue(should_record_dispatcher_tick(state, has_work=False, now=T0))

    def test_a_line_that_only_mentions_the_tick_name_is_not_read_as_a_tick(self) -> None:
        """The tail reader must match the event type exactly, not by substring."""
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                record_dispatcher_tick(state, configured_targets={"amir"}, now=T0)
                expected = T0.isoformat().replace("+00:00", "Z")
                with open(state, "a", encoding="utf-8") as handle:
                    handle.write(
                        json.dumps(
                            {
                                "id": "other_1",
                                "type": "outbox.delivered",
                                "task_id": "outbox_other",
                                "timestamp": (T0 + timedelta(hours=3)).isoformat().replace("+00:00", "Z"),
                                "payload": {"note": "mentions outbox.dispatcher.tick in prose"},
                            }
                        )
                        + "\n"
                    )
                record = last_dispatcher_tick_record(state)
                self.assertEqual(record["timestamp"], expected)
                self.assertEqual(last_dispatcher_tick_timestamp(state), expected)

    def test_a_changed_snapshot_is_recorded_immediately(self) -> None:
        """A coalesced cycle must not leave a stale attestation or health flag."""
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                recorded = {
                    "healthy": True,
                    "configured_targets": ["amir"],
                    "materialization_remaining": False,
                    "skipped_unconfigured_targets": [],
                    "skipped_intentional_human_targets": [],
                    "route_revision": "2026-09-11-r1",
                    "route_sha256": "a" * 64,
                }
                record_dispatcher_tick(
                    state,
                    configured_targets={"amir"},
                    healthy=True,
                    route_revision="2026-09-11-r1",
                    route_sha256="a" * 64,
                    now=T0,
                )
                soon = T0 + timedelta(seconds=30)
                # identical snapshot: coalesced
                self.assertFalse(
                    should_record_dispatcher_tick(
                        state, has_work=False, now=soon, snapshot=dict(recorded)
                    )
                )
                # a newly staged route document: written immediately
                self.assertTrue(
                    should_record_dispatcher_tick(
                        state,
                        has_work=False,
                        now=soon,
                        snapshot={**recorded, "route_revision": "2026-09-11-r2", "route_sha256": "b" * 64},
                    )
                )
                # a target removed from the map: written immediately
                self.assertTrue(
                    should_record_dispatcher_tick(
                        state, has_work=False, now=soon, snapshot={**recorded, "configured_targets": []}
                    )
                )
                # a fault that has cleared: written immediately
                self.assertTrue(
                    should_record_dispatcher_tick(
                        state, has_work=False, now=soon, snapshot={**recorded, "healthy": False}
                    )
                )

    def test_the_heartbeat_leaves_room_inside_the_consumer_windows(self) -> None:
        """Health staleness and the cancel gate both refuse past 300 seconds."""
        from arvyx_control.outbox import TICK_HEARTBEAT_SECONDS

        self.assertLess(TICK_HEARTBEAT_SECONDS + 60, 300)


if __name__ == "__main__":
    unittest.main()
