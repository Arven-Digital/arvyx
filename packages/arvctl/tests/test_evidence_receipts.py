from __future__ import annotations
from arvyx_control.replica_authority import authority_context

from datetime import datetime, timedelta, timezone
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from arvyx_control.control import acknowledge_thread, complete_thread, post_thread
from arvyx_control.cli import main
from arvyx_control.execution import (
    claim_execution,
    heartbeat_execution_as_target,
    materialize_executions,
)
from arvyx_control.outbox import claim_due, mark_delivered, record_receipt, record_failure, project_outbox
from arvyx_control.receipts import EvidenceEvent, project_subject_receipt
from arvyx_control.session_return import request_session_return


UTC = timezone.utc
T0 = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)


class EvidenceReceiptProjectionTests(unittest.TestCase):
    def test_unknown_evidence_never_projects_green(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                posted = post_thread(
                    state,
                    "Investigate",
                    actor="amir",
                    target="esme",
                    actor_identity_bound=True,
                )

                receipt = project_subject_receipt(state, subject_id=posted.thread.id)

                self.assertEqual(receipt.status, "YELLOW")
                self.assertEqual(receipt.legs["capture"].state, "succeeded")
                self.assertEqual(receipt.legs["dispatch"].state, "pending")
                self.assertEqual(receipt.legs["accept"].state, "pending")
                self.assertEqual(receipt.legs["work"].state, "pending")
                self.assertEqual(receipt.legs["deliver"].state, "pending")

    def test_operator_cli_exposes_subject_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                posted = post_thread(
                    state, "Inspect", actor="amir", target="esme", actor_identity_bound=True,
                )
                output = io.StringIO()

                with redirect_stdout(output):
                    status = main(["--authority-vault", str(vault),
                        "execution", "receipt", "--state", str(state),
                        "--subject-id", posted.thread.id, "--json",
                    ])

                self.assertEqual(status, 0)
                self.assertEqual(json.loads(output.getvalue())["status"], "YELLOW")

    def test_unobservable_runtime_outcome_does_not_prove_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                posted = post_thread(
                    state,
                    "Observe",
                    actor="amir",
                    target="esme",
                    actor_identity_bound=True,
                )
                materialize_executions(state, execution_capable_targets={"esme"}, now=T0)
                execution = claim_execution(
                    state,
                    worker="worker",
                    execution_capable_targets={"esme"},
                    now=T0,
                    lease_seconds=120,
                )
                assert execution is not None
                heartbeat_execution_as_target(
                    state,
                    execution_id=execution.id,
                    attempt_id=execution.attempt_id,
                    actor="esme",
                    now=T0,
                    runtime_outcome="unobservable",
                )

                receipt = project_subject_receipt(state, subject_id=posted.thread.id)

                self.assertEqual(receipt.status, "YELLOW")
                self.assertEqual(receipt.legs["work"].state, "pending")
                self.assertEqual(receipt.legs["work"].reason, "unobservable")

    def test_provider_error_runtime_outcome_projects_failed_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                posted = post_thread(
                    state,
                    "Observe failure",
                    actor="amir",
                    target="esme",
                    actor_identity_bound=True,
                )
                execution = claim_execution(
                    state,
                    worker="worker",
                    execution_capable_targets={"esme"},
                    now=T0,
                    lease_seconds=120,
                )
                assert execution is not None
                heartbeat_execution_as_target(
                    state,
                    execution_id=execution.id,
                    attempt_id=execution.attempt_id,
                    actor="esme",
                    now=T0,
                    runtime_outcome="provider_error",
                )

                receipt = project_subject_receipt(state, subject_id=posted.thread.id)

                self.assertEqual(receipt.status, "RED")
                self.assertEqual(receipt.legs["work"].state, "failed")

    def test_progress_heartbeat_alone_does_not_prove_work_complete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                posted = post_thread(
                    state, "Progress", actor="amir", target="esme", actor_identity_bound=True,
                )
                execution = claim_execution(
                    state, worker="worker", execution_capable_targets={"esme"}, now=T0,
                )
                assert execution is not None
                heartbeat_execution_as_target(
                    state,
                    execution_id=execution.id,
                    attempt_id=execution.attempt_id,
                    actor="esme",
                    now=T0,
                    runtime_outcome="progressing",
                )

                receipt = project_subject_receipt(state, subject_id=posted.thread.id)

                self.assertEqual(receipt.legs["work"].state, "pending")
                self.assertEqual(receipt.legs["work"].reason, "progressing")

    def test_terminal_beats_old_failed_beat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                posted = post_thread(
                    state, "Recover", actor="amir", target="esme", actor_identity_bound=True,
                )
                first = claim_execution(
                    state, worker="worker-one", execution_capable_targets={"esme"},
                    now=T0, lease_seconds=10,
                )
                assert first is not None
                heartbeat_execution_as_target(
                    state,
                    execution_id=first.id,
                    attempt_id=first.attempt_id,
                    actor="esme",
                    now=T0,
                    lease_seconds=10,
                    runtime_outcome="provider_error",
                )
                second = claim_execution(
                    state, worker="worker-two", execution_capable_targets={"esme"},
                    now=datetime(2026, 9, 2, 12, 0, 25, tzinfo=UTC), lease_seconds=60,
                )
                assert second is not None
                complete_thread(
                    state, posted.thread.id, actor="esme", actor_identity_bound=True,
                )

                receipt = project_subject_receipt(state, subject_id=posted.thread.id)

                self.assertEqual(receipt.legs["work"].state, "succeeded")

    def test_inference_cannot_prove_a_leg(self) -> None:
        with self.assertRaisesRegex(ValueError, "inferred evidence cannot prove success"):
            EvidenceEvent(
                leg="work",
                state="succeeded",
                provenance="inferred",
                evidence_ref="model-guessed-progress",
            )

    def test_full_identity_bound_lifecycle_projects_green(self) -> None:
        self._full_identity_bound_lifecycle()

    def test_delivered_replacement_supersedes_old_failed_return_only_after_terminal(self) -> None:
        self._full_identity_bound_lifecycle(replacement=True)

    def _full_identity_bound_lifecycle(self, *, replacement=False) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                posted = post_thread(
                    state,
                    "Return result",
                    actor="amir",
                    target="esme",
                    actor_identity_bound=True,
                )
                delivery = claim_due(
                    state,
                    worker="dispatcher",
                    now=T0,
                    deliver_after="2000-01-01T00:00:00Z",
                )[0]
                mark_delivered(state, outbox_id=delivery.id, worker="dispatcher", claim_attempts=delivery.attempts, now=T0)
                record_receipt(
                    state,
                    outbox_id=delivery.id,
                    actor="esme",
                    status="accepted",
                    now=T0,
                )
                acknowledge_thread(
                    state,
                    posted.thread.id,
                    actor="esme",
                    actor_identity_bound=True,
                )
                materialize_executions(state, execution_capable_targets={"esme"}, now=T0)
                execution = claim_execution(
                    state,
                    worker="worker",
                    execution_capable_targets={"esme"},
                    now=T0,
                    lease_seconds=120,
                )
                assert execution is not None
                heartbeat_execution_as_target(
                    state,
                    execution_id=execution.id,
                    attempt_id=execution.attempt_id,
                    actor="esme",
                    now=T0,
                    lease_seconds=120,
                    detail="material progress",
                )
                failed_item = None
                if replacement:
                    failed = request_session_return(state, execution_id=execution.id,
                        attempt_id=execution.attempt_id, actor='esme', message='Earlier result',
                        expected_word_count=2, idempotency_key='earlier-receipt-return', now=T0)
                    attempts = claim_due(state, worker='dispatcher', now=T0,
                        deliver_after='2000-01-01T00:00:00Z', limit=10)
                    failed_item = next(item for item in attempts if item.subject_id == failed.request_id)
                    record_failure(state, outbox_id=failed_item.id, worker='dispatcher',
                        claim_attempts=failed_item.attempts, detail='synthetic permanent refusal',
                        transient=False, now=T0)
                    # One session return per attempt: the attempt that sent the
                    # failed return can never request another. A permanently
                    # failed return frees the lineage only for a new attempt, so
                    # the replacement comes from the reclaimed attempt.
                    with self.assertRaisesRegex(ValueError, "execution attempt already has a session return"):
                        request_session_return(state, execution_id=execution.id,
                            attempt_id=execution.attempt_id, actor='esme', message='Verified result',
                            expected_word_count=2, idempotency_key='evidence-receipt-same-attempt', now=T0)
                    current = T0 + timedelta(seconds=240)
                    reclaimed = claim_execution(state, worker="worker", execution_capable_targets={"esme"},
                        now=current, lease_seconds=120)
                    assert reclaimed is not None
                    self.assertEqual(reclaimed.id, execution.id)
                    self.assertNotEqual(reclaimed.attempt_id, execution.attempt_id)
                    execution = reclaimed
                    heartbeat_execution_as_target(state, execution_id=execution.id,
                        attempt_id=execution.attempt_id, actor="esme", now=current,
                        lease_seconds=120, detail="material progress")
                else:
                    current = T0
                returned = request_session_return(
                    state,
                    execution_id=execution.id,
                    attempt_id=execution.attempt_id,
                    actor="esme",
                    message="Verified result",
                    expected_word_count=2,
                    idempotency_key="evidence-receipt-return-1",
                    now=current,
                )
                return_delivery = claim_due(
                    state,
                    worker="dispatcher",
                    now=current,
                    deliver_after="2000-01-01T00:00:00Z",
                    limit=10,
                )
                return_item = next(item for item in return_delivery if item.subject_id == returned.request_id)
                mark_delivered(
                    state,
                    outbox_id=return_item.id,
                    worker="dispatcher", claim_attempts=next(c.attempts for c in return_delivery if c.id == return_item.id),
                    provider_receipt="provider-message-1",
                    now=current,
                )
                if replacement:
                    self.assertEqual(project_subject_receipt(state, subject_id=posted.thread.id).legs['deliver'].state, 'failed')
                complete_thread(
                    state,
                    posted.thread.id,
                    actor="esme",
                    actor_identity_bound=True,
                )

                receipt = project_subject_receipt(state, subject_id=posted.thread.id)

                self.assertEqual(receipt.status, "GREEN")
                if failed_item:
                    self.assertEqual(project_outbox(state)[failed_item.id].status, 'dead_lettered')
                self.assertTrue(all(leg.state == "succeeded" for leg in receipt.legs.values()))
                self.assertEqual(receipt.legs["deliver"].provenance, "provider")


if __name__ == "__main__":
    unittest.main()
