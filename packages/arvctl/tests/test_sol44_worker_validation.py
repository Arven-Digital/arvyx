from arvyx_control.replica_authority import authority_context
"""Astra43 finding 4 regression source. Status: NOT_EXECUTED."""
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control import execution as lifecycle
from arvyx_control.control import post_thread

NOW = datetime(2026, 10, 28, tzinfo=timezone.utc)


class WorkerValidationTests(unittest.TestCase):
    def assignment(self, state):
        return post_thread(
            state, title="worker validation", actor="operator", target="amir",
            thread_type="ask", actor_identity_bound=True,
        ).thread.id

    def test_invalid_worker_precedes_all_claim_side_effects(self):
        for worker in (None, False, 0, 42, [], {}, "", " ", "\t\r\n", "\u2003"):
            for mode in ("normal", "subject", "execution", "direct"):
                with self.subTest(worker=worker, mode=mode), tempfile.TemporaryDirectory() as tmp:
                    state = Path(tmp) / "events.jsonl"
                    vault = Path(tmp) / "authority-vault"
                    vault.mkdir(exist_ok=True)
                    with authority_context(vault, state):
                        subject = self.assignment(state)
                        selector = {}
                        if mode == "execution":
                            root = lifecycle.materialize_executions(
                                state, execution_capable_targets={"amir"}, now=NOW,
                            )[0]
                            selector = {"execution_id": root.id, "target": "amir"}
                        elif mode in {"subject", "direct"}:
                            selector = {"subject_id": subject, "target": "amir"}
                        before = state.read_bytes()
                        with patch.object(lifecycle, "_materialize_executions") as materialize, \
                             patch.object(lifecycle, "_reconcile_executions") as reconcile, \
                             patch.object(lifecycle, "_locked_state") as lock:
                            with self.assertRaisesRegex(ValueError, "worker"):
                                if mode == "direct":
                                    lifecycle._claim_exact_execution(
                                        state, worker=worker, execution_capable_targets={"amir"},
                                        execution_id=None, now=NOW, lease_seconds=60, **selector,
                                    )
                                else:
                                    lifecycle.claim_execution(
                                        state, worker=worker, execution_capable_targets={"amir"},
                                        now=NOW, **selector,
                                    )
                            materialize.assert_not_called()
                            reconcile.assert_not_called()
                            lock.assert_not_called()
                        self.assertEqual(state.read_bytes(), before)
                        claimed = lifecycle.claim_execution(
                            state, worker="ValidWorker", execution_capable_targets={"amir"},
                            now=NOW, **selector,
                        )
                        self.assertIsNotNone(claimed)
                        self.assertEqual(lifecycle.project_executions(state)[claimed.id], claimed)

    def test_trimmed_owner_remains_usable_and_case_sensitive(self):
        for exact in (False, True):
            with self.subTest(exact=exact), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / "events.jsonl"
                vault = Path(tmp) / "authority-vault"
                vault.mkdir(exist_ok=True)
                with authority_context(vault, state):
                    subject = self.assignment(state)
                    claimed = lifecycle.claim_execution(
                        state, worker="  WorkerA\t", execution_capable_targets={"amir"},
                        now=NOW, **({"subject_id": subject, "target": "amir"} if exact else {}),
                    )
                    self.assertEqual(claimed.lease_owner, "WorkerA")
                    self.assertEqual(lifecycle.project_executions(state)[claimed.id], claimed)
                    for worker in ("WorkerA", "  WorkerA\t"):
                        lifecycle.heartbeat_execution(
                            state, execution_id=claimed.id, attempt_id=claimed.attempt_id,
                            worker=worker, now=NOW,
                        )
                    before = state.read_bytes()
                    with self.assertRaisesRegex(ValueError, "not leased by worker"):
                        lifecycle.heartbeat_execution(
                            state, execution_id=claimed.id, attempt_id=claimed.attempt_id,
                            worker="workera", now=NOW,
                        )
                    self.assertEqual(state.read_bytes(), before)
                    lifecycle.record_execution_failure(
                        state, execution_id=claimed.id, attempt_id=claimed.attempt_id,
                        worker="  WorkerA\t", detail="synthetic failure", now=NOW,
                    )
