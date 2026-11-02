from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.replica_authority import authority_context
from arvyx_control.control import acknowledge_thread, create_handoff, post_thread
from arvyx_control.execution import (
    cancel_execution,
    claim_execution,
    materialize_executions,
    project_executions,
    queue_health,
)

UTC = timezone.utc
T0 = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)


class AssignmentDrivenExecutionKernelTests(unittest.TestCase):
    def test_actionable_thread_assignment_materializes_before_ack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with patch("arvyx_control.control._now", return_value="2026-09-02T11:59:00Z"):
                    posted = post_thread(
                        state,
                        title="kernel task",
                        actor="esme",
                        target="odin",
                        thread_type="ask",
                        actor_identity_bound=True,
                    )

                created = materialize_executions(
                    state,
                    execution_capable_targets={"odin"},
                    now=T0,
                )

                self.assertEqual(len(created), 1)
                self.assertEqual(created[0].subject_id, posted.thread.id)
                self.assertEqual(created[0].target, "odin")
                self.assertEqual(created[0].source_event_type, "thread.created")

    def test_target_ack_does_not_create_a_second_execution_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with patch("arvyx_control.control._now", return_value="2026-09-02T11:59:00Z"):
                    posted = post_thread(
                        state,
                        title="one root",
                        actor="esme",
                        target="amir",
                        thread_type="ask",
                        actor_identity_bound=True,
                    )
                materialize_executions(state, execution_capable_targets={"amir"}, now=T0)
                with patch("arvyx_control.control._now", return_value="2026-09-02T12:00:01Z"):
                    acknowledge_thread(
                        state,
                        posted.thread.id,
                        actor="amir",
                        actor_identity_bound=True,
                    )

                again = materialize_executions(
                    state,
                    execution_capable_targets={"amir"},
                    now=T0,
                )

                self.assertEqual(again, [])
                self.assertEqual(len(project_executions(state)), 1)

    def test_handoff_assignment_materializes_before_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with patch("arvyx_control.control._now", return_value="2026-09-02T11:59:00Z"):
                    handoff = create_handoff(
                        state,
                        "kernel handoff",
                        from_agent="amir",
                        to_agent="kiran",
                        actor_identity_bound=True,
                    )

                created = materialize_executions(
                    state,
                    execution_capable_targets={"kiran"},
                    now=T0,
                )

                self.assertEqual(len(created), 1)
                self.assertEqual(created[0].subject_id, handoff.handoff.id)
                self.assertEqual(created[0].target, "kiran")
                self.assertEqual(created[0].source_event_type, "handoff.created")

    def test_non_actionable_update_does_not_materialize(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with patch("arvyx_control.control._now", return_value="2026-09-02T11:59:00Z"):
                    post_thread(
                        state,
                        title="status only",
                        actor="esme",
                        target="amir",
                        thread_type="update",
                        actor_identity_bound=True,
                    )

                self.assertEqual(
                    materialize_executions(
                        state,
                        execution_capable_targets={"amir"},
                        now=T0,
                    ),
                    [],
                )

    def test_health_reports_actionable_assignment_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with patch("arvyx_control.control._now", return_value="2026-09-02T11:59:00Z"):
                    posted = post_thread(
                        state,
                        title="not materialized yet",
                        actor="esme",
                        target="odin",
                        thread_type="ask",
                        actor_identity_bound=True,
                    )

                health = queue_health(
                    state,
                    execution_capable_targets={"odin"},
                    now=T0,
                )

                self.assertEqual(health["assigned_without_live_execution_count"], 1)
                self.assertEqual(health["assigned_without_live_execution"], [posted.thread.id])

    def test_health_reports_paused_execution_separately_from_missing_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with patch("arvyx_control.control._now", return_value="2026-09-02T11:59:00Z"):
                    post_thread(state, title="paused work", actor="esme", target="odin", thread_type="ask", actor_identity_bound=True)
                execution = claim_execution(state, worker="worker", execution_capable_targets={"odin"}, now=T0)
                assert execution is not None
                cancel_execution(state, execution_id=execution.id, reason="operator pause", cancelled_by="operator", now=T0)

                health = queue_health(state, execution_capable_targets={"odin"}, now=T0)

                self.assertEqual(health["assigned_without_live_execution_count"], 0)
                self.assertEqual(health["assigned_without_live_execution"], [])
                self.assertEqual(health["paused_execution_count"], 1)
                self.assertEqual(health["paused_executions"], [execution.id])

    def _pre_cutoff_assignment(self, state: Path, *, legacy_shape: bool) -> str:
        """Post a pre-cutoff assignment and its identity-bound target ACK.

        A genuine pre-provenance record has no ``actor_identity_bound`` field at
        all. The current writer serializes unknown provenance as explicit
        ``null`` (docs/durable-agent-execution.md), which never qualifies for the
        legacy fallback; ``legacy_shape`` emulates the historical producer by
        omitting the field from the creation payload only.
        """
        from arvyx_control import control as control_module

        current_payload = control_module._thread_event_payload

        def historical_payload(thread):
            payload = current_payload(thread)
            payload.pop("actor_identity_bound", None)
            return payload

        with patch(
            "arvyx_control.control._now",
            side_effect=["2026-09-01T23:58:00Z", "2026-09-01T23:59:00Z"],
        ):
            with patch.object(
                control_module, "_thread_event_payload",
                historical_payload if legacy_shape else current_payload,
            ):
                posted = post_thread(
                    state,
                    title="legacy assignment",
                    actor="esme",
                    target="odin",
                    thread_type="ask",
                )
            self.assertEqual("actor_identity_bound" in posted.event.payload, not legacy_shape)
            acknowledge_thread(
                state,
                posted.thread.id,
                actor="odin",
                actor_identity_bound=True,
            )
        return posted.thread.id

    def test_pre_cutoff_assignment_uses_exact_target_ack_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                thread_id = self._pre_cutoff_assignment(state, legacy_shape=True)

                created = materialize_executions(
                    state,
                    execution_capable_targets={"odin"},
                    now=T0,
                )
                self.assertEqual(len(created), 1)
                self.assertEqual(created[0].subject_id, thread_id)

    def test_pre_cutoff_explicit_null_provenance_is_not_legacy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._pre_cutoff_assignment(state, legacy_shape=False)
                self.assertEqual(
                    materialize_executions(state, execution_capable_targets={"odin"}, now=T0), [],
                )

    def test_unbound_assignment_cannot_materialize_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with patch(
                    "arvyx_control.control._now",
                    side_effect=["2026-09-02T11:59:00Z", "2026-09-02T12:00:01Z"],
                ):
                    posted = post_thread(
                        state,
                        title="untrusted assignment",
                        actor="operator",
                        target="odin",
                        thread_type="ask",
                        actor_identity_bound=False,
                    )
                    acknowledge_thread(
                        state,
                        posted.thread.id,
                        actor="odin",
                        actor_identity_bound=True,
                    )

                self.assertEqual(
                    materialize_executions(
                        state,
                        execution_capable_targets={"odin"},
                        now=T0,
                    ),
                    [],
                )


if __name__ == "__main__":
    unittest.main()
