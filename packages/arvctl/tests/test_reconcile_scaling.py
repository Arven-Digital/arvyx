"""reconcile_executions must be linear in the log, and exactly as strict as before.

Production evidence (2026-09-24, 306k events, ~430 executions): every worker and
watchdog tick spent ~30 s in reconcile_executions while holding the state lock,
because each execution rescanned the whole log (31.8M terminal checks per tick).
"""
from __future__ import annotations
from arvyx_control.replica_authority import authority_context

from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control import execution as execution_module
from arvyx_control.control import (
    _append_event, _event, accept_handoff, acknowledge_thread, complete_handoff,
    complete_thread, create_handoff, post_thread, read_events,
)
from arvyx_control.execution import (
    _is_authoritative_terminal,
    materialize_executions,
    project_executions,
    reconcile_executions,
)

UTC = timezone.utc
T0 = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)


def _reference_terminals(state: Path) -> dict[str, str]:
    """The pre-fix algorithm, verbatim in behavior: for each non-archived,
    non-completed execution, the newest authoritative terminal in the log."""
    from arvyx_control.operator_archive import archived_ids

    executions = project_executions(state)
    events = read_events(state)
    archived = archived_ids(events)
    explicitly_closed = {
        e.task_id for e in events
        if e.type == "execution.closed" and e.payload.get("status") == "closed"
        and isinstance(e.payload.get("operator_archive"), dict)
        and e.payload["operator_archive"].get("operation") == "operator_archive"
    }
    expected: dict[str, str] = {}
    for execution in executions.values():
        if execution.subject_id in archived or execution.id in explicitly_closed:
            continue
        terminal = next(
            (event for event in reversed(events) if _is_authoritative_terminal(event, execution)),
            None,
        )
        if terminal is None or execution.status == "completed":
            continue
        expected[execution.id] = terminal.id
    return expected


class ReconcileScalingTests(unittest.TestCase):
    def _thread(self, state: Path, *, target: str, title: str) -> str:
        thread = post_thread(
            state, title=title, actor="esme", target=target, thread_type="ask",
            actor_identity_bound=True,
        )
        acknowledge_thread(state, thread.thread.id, actor=target, actor_identity_bound=True)
        return thread.thread.id

    def _noise(self, state: Path, count: int) -> None:
        for index in range(count):
            _append_event(state, _event(
                "outbox.dispatcher.tick", "outbox_dispatcher",
                f"2026-08-20T12:{index // 60 % 60:02d}:{index % 60:02d}Z", {"healthy": True},
            ))

    def _build(self, state: Path) -> None:
        subjects = [self._thread(state, target="amir", title=f"work {i}") for i in range(10)]
        kiran = self._thread(state, target="kiran", title="kiran work")
        handoff = create_handoff(
            state, "target-owned work", from_agent="esme", to_agent="amir", actor_identity_bound=True,
        )
        accept_handoff(state, handoff.handoff.id, actor="amir", actor_identity_bound=True)
        materialize_executions(state, execution_capable_targets={"amir", "kiran"}, now=T0)
        self._noise(state, 500)
        # Authoritative: bound target DONE (two of them twice; newest must win).
        for subject in subjects[:4]:
            complete_thread(state, subject, actor="amir", actor_identity_bound=True)
        self._noise(state, 300)
        # Non-authoritative terminals that must never complete an execution.
        complete_thread(state, subjects[4], actor="amir")                              # unbound
        complete_thread(state, subjects[5], actor="operator", actor_identity_bound=True)  # non-target
        complete_thread(state, kiran, actor="amir", actor_identity_bound=True)           # wrong target
        complete_handoff(state, handoff.handoff.id, actor="amir", actor_identity_bound=True)
        self._noise(state, 200)

    def test_terminal_checks_are_bounded_by_executions_not_log_length(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._build(state)
                executions = len(project_executions(state))
                events = len(read_events(state))
                calls = {"n": 0}
                real = execution_module._is_authoritative_terminal

                def counting(event, execution):
                    calls["n"] += 1
                    return real(event, execution)

                with patch.object(execution_module, "_is_authoritative_terminal", counting):
                    reconcile_executions(state, now=T0 + timedelta(seconds=5))
                # Pre-fix: one full-log scan per execution, i.e. up to executions * events.
                self.assertGreater(events, 1000)
                self.assertLessEqual(calls["n"], executions)

    def test_linear_reconcile_matches_the_reference_algorithm_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._build(state)
                reference_copy = Path(tmp) / "reference.jsonl"
                shutil.copyfile(state, reference_copy)
                expected = _reference_terminals(reference_copy)

                reconciled = reconcile_executions(state, now=T0 + timedelta(seconds=5))

                self.assertEqual({item.id: item.terminal_event_id for item in reconciled}, expected)
                self.assertEqual(len(expected), 5)  # 4 bound thread DONEs + 1 bound handoff completion
                # Idempotent: a second pass finds nothing new, exactly like the reference.
                self.assertEqual(reconcile_executions(state, now=T0 + timedelta(seconds=6)), [])
                self.assertEqual(_reference_terminals(state), {})

    def test_newest_authoritative_terminal_wins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self._thread(state, target="amir", title="twice")
                materialize_executions(state, execution_capable_targets={"amir"}, now=T0)
                complete_thread(state, subject, actor="amir", actor_identity_bound=True)
                newest = [e for e in read_events(state) if e.type == "thread.done"][-1]
                # Forge a later bound terminal for the same subject directly in the log.
                later = _event("thread.done", subject, "2026-08-20T13:00:00Z",
                               {**newest.payload, "done_at": "2026-08-20T13:00:00Z"})
                _append_event(state, later)
                reference_copy = Path(tmp) / "reference.jsonl"
                shutil.copyfile(state, reference_copy)
                expected = _reference_terminals(reference_copy)
                reconciled = reconcile_executions(state, now=T0 + timedelta(seconds=5))
                self.assertEqual({item.id: item.terminal_event_id for item in reconciled}, expected)
                self.assertEqual(next(iter(expected.values())), later.id)

    def test_later_non_authoritative_terminal_cannot_mask_an_earlier_authoritative_one(self) -> None:
        # An index that kept only the newest terminal per (type, subject, actor) would
        # pick the later unbound DONE and silently drop the valid bound one.
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self._thread(state, target="amir", title="bound then unbound")
                materialize_executions(state, execution_capable_targets={"amir"}, now=T0)
                complete_thread(state, subject, actor="amir", actor_identity_bound=True)
                bound = [e for e in read_events(state) if e.type == "thread.done"][-1]
                _append_event(state, _event(
                    "thread.done", subject, "2026-08-20T13:00:00Z",
                    {**bound.payload, "actor_identity_bound": False, "done_at": "2026-08-20T13:00:00Z"},
                ))
                reference_copy = Path(tmp) / "reference.jsonl"
                shutil.copyfile(state, reference_copy)
                expected = _reference_terminals(reference_copy)
                self.assertEqual(list(expected.values()), [bound.id])
                reconciled = reconcile_executions(state, now=T0 + timedelta(seconds=5))
                self.assertEqual({item.id: item.terminal_event_id for item in reconciled}, expected)


if __name__ == "__main__":
    unittest.main()
