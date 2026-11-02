"""Events must be stamped where they are appended, not where the call entered.

A control pass that samples its clock on entry, waits on the state lock, and then
re-reads the whole event log can stamp a derived event *before* the cause it was
read from. That is the defect behind the ``thread.created`` inversions in the
production log, where three events of a single worker pass shared one
byte-identical stamp while being appended after a thread stamped 30 seconds later.

The first test pins the observable signature (appends in one call carry their own
stamps); the second pins the invariant itself (a derived event never predates its
source). Both fail against a clock sampled on entry.
"""

from __future__ import annotations
from arvyx_control.replica_authority import authority_context

from datetime import datetime, timezone
from itertools import count
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control import execution
from arvyx_control import projection_cache
from arvyx_control.control import ControlEvent, post_thread, read_events


UTC = timezone.utc


def _parsed(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


class AppendTimeStampTests(unittest.TestCase):
    def _thread(self, state: Path, title: str, *, stamp: str = "2026-08-20T11:59:00Z") -> None:
        with patch("arvyx_control.control._now", return_value=stamp):
            post_thread(
                state,
                title=title,
                actor="esme",
                target="amir",
                thread_type="ask",
                actor_identity_bound=True,
            )

    def test_two_appends_in_one_call_do_not_share_a_stamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._thread(state, "work one")
                self._thread(state, "work two")
                ticks = count()
                with patch(
                    "arvyx_control.execution._timestamp",
                    side_effect=lambda value=None: f"2026-08-20T12:00:{10 + next(ticks):02d}Z",
                ):
                    created = execution.materialize_executions(
                        state, execution_capable_targets={"amir"}
                    )
                stamps = [
                    event.timestamp
                    for event in read_events(state)
                    if event.type == "execution.created"
                ]
                self.assertEqual(len(created), 2, "both threads should materialize one execution")
                self.assertEqual(
                    len(set(stamps)),
                    2,
                    "two events appended in one call shared a stamp: the clock was sampled "
                    "once on entry instead of at each append",
                )

    def test_execution_created_is_not_stamped_before_the_thread_appended_while_it_waited(
        self,
    ) -> None:
        """The racing writer, without deadlocking on the state lock.

        Another process can append a thread between this call's clock sample and
        its log read, so the read already sees it. Simulating that directly on the
        read result reproduces the ordering without taking the lock twice.
        """
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                real_read = execution.read_events
                real_timestamp = execution._timestamp
                after_read: list[bool] = []

                def read_with_racing_thread(path: Path):
                    events = real_read(path)
                    after_read.append(True)
                    events.append(
                        ControlEvent(
                            id="event_racing_thread",
                            type="thread.created",
                            task_id="thread_racing",
                            timestamp="2026-08-20T12:00:05Z",
                            payload={"target": "amir", "type": "ask", "actor_identity_bound": True},
                        )
                    )
                    return events

                def clock(value=None):
                    if value is not None:
                        return real_timestamp(value)
                    return "2026-08-20T12:00:30Z" if after_read else "2026-08-20T11:59:00Z"

                # The scan reads through the projection cache now: it resumes from the
                # checkpoint and only falls back to a full parse, so the racing append
                # is injected at both read entry points. The invariant under test is
                # unchanged — whichever read sees the thread, the derived event must be
                # stamped where it is appended, not where the call entered.
                with patch("arvyx_control.execution.read_events", side_effect=read_with_racing_thread), patch(
                    "arvyx_control.projection_cache.read_events", side_effect=read_with_racing_thread
                ), patch("arvyx_control.execution._timestamp", side_effect=clock):
                    execution.materialize_executions(state, execution_capable_targets={"amir"})

                created = next(
                    event for event in read_events(state) if event.type == "execution.created"
                )
                self.assertGreaterEqual(
                    _parsed(created.timestamp),
                    _parsed("2026-08-20T12:00:05Z"),
                    "execution.created predates the thread it was materialized from: the "
                    "stamp was taken before the log read instead of at the append",
                )


    def test_a_resumed_scan_stamps_after_the_tail_it_read(self) -> None:
        """The same invariant on the checkpoint-resumed path.

        This is the path production actually runs: the scan takes the seeded
        prefix from the checkpoint and only the tail from the log, so the racing
        writer arrives through ``read_tail_events``. The execution materialized
        from it must still be stamped where it is appended, not where the call
        entered — the invariant does not get weaker just because the read moved.
        """
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._thread(state, "materialized into the checkpoint")
                report = projection_cache.build_projection_checkpoint(state, force=True)
                self.assertTrue(report["built"], report)
                real_tail = projection_cache.read_tail_events
                real_timestamp = execution._timestamp
                after_read: list[bool] = []

                def tail_with_racing_thread(path: Path, offset: int, first_line: int):
                    events = real_tail(path, offset, first_line)
                    after_read.append(True)
                    events.append(
                        ControlEvent(
                            id="event_racing_thread",
                            type="thread.created",
                            task_id="thread_racing",
                            timestamp="2026-08-20T12:00:05Z",
                            payload={"target": "amir", "type": "ask", "actor_identity_bound": True},
                        )
                    )
                    return events

                def clock(value=None):
                    if value is not None:
                        return real_timestamp(value)
                    return "2026-08-20T12:00:30Z" if after_read else "2026-08-20T11:59:00Z"

                with patch.object(
                    projection_cache, "read_tail_events", side_effect=tail_with_racing_thread
                ), patch("arvyx_control.execution._timestamp", side_effect=clock):
                    execution.materialize_executions(state, execution_capable_targets={"amir"})

                created = next(
                    event
                    for event in read_events(state)
                    if event.type == "execution.created"
                    # the event's task_id is the execution id, not the thread it came from
                    and event.payload.get("subject_id") == "thread_racing"
                )
                self.assertGreaterEqual(
                    _parsed(created.timestamp),
                    _parsed("2026-08-20T12:00:05Z"),
                    "the resumed path stamped before the tail it read: the clock was sampled "
                    "before the read instead of at the append",
                )


if __name__ == "__main__":
    unittest.main()
