"""The control-event log is read incrementally, and must stay exact while doing it.

Every read surface projects this append-only log, and a full parse of the production log
(103 MB / 242k events) costs ~3 s, so `/summary` and `/control-plane` took 22 s and 13 s.
`read_events` now keeps what it parsed and reads only appended bytes. These tests pin the
properties that make that safe: no duplicate or missed event, a full re-parse when the
file is not merely appended to, and a torn tail still failing closed with the right line
number.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from arvyx_control.replica_authority import authority_context
from arvyx_control import control


def _event(index: int) -> str:
    return json.dumps(
        {
            "id": f"evt_{index}",
            "type": "thread.created",
            "task_id": f"task_{index}",
            "timestamp": f"2026-09-14T00:00:{index:02d}Z",
            "payload": {"index": index},
        }
    )


class EventReadCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        control._EVENT_CACHE.clear()  # noqa: SLF001 - the cache is the subject here
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "control-events.jsonl"
        self.vault = Path(self.tmp.name) / "vault"
        self.vault.mkdir(exist_ok=True)
        self.enterContext(authority_context(self.vault, self.state))

    def tearDown(self) -> None:
        control._EVENT_CACHE.clear()  # noqa: SLF001
        self.tmp.cleanup()

    def _write(self, lines: list[str]) -> None:
        self.state.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")

    def _append(self, lines: list[str]) -> None:
        with self.state.open("a", encoding="utf-8") as handle:
            for line in lines:
                handle.write(f"{line}\n")

    def test_second_read_of_an_unchanged_log_parses_nothing(self) -> None:
        self._write([_event(1), _event(2)])
        first = control.read_events(self.state)
        self.assertEqual([event.id for event in first], ["evt_1", "evt_2"])

        real = control.parse_event_line
        calls = 0

        def counting(line: str, *, line_number: int):
            nonlocal calls
            calls += 1
            return real(line, line_number=line_number)

        with mock.patch.object(control, "parse_event_line", counting):
            second = control.read_events(self.state)
        self.assertEqual(calls, 0, "a cached read must not parse any line again")
        self.assertEqual([event.id for event in second], ["evt_1", "evt_2"])

    def test_append_yields_old_and_new_events_exactly_once(self) -> None:
        self._write([_event(1), _event(2)])
        control.read_events(self.state)
        self._append([_event(3), _event(4)])
        events = control.read_events(self.state)
        self.assertEqual([event.id for event in events], ["evt_1", "evt_2", "evt_3", "evt_4"])

    def test_incremental_read_parses_only_the_appended_bytes(self) -> None:
        self._write([_event(1), _event(2)])
        control.read_events(self.state)
        self._append([_event(3)])
        real = control.parse_event_line
        calls = 0

        def counting(line: str, *, line_number: int):
            nonlocal calls
            calls += 1
            return real(line, line_number=line_number)

        with mock.patch.object(control, "parse_event_line", counting):
            events = control.read_events(self.state)
        self.assertEqual(calls, 1, "only the appended line is parsed")
        self.assertEqual([event.id for event in events], ["evt_1", "evt_2", "evt_3"])

    def test_in_place_rewrite_of_a_longer_log_is_not_read_as_an_append(self) -> None:
        self._write([_event(1)])
        control.read_events(self.state)
        # Same inode, longer content written in place. Only the prefix check catches this:
        # size and mtime alone both look like an append.
        self._write([_event(5), _event(6)])
        events = control.read_events(self.state)
        self.assertEqual([event.id for event in events], ["evt_5", "evt_6"])

    def test_replaced_log_is_reparsed_not_mixed(self) -> None:
        self._write([_event(1), _event(2), _event(3)])
        control.read_events(self.state)
        replacement = Path(self.tmp.name) / "replacement.jsonl"
        replacement.write_text(f"{_event(9)}\n", encoding="utf-8")
        replacement.replace(self.state)
        events = control.read_events(self.state)
        self.assertEqual([event.id for event in events], ["evt_9"])

    def test_rewritten_log_of_equal_length_is_not_read_from_cache(self) -> None:
        self._write([_event(1)])
        control.read_events(self.state)
        # same byte length, different content: only the mtime check catches this
        self._write([_event(7)])
        events = control.read_events(self.state)
        self.assertEqual([event.id for event in events], ["evt_7"])

    def test_torn_tail_fails_closed_and_keeps_the_line_number(self) -> None:
        self._write([_event(1), _event(2)])
        control.read_events(self.state)
        with self.state.open("a", encoding="utf-8") as handle:
            handle.write('{"id": "evt_3", "type": "thr')
        with self.assertRaises(ValueError) as caught:
            control.read_events(self.state)
        self.assertIn("line 3", str(caught.exception))

    def test_returned_list_is_a_copy(self) -> None:
        self._write([_event(1)])
        first = control.read_events(self.state)
        first.clear()
        self.assertEqual(len(control.read_events(self.state)), 1)

    def test_max_bytes_snapshot_path_is_unchanged(self) -> None:
        self._write([_event(1), _event(2)])
        with self.assertRaises(ValueError):
            control.read_events(self.state, max_bytes=10)
        self.assertEqual(len(control.read_events(self.state, max_bytes=4096)), 2)


if __name__ == "__main__":
    unittest.main()
