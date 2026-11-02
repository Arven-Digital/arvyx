"""Latest15 regressions; authored but not executed in the no-check fix lane."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from arvyx_control.control import create_handoff, accept_handoff, complete_handoff, read_events
from arvyx_control.operator_archive import _validate_history
from arvyx_control.replica_authority import authority_context
from arvyx_control.delivery_probe import ProbeConfig, check_ticks, run_probe
from arvyx_control.liveness import write_tick_record


class ArchiveLivenessRegressions(unittest.TestCase):
    def test_writer_supersession_and_malformed_repeats(self):
        for actor, bound in [('operator', False), ('source', True), ('target', False)]:
            with self.subTest(actor=actor, bound=bound), tempfile.TemporaryDirectory() as root:
                state = Path(root) / 'events.jsonl'
                vault = Path(root) / 'vault'
                vault.mkdir()
                with authority_context(vault, state):
                    handoff = create_handoff(state, 'Synthetic handoff', 'source', 'target').handoff
                    accept_handoff(state, handoff.id, actor='target', actor_identity_bound=True)
                    complete_handoff(state, handoff.id, actor=actor, actor_identity_bound=bound)
                    complete_handoff(state, handoff.id, actor='target', actor_identity_bound=True)
                    events = read_events(state)
                    _validate_history(events, handoff.id)
                    before = state.read_bytes()
                    with self.assertRaises(ValueError):
                        complete_handoff(state, handoff.id, actor='target', actor_identity_bound=True)
                    self.assertEqual(before, state.read_bytes())
                terminal = events[-1]
                for changes in ({'completed_by': 'source'}, {'actor_identity_bound': False},
                                {'actor_identity_bound': None}, {'to_agent': 'other'},
                                {'accepted_by': 'other'}):
                    malformed = events[:-1] + [replace(terminal, payload={**terminal.payload, **changes})]
                    with self.subTest(changes=changes), self.assertRaises(ValueError):
                        _validate_history(malformed, handoff.id)
                missing = dict(terminal.payload)
                missing.pop('actor_identity_bound')
                with self.assertRaises(ValueError):
                    _validate_history(events[:-1] + [replace(terminal, payload=missing)], handoff.id)
                duplicate = replace(terminal, id='event_' + 'f' * 24)
                with self.assertRaises(ValueError):
                    _validate_history(events + [duplicate], handoff.id)

    def test_tick_skew_boundary_and_folded_verdict(self):
        now = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)
        config = ProbeConfig(tick_components=('dispatcher',), transport=False)
        for offset, status, code in [(3600, 'clock_skew', 'tick_clock_skew'),
                                     (6, 'clock_skew', 'tick_clock_skew'),
                                     (5, 'fresh', None), (0, 'fresh', None),
                                     (-31, 'stale', 'tick_stale')]:
            with self.subTest(offset=offset), tempfile.TemporaryDirectory() as root:
                state = Path(root) / 'events.jsonl'
                state.touch()
                stamp = now + timedelta(seconds=offset)
                vault = Path(root) / 'vault'
                vault.mkdir()
                with authority_context(vault, state):
                    self.assertTrue(write_tick_record(state, component='dispatcher',
                                                      now=stamp, result='idle'))
                ticks, findings = check_ticks(state, now=now, config=config)
                self.assertEqual(status, ticks['dispatcher']['status'])
                self.assertEqual([] if code is None else [code], [f.code for f in findings])
                report = run_probe(state, routes={}, now=now, config=config, environ={})
                self.assertEqual('ok' if code is None else 'failed', report.verdict)
                # run_probe_command selects /fail exactly when this verdict is failed.
                if status == 'clock_skew':
                    self.assertNotIn('age_seconds', ticks['dispatcher'])
