"""Deterministic post-snapshot interleavings; intentionally not executed."""
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_watchdog import WatchdogTests, ROUTES, ENV_OK, T0
from arvyx_control.control import complete_thread
from arvyx_control.execution import (remediate_dead_letter, replay_execution, claim_execution,
                                     close_execution, project_executions)
from arvyx_control.replica_authority import authority_context
from arvyx_control.watchdog import run_watchdog, project_watchdog_tick


class RevisionTests(unittest.TestCase):
    _acked = WatchdogTests._acked
    _dead_letter = WatchdogTests._dead_letter

    def test_recovery_claim_closure_and_completion_win_before_conditional_write(self):
        for change in ('replay', 'claim', 'close', 'complete'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / 'events.jsonl'
                vault = Path(tmp) / 'vault'
                vault.mkdir()
                with authority_context(vault, state):
                    execution_id = self._dead_letter(state)
                    observed = project_executions(state)[execution_id]
                    recovered = []
                    def interleave(*args, **kwargs):
                        if change in {'replay', 'claim'}:
                            replay_execution(state, execution_id=execution_id, replayed_by='operator',
                                             now=T0 + timedelta(seconds=20))
                            if change == 'claim':
                                claim_execution(state, worker='fresh-worker', execution_capable_targets={'amir'},
                                                now=T0 + timedelta(seconds=21))
                        elif change == 'close':
                            close_execution(state, execution_id=execution_id, reason='explicit closure',
                                            closed_by='operator', resolution_category='obsolete')
                        else:
                            complete_thread(state, observed.subject_id, actor='amir', actor_identity_bound=True)
                        recovered.append(project_executions(state)[execution_id])
                        result = remediate_dead_letter(*args, **kwargs)
                        self.assertEqual('changed', result[0])
                        return result
                    with patch('arvyx_control.watchdog.remediate_dead_letter', side_effect=interleave):
                        tick = run_watchdog(state, routes=ROUTES, environ=ENV_OK,
                                            now=T0 + timedelta(seconds=30))
                    self.assertTrue(recovered)
                    self.assertEqual([], tick['held'])
                    self.assertEqual([], tick['replayed'])
                    self.assertTrue(project_watchdog_tick(state)['initialized'])
                    after = project_executions(state)[execution_id]
                    self.assertEqual(recovered[0], after)
                    if change == 'claim':
                        self.assertEqual('leased', after.status)
                        self.assertEqual('fresh-worker', after.lease_owner)
                        self.assertTrue(after.attempt_id)
