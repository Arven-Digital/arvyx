"""Unexecuted regression coverage for the watchdog producer/consumer contract."""
import unittest

from test_operator_alert_dismissal import AlertDismissalTests
from arvyx_control.agent_delivery import AgentRoute
from arvyx_control.control import read_events, _project_threads, read_thread
from arvyx_control.execution import close_execution
from arvyx_control.watchdog import run_watchdog
from arvyx_control.watchdog_alerts import hold_alert_body, operator_hold_alert_bodies


class ExactFormatTests(unittest.TestCase):
    def test_only_canonical_and_historical_undotted(self):
        fields = dict(target='demo', subject_type='thread', subject_id='thread_demo', hold_reason='exact.')
        canonical = hold_alert_body(**fields)
        bodies = operator_hold_alert_bodies(**fields)
        self.assertEqual(('target=demo subject=thread thread_demo; exact..',
                          'target=demo subject=thread thread_demo; exact.'), bodies)
        self.assertEqual(canonical, bodies[0])
        for altered in (canonical + '.', canonical + ' suffix', canonical + ' Investigate',
                        canonical.replace('exact', 'changed'), canonical + '\n'):
            self.assertNotIn(altered, bodies)


class RealProducerTests(unittest.TestCase):
    request = AlertDismissalTests.request
    apply = AlertDismissalTests.apply

    def setUp(self):
        import tempfile
        from datetime import datetime, timedelta, timezone
        from pathlib import Path
        from arvyx_control.replica_authority import authority_context
        from arvyx_control.control import post_thread
        from arvyx_control.execution import claim_execution, project_executions, replay_execution
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / 'events.jsonl'
        self.vault = Path(self.tmp.name) / 'vault'
        self.vault.mkdir()
        self.enterContext(authority_context(self.vault, self.state))
        self.subject = post_thread(self.state, title='Synthetic work', actor='operator',
            target='demobot', thread_type='ask', body='Synthetic work',
            actor_identity_bound=True).thread
        # The watchdog pages the operator only for a HOLD it applied itself
        # (exhausted replay budget) or a worker repeated-BLOCKED HOLD; a manual
        # operator HOLD is never paged back to the operator. Drive the real
        # lease-exhaustion path so the page under test is actual producer output.
        t0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
        capable = {'demobot'}
        def claim(offset):
            return claim_execution(self.state, worker='fixture-worker', execution_capable_targets=capable,
                now=t0 + timedelta(seconds=offset), lease_seconds=1, max_attempts=1)
        self.execution = claim(0)
        self.assertIsNotNone(self.execution)
        self.assertIsNone(claim(16))
        replay_execution(self.state, execution_id=self.execution.id, now=t0 + timedelta(seconds=17))
        claim(20)
        claim(36)
        self.assertEqual('dead_lettered', project_executions(self.state)[self.execution.id].status)
        routes = {'demobot': AgentRoute('demobot', 'hermes-webhook', 'DEMO_URL', 'DEMO_SECRET')}
        environ = {'DEMO_URL': 'https://runtime.invalid/hook', 'DEMO_SECRET': 'synthetic-only'}
        report = run_watchdog(self.state, routes=routes, environ=environ, probe=False,
                              now=t0 + timedelta(seconds=100))
        self.assertEqual([self.execution.id], report['escalated'])
        held = project_executions(self.state)[self.execution.id]
        self.assertEqual('held', held.status)
        self.alert = next(t for t in _project_threads(self.state).values()
                          if t.actor == 'arvyx-watchdog' and t.target == 'operator'
                          and t.title == f'[watchdog] execution {self.execution.id} held for operator')
        fields = dict(target='demobot', subject_type='thread', subject_id=self.subject.id,
                      hold_reason=held.hold_reason)
        self.assertEqual(hold_alert_body(**fields), self.alert.body)
        self.assertEqual(operator_hold_alert_bodies(**fields)[0], self.alert.body)
        self.assertTrue(self.alert.body.endswith(held.hold_reason + '.'))
        close_execution(self.state, execution_id=self.execution.id, reason='Synthetic explicit closure',
                        closed_by='operator', resolution_category='no_longer_actionable')

    def test_real_page_dryrun_apply_readback_retry(self):
        request = self.request()
        before = self.state.read_bytes()
        self.assertFalse(self.apply(request)['changed'])
        self.assertEqual(before, self.state.read_bytes())
        first = self.apply(request, dry_run=False)
        read_thread(self.state, self.alert.id)
        self.assertFalse(self.apply(request, dry_run=False)['changed'])
        self.assertEqual('retired', _project_threads(self.state)[self.alert.id].status)
        self.assertFalse(first['record']['done_at'])
        self.assertEqual(1, sum(e.type == 'thread.operator_archived' and e.task_id == self.alert.id
                               for e in read_events(self.state)))
