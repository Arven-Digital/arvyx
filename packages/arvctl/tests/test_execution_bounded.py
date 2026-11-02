from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.replica_authority import authority_context
from arvyx_control.control import post_thread, read_events, _append_event_unlocked, _event
from arvyx_control.execution import claim_execution, materialize_executions, project_executions

NOW = datetime(2026, 9, 22, tzinfo=timezone.utc)


class BoundedExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / 'events.jsonl'
        self.vault = Path(self.tmp.name) / "vault"
        self.vault.mkdir()
        self.enterContext(authority_context(self.vault, self.state))

    def post(self, target='sage', bound=True):
        with patch('arvyx_control.control._now', return_value='2026-09-21T23:59:00Z'):
            return post_thread(self.state, title='bounded test', actor='keeper', target=target,
                               thread_type='ask', actor_identity_bound=bound).thread.id

    def claim(self, **kwargs):
        return claim_execution(self.state, worker='test', execution_capable_targets={'sage', 'juniper'},
                               now=NOW, target='sage', **kwargs)

    def test_exact_subject_leaves_all_unrelated_work_unchanged(self):
        for status in ('pending', 'held', 'dead_lettered', 'leased'):
            subject = self.post()
            item = next(item for item in materialize_executions(
                self.state, execution_capable_targets={'sage'}, now=NOW)
                if item.subject_id == subject)
            payload = item.to_dict()
            payload.update(status=status, lease_owner='unrelated-worker',
                           lease_expires_at='2026-09-21T00:00:00Z', attempts=3,
                           attempt_id=f'unrelated-{status}-attempt')
            _append_event_unlocked(self.state, _event('execution.held', item.id, NOW.isoformat(), payload))
        unmaterialized = self.post('juniper')
        chosen = self.post()
        before = project_executions(self.state)
        self.assertEqual(len(before), 4)
        self.assertEqual({item.status for item in before.values()},
                         {'pending', 'held', 'dead_lettered', 'leased'})
        events = read_events(self.state)
        result = self.claim(subject_id=chosen)
        self.assertEqual(result.subject_id, chosen)
        after = project_executions(self.state)
        self.assertEqual(len(after), 5)
        self.assertEqual({key: after[key] for key in before}, before)
        self.assertNotIn(unmaterialized, {item.subject_id for item in after.values()})
        self.assertTrue(all(e.task_id == result.id for e in read_events(self.state)[len(events):]))

    def test_nonexistent_foreign_unbound_and_empty_fail_without_writes(self):
        foreign, unbound = self.post('juniper'), self.post(bound=False)
        for selector in ({'subject_id': 'missing'}, {'execution_id': 'missing'},
                         {'subject_id': foreign}, {'subject_id': unbound}, {'subject_id': ''}):
            before = self.state.read_bytes()
            with self.assertRaises(ValueError):
                self.claim(**selector)
            self.assertEqual(self.state.read_bytes(), before)

    def test_expired_attempt_cannot_be_replayed_by_selector(self):
        subject = self.post()
        execution = claim_execution(self.state, worker='old', execution_capable_targets={'sage'},
                                    now=NOW - timedelta(minutes=5))
        before = self.state.read_bytes()
        with self.assertRaises(ValueError):
            self.claim(execution_id=execution.id)
        self.assertEqual(self.state.read_bytes(), before)

    def test_exact_execution_and_concurrent_claim_are_one_shot(self):
        subject = self.post()
        execution = materialize_executions(self.state, execution_capable_targets={'sage'}, now=NOW)[0]
        def attempt(_):
            with authority_context(self.vault, self.state):
                try:
                    return self.claim(execution_id=execution.id)
                except ValueError:
                    return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))
        self.assertEqual(sum(r is not None for r in results), 1)
        self.assertEqual(project_executions(self.state)[execution.id].attempts, 1)

    def test_cli_dispatch_is_exact_and_refusals_never_dispatch(self):
        import io
        import json
        import os
        from contextlib import redirect_stdout, redirect_stderr
        from arvyx_control.cli import main
        from arvyx_control.agent_delivery import AgentDeliveryResult
        old, chosen = self.post(), self.post()
        routes = Path(self.tmp.name) / 'routes.json'
        routes.write_text(json.dumps({'routes': {'sage': {
            'runtime': 'hermes-webhook', 'url_env': 'TEST_URL',
            'credential_env': 'TEST_SECRET', 'timeout_seconds': 1}}}))
        args = ['execution', 'worker', '--state', str(self.state), '--worker', 'test',
                '--routes', str(routes), '--target', 'sage', '--subject-id', chosen,
                '--now', '2026-09-22T00:00:00Z', '--json']
        with patch.dict(os.environ, {'TEST_URL': 'https://runtime.invalid/hook', 'TEST_SECRET': 'synthetic'}), \
             patch('arvyx_control.cli.deliver_execution_attempt', return_value=AgentDeliveryResult(True, 'accepted', 202, 'test')) as deliver, \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--authority-vault", str(self.vault), *args]), 0)
            self.assertEqual(deliver.call_args.args[0].subject_id, chosen)
            before = self.state.read_bytes()
            self.assertEqual(main(["--authority-vault", str(self.vault), *args]), 2)
            self.assertEqual(deliver.call_count, 1)
            self.assertEqual(self.state.read_bytes(), before)
        self.assertNotIn(old, {e.subject_id for e in project_executions(self.state).values()})

    def test_terminal_subject_refuses_and_unrelated_terminal_is_not_reconciled(self):
        old = self.post()
        item = materialize_executions(self.state, execution_capable_targets={'sage'}, now=NOW)[0]
        from arvyx_control.control import complete_thread
        complete_thread(self.state, old, actor='sage', actor_identity_bound=True)
        chosen = self.post()
        before = self.state.read_bytes()
        with self.assertRaises(ValueError):
            self.claim(subject_id=old)
        self.assertEqual(self.state.read_bytes(), before)
        self.claim(subject_id=chosen)
        self.assertEqual(project_executions(self.state)[item.id], item)

    def test_handoff_selection(self):
        from arvyx_control.control import create_handoff
        handoff = create_handoff(self.state, 'bounded', from_agent='keeper', to_agent='sage',
                                 actor_identity_bound=True).handoff
        self.assertEqual(self.claim(subject_id=handoff.id).subject_id, handoff.id)

    def test_health_labels_preserve_real_held_debt(self):
        from arvyx_control.control import acknowledge_thread, list_thread_inbox
        from arvyx_control.execution import hold_execution, queue_health
        from arvyx_control.api import _continuation_by_agent
        subject = self.post()
        with patch('arvyx_control.control._now', return_value='2026-09-21T20:00:00Z'):
            acknowledge_thread(self.state, subject, actor='sage', actor_identity_bound=True)
        item = materialize_executions(self.state, execution_capable_targets={'sage'}, now=NOW)[0]
        hold_execution(self.state, execution_id=item.id, held_by='operator', reason='awaiting input', now=NOW)
        health = queue_health(self.state, execution_capable_targets={'sage'}, now=NOW)
        self.assertEqual(health['assigned_without_live_execution'], [subject])
        self.assertEqual(health['acked_without_live_execution'], [subject])
        self.assertEqual(health['held_count'], 1)
        continuation = _continuation_by_agent(list_thread_inbox(self.state).threads, now=NOW)
        self.assertEqual(continuation['sage']['stale_count'], 1)

    def test_selector_requires_target_and_rejects_conflicting_ids(self):
        subject = self.post()
        before = self.state.read_bytes()
        with self.assertRaises(ValueError):
            claim_execution(self.state, worker='test', execution_capable_targets={'sage'}, subject_id=subject)
        with self.assertRaises(ValueError):
            self.claim(subject_id=subject, execution_id='missing')
        self.assertEqual(self.state.read_bytes(), before)
