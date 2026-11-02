# Regression source only; not executed in this fix lane.
from datetime import datetime, timezone
from pathlib import Path
import io
import json
import tempfile
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from arvyx_control.api import handle_api_request
from arvyx_control.auth import issue_token
from arvyx_control.control import list_thread_inbox, post_thread, same_agent_identity
from arvyx_control.execution import (
    cancel_execution, claim_execution, hold_execution, materialize_executions,
    project_executions, reconcile_executions, replay_execution, resume_execution,
)
from arvyx_control.replica_authority import authority_context
from arvyx_control.vault import init_vault

NOW = datetime(2026, 10, 28, tzinfo=timezone.utc)


class ExecutionIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / 'events.jsonl'
        self.vault = Path(self.tmp.name) / 'vault'
        self.enterContext(authority_context(self.vault, self.state))
        init_vault(self.vault)
        (self.vault / 'registry/agents/nova.json').write_text(json.dumps({
            'id': 'nova', 'scopes': ['control.read', 'control.write']}))
        self.sender = issue_token(self.vault, 'demobot', scopes=['control.read', 'control.write']).token
        self.owner = issue_token(self.vault, 'nova', scopes=['control.read', 'control.write']).token

    def api(self, method, path, body=None, token=None):
        return handle_api_request(
            method=method, path=path, body=body, state=self.state, vault=self.vault,
            authorization=f'Bearer {token or self.owner}',
            idempotency_key=f'latest15-{uuid.uuid4().hex}' if method == 'POST' else None,
        )

    def root(self, target='nova'):
        with patch('arvyx_control.control._now', return_value='2026-10-28T00:00:00Z'):
            subject = post_thread(self.state, title='Synthetic identity regression', actor='demobot',
                                  target=target, thread_type='ask', actor_identity_bound=True).thread.id
        roots = materialize_executions(self.state, execution_capable_targets={'nova'}, now=NOW)
        return next(root for root in roots if root.subject_id == subject)

    def change_history(self, root, history):
        if history in {'held', 'replayed'}:
            hold_execution(self.state, execution_id=root.id, reason='synthetic hold', held_by='operator', now=NOW)
            if history == 'replayed':
                replay_execution(self.state, execution_id=root.id, now=NOW)
        else:
            cancel_execution(self.state, execution_id=root.id, reason='synthetic pause', cancelled_by='operator', now=NOW)
            if history == 'resumed':
                resume_execution(self.state, execution_id=root.id, resumed_by='operator', now=NOW)

    def test_exact_selectors_reject_never_attempted_recovery_history_without_dispatch(self):
        from arvyx_control.cli import main
        routes = Path(self.tmp.name) / 'routes.json'
        routes.write_text(json.dumps({'routes': {'nova': {
            'runtime': 'hermes-webhook', 'url_env': 'TEST_URL',
            'credential_env': 'TEST_SECRET', 'timeout_seconds': 1}}}))
        for history in ('held', 'replayed', 'paused', 'resumed'):
            root = self.root()
            self.change_history(root, history)
            self.assertEqual(project_executions(self.state)[root.id].attempts, 0)
            for selector, value in (('execution_id', root.id), ('subject_id', root.subject_id)):
                with self.subTest(history=history, selector=selector):
                    before = self.state.read_bytes()
                    with self.assertRaises(ValueError):
                        claim_execution(self.state, worker='test', execution_capable_targets={'nova'},
                                        target='nova', now=NOW, **{selector: value})
                    self.assertEqual(before, self.state.read_bytes())
                    with patch.dict('os.environ', {'TEST_URL': 'https://runtime.invalid/hook', 'TEST_SECRET': 'synthetic'}), \
                         patch('arvyx_control.cli.deliver_execution_attempt') as delivery, \
                         redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        result = main(['--authority-vault', str(self.vault), 'execution', 'worker',
                                       '--state', str(self.state), '--worker', 'test', '--routes', str(routes),
                                       '--target', 'nova', '--' + selector.replace('_', '-'), value,
                                       '--now', '2026-10-28T00:00:00Z', '--json'])
                        self.assertEqual(result, 2)
                        delivery.assert_not_called()
                    self.assertEqual(before, self.state.read_bytes())

    def test_ordinary_worker_retains_replay_and_resume_and_exact_accepts_untouched_pending(self):
        for history in ('replayed', 'resumed', 'untouched'):
            with self.subTest(history=history):
                root = self.root()
                if history != 'untouched':
                    self.change_history(root, history)
                selector = {'execution_id': root.id, 'target': 'nova'} if history == 'untouched' else {}
                claimed = claim_execution(self.state, worker='ordinary', execution_capable_targets={'nova'},
                                          now=NOW, **selector)
                self.assertEqual(claimed.id, root.id)
                self.assertEqual(claimed.attempts, 1)
                self.assertEqual(claimed.status, 'leased')

    def test_historical_mixed_case_target_http_lifecycle_preserves_literals(self):
        # Domain-created history predates these HTTP calls; never rewrite it.
        root = self.root('Nova')
        before = self.state.read_bytes()
        for path in ('/threads', '/threads?target=Nova', '/threads?agent=NOVA', '/threads/pending?target=nova'):
            response = self.api('GET', path)
            self.assertEqual(response.status, 200, response.body)
            self.assertEqual([t['id'] for t in response.body['threads']], [root.subject_id])
            self.assertEqual(response.body['threads'][0]['target'], 'Nova')
        self.assertEqual(before, self.state.read_bytes())
        read = self.api('POST', '/threads/read-all', {'target': 'Nova', 'include_pending': True})
        self.assertEqual(read.status, 200, read.body)
        self.assertEqual([t['id'] for t in read.body['threads']], [root.subject_id])
        claimed = claim_execution(self.state, worker='ordinary', execution_capable_targets={'nova'}, now=NOW)
        self.assertEqual(claimed.target, 'nova')
        for action in ('ack', 'done'):
            response = self.api('POST', f'/threads/{root.subject_id}/{action}', {})
            self.assertEqual(response.status, 200, response.body)
            self.assertEqual(response.body['thread']['target'], 'Nova')
            self.assertEqual(response.body['thread']['id'], root.subject_id)
        reconcile_executions(self.state, now=NOW)
        self.assertEqual(project_executions(self.state)[root.id].status, 'completed')
        self.assertTrue(self.state.read_bytes().startswith(before))

    def test_http_producer_accepts_same_identity_and_foreign_and_broadcast_stay_denied(self):
        response = self.api('POST', '/threads', {'title': 'Synthetic mixed spelling', 'target': 'Nova',
                                                 'type': 'ask'}, token=self.sender)
        self.assertEqual(response.status, 201, response.body)
        subject = response.body['thread']['id']
        self.assertEqual(response.body['thread']['target'], 'Nova')
        self.assertIn(subject, [t.id for t in list_thread_inbox(self.state, 'nova').threads])
        # Exact source ownership uses the same comparator, but canonical selector is mandatory.
        claimed = claim_execution(self.state, worker='canary', execution_capable_targets={'nova'},
                                  subject_id=subject, target='nova', now=NOW)
        self.assertEqual(claimed.target, 'nova')
        foreign = post_thread(self.state, title='Foreign', actor='demobot', target='Uma', thread_type='ask').thread
        broadcast = post_thread(self.state, title='Broadcast', actor='demobot', target='all', thread_type='status').thread
        for path in ('/threads?target=uma', '/threads?target=UMA', '/threads?target=all', '/threads/pending?agent=Uma'):
            self.assertEqual(self.api('GET', path).status, 403)
        self.assertEqual(self.api('POST', '/threads/read-all', {'target': 'UMA'}).status, 403)
        for thread in (foreign, broadcast):
            for action in ('ack', 'done'):
                self.assertEqual(self.api('POST', f'/threads/{thread.id}/{action}', {}).status, 403)

    def test_canonical_comparator_has_no_empty_or_broadcast_ownership(self):
        self.assertTrue(same_agent_identity('Nova', 'nova'))
        for left, right in (('', ''), ('all', 'ALL'), ('Nova', 'uma'), (None, 'nova')):
            self.assertFalse(same_agent_identity(left, right))

    def test_mixed_case_ownership_does_not_casefold_completion_evidence(self):
        response = self.api('POST', '/threads', {'title': 'Literal evidence', 'target': 'Nova', 'type': 'ask',
                                                 'completion_artifact': 'Synthetic/Proof.md',
                                                 'completion_anchor': 'ExactAnchor'}, token=self.sender)
        self.assertEqual(response.status, 201, response.body)
        subject = response.body['thread']['id']
        rejected = self.api('POST', f'/threads/{subject}/done', {
            'evidence_artifact': 'synthetic/proof.md', 'evidence_anchor': 'ExactAnchor',
            'evidence_method': 'direct-read'})
        self.assertEqual(rejected.status, 400)
        accepted = self.api('POST', f'/threads/{subject}/done', {
            'evidence_artifact': 'Synthetic/Proof.md', 'evidence_anchor': 'ExactAnchor',
            'evidence_method': 'direct-read'})
        self.assertEqual(accepted.status, 200, accepted.body)
