"""Provider-free team authority and HTML boundary tests."""
import tempfile
import json
from pathlib import Path
import unittest

from arvyx_control.replica_authority import authority_context
from arvyx_control.cockpit_team import TeamAuthority, render_team
from arvyx_control.auth import issue_token, revoke_token


class TeamTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.vault = self.root / 'vault'
        self.vault.mkdir(mode=0o700)
        self.state = self.root / 'events.jsonl'
        self.enterContext(authority_context(self.vault, self.state))
        fixture_identity = 'fixture-operator'
        self.team = TeamAuthority(self.vault, self.state, bearer_secret=fixture_identity,
                                  authorization='Bearer ' + fixture_identity)

    def test_real_task_create_read_and_idempotency_fence(self):
        payload = {'title': 'Build fixture', 'owner': 'nova', 'idempotency_key': 'fixture-task-create-1'}
        result = self.team.action('task-create', payload)
        self.assertEqual(result.status, 201, result.body)
        tasks = self.team.read()['tasks']['tasks']
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]['owner'], 'nova')
        self.assertEqual(self.team.action('task-create', payload).status, 409)
        self.assertEqual(len(self.team.read()['tasks']['tasks']), 1)

    def test_missing_identity_never_enables_demo(self):
        team = TeamAuthority(self.vault, self.state)
        result = team.action('task-create', {'title': 'No', 'owner': 'nova', 'idempotency_key': 'no'})
        self.assertEqual(result.status, 401)
        self.assertFalse(self.state.exists())
        self.assertFalse(team.read()['availability']['tasks'])

    def test_unknown_action_actor_injection_and_command_execution_refused(self):
        for name, body in [('consume', {}), ('task-done', {}),
                           ('task-create', {'title': 'x', 'owner': 'nova', 'actor': 'operator', 'idempotency_key': 'x'})]:
            with self.assertRaises(ValueError):
                self.team.action(name, body)
        self.assertFalse(self.state.exists())

    def test_approval_is_explicit_and_does_not_execute(self):
        result = self.team.action('approval-request', {'command': 'printf fixture', 'requester': 'nova',
                                  'reason': 'local test', 'idempotency_key': 'fixture-approval-request-1'})
        self.assertEqual(result.status, 201, result.body)
        approval = self.team.read()['approvals']['approvals'][0]
        self.assertEqual(approval['status'], 'requested')
        self.assertIn('data-approve="' + approval['id'], render_team(self.team.read(), {'sessions': []}))
        with self.assertRaises(ValueError):
            self.team.action('approval-approve', {'id': approval['id'], 'confirm': 'wrong', 'idempotency_key': 'approve-1'})
        result = self.team.action('approval-approve', {'id': approval['id'], 'confirm': approval['id'], 'idempotency_key': 'test-000000000001'})
        self.assertEqual(result.status, 200, result.body)
        self.assertEqual(self.team.read()['approvals']['approvals'][0]['status'], 'approved')

    def test_memory_requires_explicit_consent(self):
        with self.assertRaises(ValueError):
            self.team.action('memory-recall', {'question': 'fixture', 'project': 'fixture', 'consent': False})

    def test_agent_cannot_approve_and_revocation_is_rechecked(self):
        directory = self.vault / 'registry/agents'
        directory.mkdir(parents=True)
        (directory / 'nova.json').write_text(json.dumps({'id': 'nova', 'scopes': ['control.read', 'control.write']}))
        token = issue_token(self.vault, 'nova').token
        agent = TeamAuthority(self.vault, self.state, authorization='Bearer ' + token)
        result = agent.action('approval-request', {'command': 'printf fixture', 'requester': 'nova',
                              'reason': 'local test', 'idempotency_key': 'agent-approval-request-1'})
        self.assertEqual(result.status, 201, result.body)
        identifier = result.body['approval']['id']
        result = agent.action('approval-approve', {'id': identifier, 'confirm': identifier,
                                                  'idempotency_key': 'agent-approval-denied-1'})
        self.assertEqual(result.status, 403, result.body)
        revoke_token(self.vault, 'nova')
        self.assertFalse(agent.read()['availability']['tasks'])

    def test_coordination_and_handoff_read_back_from_control_authority(self):
        result = self.team.action('organizer-post', {'title': 'Local coordination', 'body': 'No provider',
                                  'actor': 'operator', 'target': 'nova', 'idempotency_key': 'fixture-thread-post-1'})
        self.assertEqual(result.status, 201, result.body)
        self.assertEqual(self.team.read()['threads']['threads'][0]['title'], 'Local coordination')
        result = self.team.action('handoff-create', {'title': 'Review fixture', 'from_agent': 'nova',
                                  'to_agent': 'rowan', 'summary': 'Provider-free evidence',
                                  'idempotency_key': 'fixture-handoff-create-1'})
        self.assertEqual(result.status, 201, result.body)
        self.assertEqual(self.team.read()['handoffs']['handoffs'][0]['to_agent'], 'rowan')

    def test_render_escapes_all_authority_content_and_keeps_evidence_inert(self):
        model = {'availability': {'tasks': True}, 'tasks': {'tasks': [
            {'id': 't1', 'title': '<script>alert(1)</script>', 'owner': 'a', 'status': 'open'}]},
            'control': {'cards': [{'id': 'x', 'kind': 'thread', 'title': 'Review', 'lane': 'review',
                                    'evidence': {'artifact': 'javascript:alert(1)'}}]}}
        page = render_team(model, {'sessions': [], 'host': 'fixture'})
        self.assertNotIn('<script>', page)
        self.assertIn('&lt;script&gt;', page)
        self.assertNotIn('href="javascript:', page)
        self.assertIn('No native organizer conversation connected', page)
        self.assertIn('Long-term memory', page)


if __name__ == '__main__':
    unittest.main()
