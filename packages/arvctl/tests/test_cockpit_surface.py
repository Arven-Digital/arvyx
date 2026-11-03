from arvyx_control.local_executor import ExecutionPolicy
from arvyx_control.replica_authority import authority_context
import tempfile
import os
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

from arvyx_control import cockpit_client, control
from arvyx_control.cockpit import LocalCockpit
from arvyx_control import cockpit_surface


@unittest.skipUnless(os.name == 'posix', 'PTY owner, curses surface, fork or pidfd semantics are POSIX-only')
class SurfaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'pilot'
        cockpit_client.initialize(self.root)
        self.service = LocalCockpit(self.root / 'runtime', self.root / 'vault', self.root / 'events.jsonl', 'laptop-a', execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))
        self.addCleanup(lambda: self.service.close())

    def session(self, name):
        with authority_context(self.root / 'vault', self.root / 'events.jsonl'):
            task = control.create_task(self.root / 'events.jsonl', name, owner='demobot').task
        return self.service.open(project='demo-agent', task=task.id, name=name, actor='operator')

    def test_shared_selection_compare_and_swap_and_restart(self):
        first, second = self.session('first'), self.session('second')
        view = self.service.view()
        selected = self.service.select(first['id'], revision=view['revision'], actor='operator')
        self.assertEqual(selected['selected'], first['id'])
        with self.assertRaisesRegex(ValueError, 'stale'):
            self.service.select(second['id'], revision=view['revision'], actor='operator')
        self.service.close()
        self.service = LocalCockpit(self.root / 'runtime', self.root / 'vault', self.root / 'events.jsonl', 'laptop-a', execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))
        self.assertEqual(self.service.view()['selected'], first['id'])

    def test_unknown_selection_does_not_change_revision(self):
        before = self.service.view()
        with self.assertRaises(ValueError):
            self.service.select('missing', revision=before['revision'], actor='operator')
        self.assertEqual(self.service.view(), before)

    def test_operator_status_distinguishes_authority_from_execution(self):
        session = self.session('authority')
        self.service.delegate(session['id'], operator='rowan', goal='inspect', limits='local only', actor='operator')
        for state in ('active', 'paused', 'ambiguous', 'revoked', 'review'):
            with self.subTest(state=state):
                self.service.db.execute('UPDATE delegations SET status=? WHERE session=?', (state, session['id']))
                self.service.db.commit()
                model = self.service.snapshot(actor='operator')
                self.assertEqual(model['operator_status']['delegations'], {state: 1})
                self.assertEqual(model['operator_status']['runner'], 'not configured')
                self.assertEqual(model['operator_status']['provider_activity'], 'not observed')
                page = cockpit_surface.render_dashboard(model)
                self.assertIn(state + ': 1', page)
                self.assertNotIn('No Autopilot', page)

    def test_dashboard_escapes_workspace_and_task_title(self):
        session = self.session('first')
        model = {'sessions': [dict(session, workspace='<script>alert(1)</script>')],
                 'tasks': [{'id': session['task'], 'title': '<img src=x onerror=alert(1)>', 'status': 'open', 'owner': 'demobot'}],
                 'view': {'selected': session['id'], 'revision': 1}, 'host': 'laptop-a'}
        page = cockpit_surface.render_dashboard(model)
        self.assertNotIn('<script>', page)
        self.assertIn('&lt;img', page)
        self.assertIn('Local pilot', page)
        self.assertIn(session['task'], page)

    def test_terminal_labels_strip_control_sequences(self):
        self.assertEqual(cockpit_surface.label('hello\x1b[2J\nworld'), 'hello?[2J?world')

    def test_private_shell_never_calls_shared_owner_or_inherits_provider_environment(self):
        with patch.object(cockpit_surface, 'request') as rpc, \
             patch('sys.stdin.isatty', return_value=True), \
             patch('sys.stdout.isatty', return_value=True), \
             patch('subprocess.run') as run:
            cockpit_surface.private_shell()
            rpc.assert_not_called()
            self.assertEqual(run.call_args.args[0], ['/bin/sh', '-i'])
            self.assertEqual(set(run.call_args.kwargs['env']), {'PATH', 'HOME', 'TERM', 'ENV', 'PS1'})
            self.assertEqual(run.call_args.kwargs['cwd'], Path.cwd())

    def test_web_button_reuses_one_owner_dashboard_and_closes_with_owner(self):
        first = self.service.dashboard(actor='operator')
        second = self.service.dashboard(actor='operator')
        self.assertEqual(first, second)
        self.assertTrue(first['url'].startswith('http://127.0.0.1:'))
        server = self.service.web_server
        self.service.close()
        self.assertEqual(server.fileno(), -1)

    def test_dashboard_does_not_emit_terminal_output(self):
        page = cockpit_surface.render_dashboard({'sessions': [], 'tasks': [], 'view': {'selected': None, 'revision': 0}, 'host': 'local'})
        self.assertIn('No sessions', page)
        self.assertIn('No tasks', page)
        self.assertNotIn('contenteditable', page)

    def test_offline_navigation_never_queues_or_sends_input(self):
        screen = MagicMock()
        screen.getmaxyx.return_value = (24, 80)
        screen.getch.side_effect = [ord('j'), 10, ord('e'), ord('q')]
        with patch.object(cockpit_surface.curses, 'curs_set'), \
             patch.object(cockpit_surface, 'snapshot', side_effect=OSError('offline')), \
             patch.object(cockpit_surface, 'request') as requests:
            self.assertIsNone(cockpit_surface._navigate(screen, self.root))
            requests.assert_not_called()

    def test_end_cancel_does_not_stop_shell(self):
        session = self.session('first')
        screen = MagicMock()
        screen.getmaxyx.return_value = (24, 80)
        screen.getch.side_effect = [ord('e'), ord('n'), ord('q')]
        model = {'sessions': [session], 'view': {'selected': session['id'], 'revision': 1}}
        with patch.object(cockpit_surface.curses, 'curs_set'), \
             patch.object(cockpit_surface, 'snapshot', return_value=model), \
             patch.object(cockpit_surface, 'export_dashboard'), \
             patch.object(cockpit_surface, 'request') as requests:
            self.assertIsNone(cockpit_surface._navigate(screen, self.root))
            requests.assert_not_called()

    def test_first_attach_sets_shared_selection_before_input(self):
        session = dict(self.session('first'), status='running')
        screen = MagicMock()
        screen.getmaxyx.return_value = (24, 80)
        screen.getch.return_value = 10
        model = {'sessions': [session], 'view': {'selected': None, 'revision': 0}}
        with patch.object(cockpit_surface.curses, 'curs_set'), \
             patch.object(cockpit_surface, 'snapshot', return_value=model), \
             patch.object(cockpit_surface, 'export_dashboard'), \
             patch.object(cockpit_surface, 'request') as requests:
            self.assertEqual(cockpit_surface._navigate(screen, self.root), session['id'])
            requests.assert_called_once_with(self.root, 'select', sid=session['id'], revision=0, actor='operator')
