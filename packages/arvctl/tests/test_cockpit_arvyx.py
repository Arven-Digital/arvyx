"""Private local frontend adapter tests; Arvyx never becomes task authority."""
import hashlib
import tempfile
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from arvyx_control.cockpit_arvyx import frontend_environment, pane_binding, launch_plan
from arvyx_control.cockpit_arvyx import FocusBridge


def _authority_fixture(view=None):
    """Synthetic owner socket matching LocalCockpit.native_lifecycle's formats.

    'inspect' returns the owner identity dict and 'panes' returns the durable
    list of {session, pane, workspace, tab} rows (empty: no registered panes).
    """
    view = {'revision': 1, 'selected': 's2'} if view is None else view
    current = {'incarnation': 'synthetic-incarnation', 'epoch': 0}
    def request(home, operation, **fields):
        if operation == 'view':
            return dict(view)
        if operation == 'native_lifecycle' and fields.get('action') == 'inspect':
            return dict(current)
        if operation == 'native_lifecycle' and fields.get('action') == 'panes':
            assert fields.get('expected') == current and fields.get('confirmed') is True
            return []
        raise AssertionError(f'unexpected authority write {operation} {fields}')
    return request


@unittest.skipUnless(os.name == 'posix', 'the native runtime (Linux x86_64 artifact, host-shell policies) is POSIX-only')
class ArvyxFrontendTests(unittest.TestCase):
    def test_environment_does_not_inherit_provider_or_ssh_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict('os.environ', {'OPENAI_API_KEY': 'do-not-copy', 'SSH_AUTH_SOCK': '/private/socket'}):
                environment = frontend_environment(Path(directory))
            self.assertNotIn('OPENAI_API_KEY', environment)
            self.assertNotIn('SSH_AUTH_SOCK', environment)
            self.assertEqual(environment['HOME'], directory)

    def test_binding_requires_exact_existing_session(self):
        sessions = [{'id': 's-1', 'name': 'demo', 'project': 'amc', 'task': 't-1'}]
        self.assertEqual(pane_binding('s-1', sessions)['task'], 't-1')
        with self.assertRaises(ValueError):
            pane_binding('demo', sessions)
        with self.assertRaises(ValueError):
            pane_binding('s-2', sessions)

    def test_no_session_start_or_takeover_is_inferred(self):
        sessions = [{'id': 's-1', 'name': 'demo', 'project': 'amc', 'task': 't-1'}]
        plan = launch_plan(sessions)
        self.assertEqual(plan[0]['sid'], 's-1')
        self.assertEqual(plan[0]['label'], 'demo')
        self.assertNotIn('start', plan[0])
        self.assertNotIn('takeover', plan[0])

    def test_global_organizer_keeps_null_work_binding(self):
        organizer = {'id': 'o-1', 'name': 'Coordinator', 'kind': 'organizer',
                     'project': None, 'task': None, 'host': 'east'}
        binding = pane_binding('o-1', [organizer])
        self.assertEqual(binding['kind'], 'organizer')
        self.assertIsNone(binding['project'])
        self.assertIsNone(binding['task'])
        self.assertEqual(binding['host'], 'east')
        self.assertEqual(launch_plan([organizer])[0], binding)

    def test_organizer_does_not_weaken_work_or_identity_fences(self):
        organizer = {'id': 'east:' + 'a' * 32, 'name': 'Coordinator',
                     'kind': 'organizer', 'project': None, 'task': None, 'host': 'east'}
        self.assertEqual(launch_plan([organizer])[0]['sid'], organizer['id'])
        for changes in ({'kind': 'work'}, {'kind': 'unknown'}, {'project': 'amc'},
                        {'task': 't-1'}, {'host': ''}, {'host': 'west'},
                        {'id': ''}, {'name': ''}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                launch_plan([organizer | changes])
        with self.assertRaises(ValueError):
            launch_plan([organizer, organizer])

    def test_organizer_and_work_render_in_separate_host_scopes(self):
        import json
        from arvyx_control.cockpit_arvyx import open_frontend
        sessions = [
            {'id': 'o-1', 'name': 'Coordinator', 'kind': 'organizer', 'project': None, 'task': None},
            {'id': 'w-1', 'name': 'Build', 'kind': 'work', 'project': 'Organizer', 'task': 't-1'},
            {'id': 'o-2', 'name': 'Other coordinator', 'kind': 'organizer', 'project': None, 'task': None, 'host': 'west'},
        ]
        commands = []
        def command(argv, **kwargs):
            commands.append(argv)
            return json.dumps({'result': {'workspace': {'workspace_id': 'w'},
                                          'root_pane': {'pane_id': 'p' + str(len(commands))}}}).encode()
        def request(home, operation, **kwargs):
            return {'list': sessions, 'snapshot': {'host': 'east'}, 'native': None}[operation]
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            frontend = home / 'frontend'
            data = b'approved fixture bytes, never executed'
            with patch('arvyx_control.native_artifact_policy.read_native_bytes', return_value=data), \
                    patch('arvyx_control.native_artifact_policy.NATIVE_MOUSE_BINARY_SHA256', hashlib.sha256(data).hexdigest()), \
                    patch('arvyx_control.cockpit_client.request', side_effect=request), \
                    patch('arvyx_control.cockpit_arvyx.subprocess.Popen') as popen, \
                    patch('arvyx_control.cockpit_arvyx.subprocess.check_output', side_effect=command), \
                    patch('arvyx_control.cockpit_arvyx.subprocess.call', return_value=0), \
                    patch('arvyx_control.cockpit_arvyx.time.sleep', side_effect=lambda _: (frontend / '.config/herdr/sessions/amc').mkdir(parents=True, exist_ok=True) or (frontend / '.config/herdr/sessions/amc/herdr.sock').touch()):
                popen.return_value.poll.return_value = None
                self.assertEqual(open_frontend(home, frontend, Path(__file__)), 0)
            creates = [cmd for cmd in commands if cmd[3:5] == ['workspace', 'create']]
            self.assertEqual([cmd[cmd.index('--label') + 1] for cmd in creates],
                             ['east / Organizer', 'east / Organizer', 'west / Organizer'])
            bindings = json.loads((frontend / 'bindings.json').read_text())['bindings']
            self.assertEqual([item['sid'] for item in bindings], ['o-1', 'w-1', 'o-2'])
            self.assertIsNone(bindings[0]['task'])
            runs = [cmd for cmd in commands if cmd[3:5] == ['pane', 'run']]
            self.assertEqual(len(runs), 3)
            self.assertTrue(all('--sid' in cmd[-1] for cmd in runs))

    def test_missing_task_binding_fails_closed(self):
        with self.assertRaises(ValueError):
            launch_plan([{'id': 's-1', 'name': 'demo', 'project': 'amc'}])

    def test_duplicate_sessions_fail_closed(self):
        session = {'id': 's-1', 'name': 'demo', 'project': 'amc', 'task': 't-1'}
        with self.assertRaises(ValueError):
            launch_plan([session, session])

    def test_fleet_binding_retains_exact_host_and_qualified_session(self):
        sessions = [{'id': host + ':' + 'a' * 32, 'host': host,
                     'name': 'same-name', 'project': 'same-project', 'task': 'task'}
                    for host in ('fixture-east', 'fixture-west')]
        plan = launch_plan(sessions, 'coordinator')
        self.assertEqual([item['host'] for item in plan], ['fixture-east', 'fixture-west'])
        self.assertEqual([item['sid'] for item in plan], [item['id'] for item in sessions])

    def test_mismatched_fleet_host_is_not_rebound(self):
        with self.assertRaisesRegex(ValueError, 'does not match'):
            launch_plan([{'id': 'east:' + 'a' * 32, 'host': 'west',
                          'name': 'demo', 'project': 'amc', 'task': 'task'}])

    def test_shared_revision_wins_over_concurrent_local_focus(self):
        sync = FocusBridge({'p1': 's1', 'p2': 's2'})
        self.assertEqual(sync.decide('p1', {'revision': 1, 'selected': 's1'}), None)
        self.assertEqual(sync.decide('p2', {'revision': 2, 'selected': 's1'}), ('frontend', 'p1'))

    def test_human_focus_produces_revision_fenced_selection(self):
        sync = FocusBridge({'p1': 's1', 'p2': 's2'})
        sync.decide('p1', {'revision': 1, 'selected': 's1'})
        self.assertEqual(sync.decide('p2', {'revision': 1, 'selected': 's1'}), ('authority', 's2'))

    def test_delayed_frontend_focus_ack_never_reverses_shared_selection(self):
        sync = FocusBridge({'p1': 's1', 'p2': 's2'})
        sync.decide('p1', {'revision': 1, 'selected': 's1'})
        self.assertEqual(sync.decide('p1', {'revision': 2, 'selected': 's2'}), ('frontend', 'p2'))
        # Snapshot may still describe the previous frame after focus RPC success.
        self.assertIsNone(sync.decide('p1', {'revision': 2, 'selected': 's2'}))
        self.assertIsNone(sync.decide('p2', {'revision': 2, 'selected': 's2'}))
        self.assertEqual(sync.decide('p1', {'revision': 2, 'selected': 's2'}), ('authority', 's1'))

    def test_new_authority_revision_supersedes_pending_frontend_focus(self):
        sync = FocusBridge({'p1': 's1', 'p2': 's2'})
        sync.decide('p1', {'revision': 1, 'selected': 's2'})
        self.assertIsNone(sync.decide('p1', {'revision': 2, 'selected': 's1'}))
        self.assertEqual(sync.decide('p2', {'revision': 2, 'selected': 's1'}), ('authority', 's2'))

    def test_closed_pane_is_not_an_actionable_focus_target(self):
        sync = FocusBridge({'p1': 's1', 'p2': 's2'})
        self.assertIsNone(sync.decide('p1', {'revision': 1, 'selected': 's2'}, available={'p1'}))

    def test_watcher_does_not_write_authority_from_stale_frontend_frame(self):
        import json
        from arvyx_control.cockpit_arvyx import _watch_focus
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / 'bindings.json'
            record.write_text(json.dumps({'authority_home': directory, 'bindings': [
                {'pane': 'p1', 'sid': 's1'}, {'pane': 'p2', 'sid': 's2'}]}))
            def command(argv, **kwargs):
                if argv[-2:] == ['api', 'snapshot']:
                    return json.dumps({'result': {'snapshot': {'panes': [
                        {'pane_id': p, 'focused': p == 'p1', 'workspace_id': 'w', 'tab_id': p}
                        for p in ('p1', 'p2')]}}}).encode()
                return b'{}'
            with patch('arvyx_control.cockpit_arvyx.subprocess.check_output', side_effect=command) as commands, \
                    patch('arvyx_control.cockpit_client.request', side_effect=_authority_fixture()) as authority, \
                    patch('arvyx_control.cockpit_client.exchange', return_value=b'{"id":"amc:pane:focus","result":{"pane":{"pane_id":"p2"}}}') as focus, \
                    patch('arvyx_control.cockpit_arvyx.time.sleep', side_effect=[None, OSError('end test')]):
                from unittest.mock import Mock
                native = Mock()
                native.invoke.side_effect = lambda operation, args, **kwargs: operation(['/proc/self/fd/fixture', *args], pass_fds=(123,), **kwargs)
                _watch_focus(record, native, record=json.loads(record.read_text()))
            focus.assert_called_once()
            self.assertEqual(commands.call_count, 4)  # two snapshots, one workspace/tab focus
            self.assertEqual([call.args[1] for call in authority.call_args_list if call.args[1] == 'view'], ['view', 'view'])
            # Every loop re-reads the owner's durable pane map under the exact
            # inspected incarnation; it is never a focus-authority write.
            self.assertEqual([call.kwargs.get('action') for call in authority.call_args_list if call.args[1] != 'view'],
                             ['inspect', 'panes', 'inspect', 'panes'])

    def test_watcher_handles_closed_bound_pane_without_stopping(self):
        import json
        from arvyx_control.cockpit_arvyx import _watch_focus
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / 'bindings.json'
            record.write_text(json.dumps({'authority_home': directory,
                                         'bindings': [{'pane': 'closed', 'sid': 's2'}]}))
            snapshot = {'result': {'snapshot': {'panes': [
                {'pane_id': 'private', 'focused': True, 'workspace_id': 'w', 'tab_id': 't'}]}}}
            with patch('arvyx_control.cockpit_arvyx.subprocess.check_output', return_value=json.dumps(snapshot).encode()) as commands, \
                    patch('arvyx_control.cockpit_client.request', side_effect=_authority_fixture()) as authority, \
                    patch('arvyx_control.cockpit_arvyx.time.sleep', side_effect=[None, OSError('end test')]):
                from unittest.mock import Mock
                native = Mock()
                native.invoke.side_effect = lambda operation, args, **kwargs: operation(['/proc/self/fd/fixture', *args], pass_fds=(123,), **kwargs)
                _watch_focus(record, native, record=json.loads(record.read_text()))
            self.assertEqual(commands.call_count, 2)
            self.assertEqual([call.args[1] for call in authority.call_args_list if call.args[1] == 'view'], ['view', 'view'])
            # Every loop re-reads the owner's durable pane map under the exact
            # inspected incarnation; it is never a focus-authority write.
            self.assertEqual([call.kwargs.get('action') for call in authority.call_args_list if call.args[1] != 'view'],
                             ['inspect', 'panes', 'inspect', 'panes'])

    def test_unbound_private_shell_does_not_change_authority(self):
        sync = FocusBridge({'p1': 's1'})
        sync.decide('p1', {'revision': 1, 'selected': 's1'})
        self.assertEqual(sync.decide('private-shell', {'revision': 1, 'selected': 's1'}), None)

    def test_watcher_uses_exact_document_verified_before_focus_loop(self):
        import json
        from arvyx_control.cockpit_arvyx import watch_focus
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / 'bindings.json'
            document = {'authority_home': directory, 'binary_sha256': 'verified', 'bindings': []}
            record.write_text(json.dumps(document))
            with patch('arvyx_control.native_artifact_policy.VerifiedNative') as verified, patch('arvyx_control.cockpit_arvyx._watch_focus') as loop:
                def entered():
                    record.write_text(json.dumps(document | {'authority_home': '/replacement'}))
                    return verified.return_value
                verified.return_value.__enter__.side_effect = entered
                watch_focus(record, None, native_fd=123)
                verified.assert_called_once_with(None, document, inherited_fd=123)
                loop.assert_called_once_with(record, verified.return_value, record=document)

    def test_failed_native_server_spawn_closes_log_and_preserves_failure(self):
        from unittest.mock import Mock
        from arvyx_control.cockpit_arvyx import _open_frontend
        native = Mock(digest='verified')
        native.invoke.side_effect = OSError('spawn failed')
        sessions = [{'id': 's', 'name': 'S', 'project': 'P', 'task': 'T'}]
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            with patch('arvyx_control.cockpit_client.request', side_effect=[sessions, {'host': 'local'}]):
                with self.assertRaisesRegex(OSError, 'spawn failed'):
                    _open_frontend(home, home / 'frontend', native)
            self.assertTrue(native.invoke.call_args.kwargs['stdout'].closed)
            self.assertEqual(native.invoke.call_count, 1)

    def test_watcher_cli_closes_original_inherited_fd_on_verification_failure(self):
        from arvyx_control.cockpit_arvyx import main
        argv = ['cockpit', '--home', '/owner', '--watch-bindings', '/binding', '--native-fd', '123']
        with patch('sys.argv', argv), patch('arvyx_control.cockpit_arvyx.watch_focus', side_effect=ValueError('refused')) as watch, patch('arvyx_control.cockpit_arvyx.os.close') as close:
            with self.assertRaisesRegex(ValueError, 'refused'):
                main()
            watch.assert_called_once_with(Path('/binding'), None, native_fd=123)
            close.assert_called_once_with(123)
