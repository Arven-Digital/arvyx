"""Lane 07 regressions: disposable state and mocked process/socket edges only."""
import json
from pathlib import Path
import subprocess
import tempfile
import os
import unittest
from unittest.mock import Mock, patch

from arvyx_control import cockpit_arvyx as frontend


@unittest.skipUnless(os.name == 'posix', 'the PTY owner fixture (host-environment natives) is POSIX-only')
class ExactPaneFocusTests(unittest.TestCase):
    def run_watcher(self, *, reply=None, failure=None, frames=('sibling', 'sibling', 'bound', 'sibling')):
        events = []
        snapshots = iter(frames)
        requests = []
        native = Mock()
        # This socket is never connected: exercise the real bounded JSON framing
        # with a mocked stream, including a fragmented response.
        stream = Mock()
        stream.__enter__ = Mock(return_value=stream)
        stream.__exit__ = Mock(return_value=False)
        if reply is None:
            reply = {'id': 'amc:pane:focus', 'result': {'pane': {'pane_id': 'bound', 'focused': True}}}
        wire = json.dumps(reply).encode() + b'\n'
        stream.recv.side_effect = [wire[:9], wire[9:]]

        def send(payload):
            request = json.loads(payload)
            requests.append(request)
            events.append(('rpc', request['method'], request['params']['pane_id']))
            if failure is not None:
                raise failure
        stream.sendall.side_effect = send

        def invoke(operation, args, **kwargs):
            self.assertIs(operation, subprocess.check_output)
            self.assertEqual(args[:2], ['--session', 'amc'])
            self.assertEqual(kwargs['timeout'], 5)
            args = args[2:]
            if args == ['api', 'snapshot']:
                focused = next(snapshots)
                events.append(('snapshot', focused))
                return json.dumps({'result': {'snapshot': {'panes': [
                    {'pane_id': pane, 'workspace_id': 'w', 'tab_id': 't', 'focused': pane == focused}
                    for pane in ('bound', 'sibling')]}}}).encode()
            events.append(tuple(args))
            return b'{}'
        native.invoke.side_effect = invoke

        view = {'revision': 7, 'selected': 's-bound', 'panels': ['s-bound', 's-sibling']}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {'authority_home': str(root / 'owner'), 'bindings': [
                {'pane': 'bound', 'sid': 's-bound'}, {'pane': 'sibling', 'sid': 's-sibling'}]}
            # The watcher digests the exact binding document it was launched with.
            (root / 'bindings.json').write_text(json.dumps(record))
            current = {'incarnation': 'synthetic-incarnation', 'epoch': 0}

            def owner(home, operation, **fields):
                # Formats match LocalCockpit.native_lifecycle: inspect -> identity
                # dict, panes -> durable [{session, pane, workspace, tab}] rows.
                if operation == 'native_lifecycle' and fields.get('action') == 'inspect':
                    return dict(current)
                if operation == 'native_lifecycle' and fields.get('action') == 'panes':
                    self.assertEqual((fields['expected'], fields['confirmed']), (current, True))
                    return []
                if operation in ('view', 'layout'):
                    return dict(view)
                raise AssertionError(f'unexpected owner request {operation}')
            with patch('arvyx_control.cockpit_client.socket.socket', return_value=stream) as socket_factory, \
                    patch('arvyx_control.cockpit_client.request', side_effect=owner) as authority, \
                    patch.object(frontend.time, 'sleep', side_effect=[None] * (len(frames) - 1) + [OSError('fixture complete')]):
                frontend._watch_focus(root / 'bindings.json', native, record=record)
            if socket_factory.called:
                stream.connect.assert_called_once_with(str(root / '.config/herdr/sessions/amc/herdr.sock'))
                self.assertTrue(stream.__exit__.called)
                self.assertTrue(all(0 < call.args[0] <= 5 for call in stream.settimeout.call_args_list))
        return events, requests, authority

    def test_07_01_exact_split_pane_focus_waits_for_observation_then_allows_human_selection(self):
        events, requests, authority = self.run_watcher()
        self.assertEqual(requests, [{'id': 'amc:pane:focus', 'method': 'pane.focus', 'params': {'pane_id': 'bound'}}])
        self.assertEqual(events[:4], [('snapshot', 'sibling'), ('workspace', 'focus', 'w'),
                                     ('tab', 'focus', 't'), ('rpc', 'pane.focus', 'bound')])
        # The stale post-ack frame must not reverse selection. Observing the
        # target clears pending focus; only the later human change writes layout.
        self.assertEqual([call.args[1] for call in authority.call_args_list if call.args[1] != 'native_lifecycle'],
                         ['view', 'view', 'view', 'view', 'layout'])
        self.assertEqual(authority.call_args.kwargs,
                         dict(panels=['s-bound', 's-sibling'], selected='s-sibling', revision=7, actor='operator'))

    def test_07_01_uncertain_focus_is_not_retried_or_written_back(self):
        for failure in (OSError('uncertain send'), TimeoutError('deadline')):
            with self.subTest(failure=failure):
                events, requests, authority = self.run_watcher(failure=failure)
                self.assertEqual(len(requests), 1)
                self.assertEqual(sum(event[0] == 'snapshot' for event in events), 1)
                self.assertEqual([call.args[1] for call in authority.call_args_list if call.args[1] != 'native_lifecycle'], ['view'])

    def test_07_01_rejects_error_mismatched_or_malformed_focus_ack_without_retry(self):
        for reply in (
            {'id': 'amc:pane:focus', 'error': {'code': 'pane_not_found'}},
            {'id': 'wrong', 'result': {'pane': {'pane_id': 'bound'}}},
            {'id': 'amc:pane:focus', 'result': {'pane': {'pane_id': 'sibling'}}},
            {'id': 'amc:pane:focus', 'result': []},
            [],
        ):
            with self.subTest(reply=reply):
                events, requests, authority = self.run_watcher(reply=reply)
                self.assertEqual(len(requests), 1)
                self.assertEqual(sum(event[0] == 'snapshot' for event in events), 1)
                self.assertEqual([call.args[1] for call in authority.call_args_list if call.args[1] != 'native_lifecycle'], ['view'])


@unittest.skipUnless(os.name == 'posix', 'the PTY owner fixture (host-environment natives) is POSIX-only')
class AttachCleanupTests(unittest.TestCase):
    def run_open(self, attach_status=0, *, attach_error=None, cleanup_errors=False):
        events = []
        server = Mock()
        watcher = Mock(pid=707)
        native = Mock(digest='fixture-digest', fd=707)
        if cleanup_errors:
            watcher.wait.side_effect = subprocess.TimeoutExpired('fixture watcher', 10)
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            isolated = home / 'frontend'

            def invoke(operation, args, **kwargs):
                events.append(tuple(args))
                if args == ['--session', 'amc', 'server']:
                    self.assertIs(operation, subprocess.Popen)
                    endpoint = isolated / '.config/herdr/sessions/amc/herdr.sock'
                    endpoint.parent.mkdir(parents=True)
                    endpoint.touch()  # readiness fixture, not a listening socket
                    return server
                if args[:4] == ['--session', 'amc', 'workspace', 'create']:
                    return json.dumps({'result': {'workspace': {'workspace_id': 'w'},
                                                  'root_pane': {'pane_id': 'p'}}}).encode()
                if args[:4] == ['--session', 'amc', 'pane', 'run']:
                    return b'{}'
                if args == ['session', 'attach', 'amc']:
                    self.assertIs(operation, subprocess.call)
                    if attach_error is not None:
                        raise attach_error
                    return attach_status
                if args == ['--session', 'amc', 'server', 'stop']:
                    self.assertIs(operation, subprocess.run)
                    self.assertEqual(kwargs['timeout'], 10)
                    if cleanup_errors:
                        raise OSError('fixture stop failed')
                    return Mock(returncode=0)
                self.fail(f'unexpected native command: {args}')
            native.invoke.side_effect = invoke
            sessions = [{'id': 's', 'name': 'S', 'project': 'P', 'task': 'T'}]
            with patch('arvyx_control.cockpit_client.request', side_effect=[sessions, {'host': 'local'}, None]), \
                    patch.object(frontend.subprocess, 'Popen', return_value=watcher) as spawn:
                if attach_error is not None:
                    with self.assertRaises(type(attach_error)) as raised:
                        frontend._open_frontend(home, isolated, native)
                    self.assertIs(raised.exception, attach_error)
                    result = None
                else:
                    result = frontend._open_frontend(home, isolated, native)
                spawn.assert_called_once()
                self.assertEqual(spawn.call_args.kwargs['pass_fds'], (707,))
                self.assertIn('--native-fd', spawn.call_args.args[0])
                self.assertTrue(spawn.call_args.kwargs['stdout'].closed)
        return result, server, watcher, events

    def assert_cleaned_up(self, server, watcher, events):
        watcher.terminate.assert_called_once_with()
        watcher.wait.assert_called_once_with(timeout=10)
        watcher.kill.assert_not_called()
        self.assertEqual(events[-1], ('--session', 'amc', 'server', 'stop'))
        server.wait.assert_called_once_with(timeout=10)

    def test_07_02_nonzero_attach_cleans_up_and_preserves_return_status(self):
        for status in (1, 23, -15):
            with self.subTest(status=status):
                result, server, watcher, events = self.run_open(status)
                self.assertEqual(result, status)
                self.assert_cleaned_up(server, watcher, events)

    def test_07_02_successful_detach_preserves_server_and_focus_watcher(self):
        result, server, watcher, events = self.run_open(0)
        self.assertEqual(result, 0)
        watcher.terminate.assert_not_called()
        watcher.wait.assert_not_called()
        server.wait.assert_not_called()
        self.assertNotIn(('--session', 'amc', 'server', 'stop'), events)

    def test_07_02_attach_exception_still_cleans_up_and_preserves_original_error(self):
        for error in (OSError('fixture attach failed'), KeyboardInterrupt()):
            with self.subTest(error=error):
                _, server, watcher, events = self.run_open(attach_error=error)
                self.assert_cleaned_up(server, watcher, events)

    def test_07_02_cleanup_errors_do_not_replace_failed_attach_status(self):
        result, _, watcher, events = self.run_open(23, cleanup_errors=True)
        self.assertEqual(result, 23)
        watcher.terminate.assert_called_once_with()
        watcher.kill.assert_called_once_with()
        self.assertEqual(watcher.wait.call_count, 2)
        self.assertEqual(events[-1], ('--session', 'amc', 'server', 'stop'))

    def test_07_02_cleanup_errors_do_not_replace_attach_exception(self):
        self.run_open(attach_error=OSError('original attach error'), cleanup_errors=True)


if __name__ == '__main__':
    unittest.main()
