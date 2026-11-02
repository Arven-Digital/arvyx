"""No model calls: deterministic driver operates a real native fixture PTY."""
import time
import unittest
from unittest.mock import patch
import test_cockpit_surface as fixtures


class JsonOperatorBoundsTests(unittest.TestCase):
    def test_output_limit_stops_stream_before_decode_or_json_materialization(self):
        import sys
        import tempfile
        from arvyx_control.cockpit_terminal_runner import JsonOperator
        with tempfile.TemporaryDirectory() as directory:
            # A root-owned system shell, not sys.executable: hosted interpreters may be
            # group-writable, which the operator trust check correctly refuses.
            operator = JsonOperator(['/bin/sh', '-c',
                'cat >/dev/null; head -c 1048576 /dev/zero | tr "\\000" x'], cwd=directory)
            with patch('arvyx_control.cockpit_terminal_runner.json.loads', side_effect=AssertionError('must not decode oversize')) as decode:
                with self.assertRaisesRegex(ValueError, 'protocol cap'):
                    operator({'goal': 'synthetic'})
            decode.assert_not_called()


class RunnerTests(unittest.TestCase):
    setUp = fixtures.SurfaceTests.setUp
    session = fixtures.SurfaceTests.session

    def prepare(self):
        first = self.session('first')
        sid = first['id']
        self.service.bind_native(sid, tool='fixture', conversation='native-one', actor='operator')
        self.service.start_native(sid, fixture=True, actor='operator')
        self.service.delegate(sid, operator='rowan', goal='Exercise fixture', limits='No providers', actor='operator')
        deadline = time.monotonic() + 3
        while 'NATIVE' not in self.service.read(sid, actor='operator')['output']:
            if time.monotonic() > deadline:
                self.fail('native fixture did not start')
            time.sleep(.01)
        return sid

    def test_runner_delta_and_takeover_fence_without_interrupt(self):
        from arvyx_control.cockpit_terminal_runner import step
        sid = self.prepare()
        calls = []
        def driver(context):
            calls.append(context)
            return {'action': 'prompt', 'text': 'hello'}
        result = step(self.service, sid, actor='rowan', driver=driver)
        self.assertEqual(result['outcome'], 'delivered')
        self.assertIn('NATIVE native-one', calls[0]['delta'])
        time.sleep(.1)
        result = step(self.service, sid, actor='rowan', driver=lambda context: {'action': 'wait', 'reason': 'human decision'})
        self.assertEqual(result['outcome'], 'waiting')
        self.assertEqual(self.service.snapshot(actor='operator')['sessions'][0]['attention'], 'human')
        self.assertEqual(self.service.list()[0]['status'], 'running')
        self.service.take_control(sid, actor='operator')
        with self.assertRaises(ValueError):
            step(self.service, sid, actor='rowan', driver=driver)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.service.list()[0]['status'], 'running')

    def test_cancellation_during_driver_prevents_delivery(self):
        from arvyx_control.cockpit_terminal_runner import step
        sid = self.prepare()
        def driver(context):
            self.service.take_control(sid, actor='operator')
            return {'action': 'prompt', 'text': 'MUST_NOT_DELIVER'}
        with self.assertRaises(ValueError):
            step(self.service, sid, actor='rowan', driver=driver)
        self.assertNotIn('MUST_NOT_DELIVER', self.service.read(sid, actor='operator')['output'])

    def test_prompt_uses_terminal_enter_not_linefeed(self):
        from arvyx_control.cockpit_terminal_runner import step
        sid = self.prepare()
        with patch('arvyx_control.cockpit_terminal_runner.os.write', side_effect=[5, 1]) as write:
            result = step(self.service, sid, actor='rowan', driver=lambda _: {'action': 'prompt', 'text': 'hello'})
        self.assertEqual([call.args[1] for call in write.call_args_list], [b'hello', b'\r'])
        self.assertEqual(result['outcome'], 'delivered')

    def test_takeover_between_text_and_enter_never_submits(self):
        from arvyx_control.cockpit_terminal_runner import step
        sid = self.prepare()
        with patch('arvyx_control.cockpit_terminal_runner.os.write', return_value=5) as write:
            with patch('arvyx_control.cockpit_terminal_runner.time.sleep', side_effect=lambda _: self.service.take_control(sid, actor='operator')):
                with self.assertRaises(ValueError):
                    step(self.service, sid, actor='rowan', driver=lambda _: {'action': 'prompt', 'text': 'hello'})
        self.assertEqual([call.args[1] for call in write.call_args_list], [b'hello'])
        self.assertEqual(self.service.delegation(sid, actor='operator')['status'], 'revoked')
        self.assertEqual(self.service.list()[0]['status'], 'running')

    def test_enter_failure_is_ambiguous_not_retryable(self):
        from arvyx_control.cockpit_terminal_runner import step
        sid = self.prepare()
        with patch('arvyx_control.cockpit_terminal_runner.os.write', side_effect=[5, BlockingIOError]):
            result = step(self.service, sid, actor='rowan', driver=lambda _: {'action': 'prompt', 'text': 'hello'})
        self.assertEqual(result['outcome'], 'ambiguous')
        with self.assertRaises(ValueError):
            step(self.service, sid, actor='rowan', driver=lambda _: self.fail('must not replay staged text'))

    def test_prompt_control_keys_rejected_before_any_pty_write(self):
        from arvyx_control.cockpit_terminal_runner import step
        sid = self.prepare()
        for key in ['\r', '\n', '\x03', '\x1a', '\x1c', '\x1b', '\x7f', '\t']:
            with self.subTest(key=repr(key)):
                with patch('arvyx_control.cockpit_terminal_runner.os.write') as write:
                    with self.assertRaisesRegex(ValueError, 'control'):
                        step(self.service, sid, actor='rowan', driver=lambda _: {'action': 'prompt', 'text': 'hello' + key})
                write.assert_not_called()

    def test_attach_detach_during_debounce_withholds_enter(self):
        from arvyx_control.cockpit_terminal_runner import step
        sid = self.prepare()
        def human_visit(_):
            lease = self.service.attach(sid, actor='operator')
            self.service.detach(sid, actor='operator', attachment=lease['attachment'])
        with patch('arvyx_control.cockpit_terminal_runner.os.write', return_value=5) as write:
            with patch('arvyx_control.cockpit_terminal_runner.time.sleep', side_effect=human_visit):
                result = step(self.service, sid, actor='rowan', driver=lambda _: {'action': 'prompt', 'text': 'hello'})
        self.assertEqual(result['outcome'], 'ambiguous')
        self.assertEqual([call.args[1] for call in write.call_args_list], [b'hello'])

    def test_partial_write_is_ambiguous_and_never_retried(self):
        from arvyx_control.cockpit_terminal_runner import step
        sid = self.prepare()
        with patch('arvyx_control.cockpit_terminal_runner.os.write', return_value=1):
            result = step(self.service, sid, actor='rowan', driver=lambda _: {'action': 'prompt', 'text': 'hello'})
        self.assertEqual(result['outcome'], 'ambiguous')
        self.assertEqual(self.service.delegation(sid, actor='operator')['status'], 'ambiguous')
        with self.assertRaises(ValueError):
            step(self.service, sid, actor='rowan', driver=lambda _: self.fail('must not retry'))

    def test_review_requires_evidence_and_does_not_accept_task(self):
        from arvyx_control.cockpit_terminal_runner import step
        from arvyx_control.control import list_tasks
        sid = self.prepare()
        with self.assertRaises(ValueError):
            step(self.service, sid, actor='rowan', driver=lambda _: {'action': 'review', 'evidence': ''})
        result = step(self.service, sid, actor='rowan', driver=lambda _: {'action': 'review', 'evidence': 'fixture test receipt'})
        self.assertEqual(result['outcome'], 'review')
        self.assertEqual(self.service.delegation(sid, actor='operator')['status'], 'review')
        self.assertNotEqual(list_tasks(self.root / 'events.jsonl').tasks[0].status, 'done')

    def test_human_attachment_withholds_prompt_and_keeps_process_alive(self):
        from arvyx_control.cockpit_terminal_runner import step
        sid = self.prepare()
        self.service.attach(sid, actor='operator')
        with self.assertRaisesRegex(ValueError, 'human attached'):
            step(self.service, sid, actor='rowan', driver=lambda _: {'action': 'prompt', 'text': 'not-sent'})
        self.assertNotIn('not-sent', self.service.read(sid, actor='operator')['output'])
        self.assertEqual(self.service.list()[0]['status'], 'running')

    def test_native_relaunch_pauses_and_resets_previous_stream_cursor(self):
        from arvyx_control.cockpit_terminal_runner import step
        sid = self.prepare()
        step(self.service, sid, actor='rowan', driver=lambda _: {'action': 'wait', 'reason': 'waiting'})
        old = self.service.delegation(sid, actor='operator')
        self.assertGreater(old['cursor'], 0)
        lease = self.service.attach(sid, actor='operator')
        self.service.write(sid, text='\x04', actor='operator', attachment=lease['attachment'])
        deadline = time.monotonic() + 3
        while self.service._get(sid)['status'] != 'stopped':
            if time.monotonic() > deadline:
                self.fail('fixture did not exit')
            time.sleep(.01)
        self.assertEqual(self.service.delegation(sid, actor='operator')['status'], 'paused')
        self.service.start_native(sid, fixture=True, actor='operator')
        current = self.service.delegation(sid, actor='operator')
        self.assertEqual(current['cursor'], 0)
        self.assertEqual(current['status'], 'paused')
        self.assertGreater(current['generation'], old['generation'])
        with self.assertRaises(ValueError):
            step(self.service, sid, actor='rowan', driver=lambda _: self.fail('launch must not reactivate'))

    def test_unchanged_output_waits_without_reinvoking_driver(self):
        from arvyx_control.cockpit_terminal_runner import step
        sid = self.prepare()
        waiting = lambda _: {'action': 'wait', 'reason': 'waiting for decision'}
        # The fixture may still be emitting start-up output after prepare() saw it
        # start (a loaded runner makes that likely). Step with a waiting driver until two
        # consecutive steps see the same cursor, so the final step observes no progress.
        previous = step(self.service, sid, actor='rowan', driver=waiting)
        deadline = time.monotonic() + 3
        while True:
            current = step(self.service, sid, actor='rowan', driver=waiting)
            if current['cursor'] == previous['cursor']:
                break
            self.assertLess(time.monotonic(), deadline, 'fixture output never settled')
            previous = current
            time.sleep(.02)
        result = step(self.service, sid, actor='rowan', driver=lambda _: self.fail('no progress must not loop'))
        self.assertEqual(result['outcome'], 'waiting')
