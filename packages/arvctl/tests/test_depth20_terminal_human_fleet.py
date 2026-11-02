"""Depth20 regressions; authored only, execution requires separate approval."""
from unittest.mock import patch
from test_cockpit_terminal_runner import RunnerTests


class HumanFenceTests(RunnerTests):
    def test_revoked_staging_blocks_regrant_until_explicit_reconciliation(self):
        from arvyx_control.cockpit_terminal_runner import step
        sid = self.prepare()
        with patch('arvyx_control.cockpit_terminal_runner.os.write', return_value=1) as write:
            with patch('arvyx_control.cockpit_terminal_runner.time.sleep',
                       side_effect=lambda _: self.service.take_control(sid, actor='operator')):
                with self.assertRaises(ValueError):
                    step(self.service, sid, actor='rowan', driver=lambda _: {'action': 'prompt', 'text': 'A'})
            for _ in range(2):
                with self.assertRaisesRegex(ValueError, 'staged input'):
                    self.service.delegate(sid, operator='rowan', goal='B', limits='No providers', actor='operator')
            self.assertEqual([c.args[1] for c in write.call_args_list], [b'A'])
        lease = self.service.attach(sid, actor='operator')
        with self.assertRaises(ValueError):
            self.service.reconcile_input(sid, actor='operator', attachment=lease['attachment'])
        self.service.reconcile_input(sid, actor='operator', attachment=lease['attachment'], confirmed_clean=True)
        self.service.detach(sid, actor='operator', attachment=lease['attachment'])
        self.service.delegate(sid, operator='rowan', goal='B', limits='No providers', actor='operator')

    def test_driver_human_visit_invalidates_before_payload(self):
        from arvyx_control.cockpit_terminal_runner import step
        sid = self.prepare()
        def driver(_):
            lease = self.service.attach(sid, actor='operator')
            self.service.write(sid, text='human', actor='operator', attachment=lease['attachment'])
            self.service.detach(sid, actor='operator', attachment=lease['attachment'])
            return {'action': 'prompt', 'text': 'STALE'}
        with patch('arvyx_control.cockpit_terminal_runner.os.write') as write:
            with self.assertRaises(ValueError):
                step(self.service, sid, actor='rowan', driver=driver)
            self.assertFalse(any(c.args[1] in (b'STALE', b'\r') for c in write.call_args_list))
