from arvyx_control.local_executor import ExecutionPolicy
"""Durable delegation control: never a provider or terminal prompt runner."""
import unittest
import test_cockpit_surface as fixtures
from arvyx_control.cockpit import LocalCockpit


class DelegationTests(unittest.TestCase):
    setUp = fixtures.SurfaceTests.setUp
    session = fixtures.SurfaceTests.session

    def grant(self, sid):
        return self.service.delegate(sid, operator='rowan', goal='Run fixture tests',
                                     limits='No network, spend or deploy', actor='operator')

    def test_explicit_goal_limits_and_no_implicit_handover(self):
        sid = self.session('first')['id']
        for goal, limits in [('', 'safe'), ('test', '')]:
            with self.assertRaises(ValueError):
                self.service.delegate(sid, operator='rowan', goal=goal, limits=limits, actor='operator')
        grant = self.grant(sid)
        self.assertEqual(grant['status'], 'active')
        with self.assertRaises(ValueError):
            self.grant(sid)
        with self.assertRaises(PermissionError):
            self.service.delegate(sid, operator='uma', goal='test', limits='safe', actor='uma')

    def test_restart_pauses_without_resend_or_reactivation(self):
        sid = self.session('first')['id']
        grant = self.grant(sid)
        self.service.close()
        self.service = LocalCockpit(self.root / 'runtime', self.root / 'vault', self.root / 'events.jsonl', 'laptop-a', execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))
        state = self.service.delegation(sid, actor='operator')
        self.assertEqual(state['status'], 'paused')
        self.assertEqual(state['goal'], grant['goal'])
        with self.assertRaises(ValueError):
            self.service.reserve_prompt(sid, generation=grant['generation'], cursor=0, actor='rowan')

    def test_take_control_invalidates_reservation_without_interrupting_process(self):
        sid = self.session('first')['id']
        self.service.start(sid, actor='operator', environment='host')
        grant = self.grant(sid)
        reservation = self.service.reserve_prompt(sid, generation=grant['generation'], cursor=0, actor='rowan')
        revoked = self.service.take_control(sid, actor='operator')
        self.assertEqual(revoked['status'], 'revoked')
        self.assertIsNone(revoked['pending'])
        self.assertEqual(self.service._get(sid)['status'], 'running')
        with self.assertRaises(ValueError):
            self.service.settle_prompt(sid, generation=grant['generation'], delivery=reservation['pending'],
                                       outcome='delivered', actor='rowan')

    def test_ambiguous_delivery_requires_human_reconciliation(self):
        sid = self.session('first')['id']
        grant = self.grant(sid)
        reserved = self.service.reserve_prompt(sid, generation=grant['generation'], cursor=12, actor='rowan')
        with self.assertRaises(ValueError):
            self.service.reserve_prompt(sid, generation=grant['generation'], cursor=12, actor='rowan')
        uncertain = self.service.settle_prompt(sid, generation=grant['generation'], delivery=reserved['pending'],
                                              outcome='ambiguous', actor='rowan')
        self.assertEqual(uncertain['status'], 'ambiguous')
        self.assertEqual(uncertain['cursor'], 12)
        with self.assertRaises(ValueError):
            self.service.reserve_prompt(sid, generation=grant['generation'], cursor=13, actor='rowan')
        self.service.take_control(sid, actor='operator')
        next_grant = self.grant(sid)
        self.assertGreater(next_grant['generation'], grant['generation'])
        self.assertEqual(next_grant['cursor'], 12)

    def test_operator_fence_cursor_and_end(self):
        sid = self.session('first')['id']
        grant = self.grant(sid)
        with self.assertRaises(PermissionError):
            self.service.reserve_prompt(sid, generation=grant['generation'], cursor=0, actor='uma')
        with self.assertRaises(ValueError):
            self.service.reserve_prompt(sid, generation=True, cursor=0, actor='rowan')
        reservation = self.service.reserve_prompt(sid, generation=grant['generation'], cursor=10, actor='rowan')
        self.service.settle_prompt(sid, generation=grant['generation'], delivery=reservation['pending'],
                                   outcome='delivered', actor='rowan')
        with self.assertRaises(ValueError):
            self.service.reserve_prompt(sid, generation=grant['generation'], cursor=9, actor='rowan')
        self.service.end(sid, actor='operator')
        self.assertEqual(self.service.delegation(sid, actor='operator')['status'], 'revoked')
        with self.assertRaises(ValueError):
            self.grant(sid)
