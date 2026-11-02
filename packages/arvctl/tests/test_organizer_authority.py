"""Organizer authority stays separate from external grants and transport claims."""
from dataclasses import FrozenInstanceError, replace
import unittest

from arvyx_control.organizer_authority import OrganizerAuthority, Identity


class OrganizerAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.policy = OrganizerAuthority()
        self.organizer = self.policy.provision_identity('main', kind='internal', organizer=True)
        self.agent = self.policy.provision_identity('worker', kind='internal')
        self.external = self.policy.provision_identity('customer', kind='external')
        self.policy.enroll_machine('host')
        self.policy.bind_agent(self.agent, machine='host', root=True)

    def decide(self, actor=None, **kwargs):
        return self.policy.authorize(actor if actor is not None else self.organizer,
                                     operation='invoke_root', machine='host',
                                     executing_agent=self.agent, **kwargs)

    def test_attributable_root_delegation(self):
        decision = self.decide()
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.authority_chain, ('main', 'worker', 'host', 'root'))
        self.assertEqual(decision.initiating_organizer, 'main')
        self.assertEqual(decision.executing_agent, 'worker')
        self.assertEqual(self.policy.audit()[-1], decision)

    def test_forged_actor_and_role_claims_fail(self):
        for actor in (Identity('main', 'internal'), replace(self.organizer),
                      {'principal': 'main', 'role': 'organizer'}, 'main'):
            self.assertFalse(self.decide(actor).allowed)
        with self.assertRaises(FrozenInstanceError):
            self.organizer.principal = 'customer'

    def test_root_does_not_make_organizer(self):
        self.assertFalse(self.decide(self.agent).allowed)

    def test_external_never_gets_organizer_or_executor_root(self):
        with self.assertRaises(ValueError):
            self.policy.provision_identity('evil', kind='external', organizer=True)
        with self.assertRaises(PermissionError):
            self.policy.set_organizer(self.external, True)
        with self.assertRaises(PermissionError):
            self.policy.bind_agent(self.external, machine='host', root=True)
        self.assertFalse(self.decide(self.external).allowed)

    def test_revocation_rechecks_dispatch(self):
        self.assertTrue(self.decide().allowed)
        self.policy.set_organizer(self.organizer, False)
        self.assertFalse(self.decide().allowed)
        import tempfile
        from pathlib import Path
        from arvyx_control.replica_authority import authority_context
        with tempfile.TemporaryDirectory() as directory, authority_context(Path(directory)/'vault'):
            self.assertFalse(self.policy.dispatch(self.organizer, operation='invoke_root',
                                                machine='host', executing_agent=self.agent).allowed)

    def test_machine_and_agent_liveness_fail_closed(self):
        for state in ('disconnected', 'unenrolled'):
            self.policy.set_machine_state('host', state)
            self.assertFalse(self.decide().allowed)
        self.policy.enroll_machine('host')
        self.assertFalse(self.decide().allowed)  # Re-enrollment needs fresh executor attestation.
        self.policy.bind_agent(self.agent, machine='host', root=False)
        self.assertFalse(self.decide().allowed)
        self.policy.bind_agent(self.agent, machine='other', root=True)
        self.assertFalse(self.decide().allowed)

    def test_management_only_on_connected_enrolled_machines(self):
        for operation in ('create_agent', 'manage_agent'):
            self.assertTrue(self.policy.authorize(self.organizer, operation=operation,
                                                 machine='host').allowed)
            self.assertFalse(self.policy.authorize(self.external, operation=operation,
                                                  machine='host').allowed)
            self.assertFalse(self.policy.authorize(self.organizer, operation=operation,
                                                  machine='unknown').allowed)
        self.assertFalse(self.policy.authorize(self.organizer, operation='external_export',
                                              machine='host').allowed)

    def test_duplicate_identity_and_cross_policy_handles_rejected(self):
        with self.assertRaises(ValueError):
            self.policy.provision_identity('main', kind='internal')
        other = OrganizerAuthority().provision_identity('main', kind='internal', organizer=True)
        self.assertFalse(self.decide(other).allowed)
        forged = replace(self.agent)
        self.assertFalse(self.policy.authorize(self.organizer, operation='invoke_root',
                                              machine='host', executing_agent=forged).allowed)

    def test_audit_is_immutable_snapshot(self):
        self.decide()
        snapshot = self.policy.audit()
        self.decide(self.external)
        self.assertEqual(len(self.policy.audit()), len(snapshot) + 1)
        with self.assertRaises(FrozenInstanceError):
            snapshot[-1].allowed = False


if __name__ == '__main__':
    unittest.main()
