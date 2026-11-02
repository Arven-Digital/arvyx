"""External delegation core contract; no transport or filesystem exports."""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from arvyx_control.external_grants import ExternalGrantStore


class ExternalGrantsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'grants.sqlite'
        self.now = datetime(2026, 10, 23, tzinfo=timezone.utc)
        from arvyx_control.replica_authority import authority_context
        self.enterContext(authority_context(Path(self.tmp.name) / "vault"))
        self.store = ExternalGrantStore(self.path, clock=lambda: self.now)
        self.addCleanup(self.store.close)
        self.store.set_authority('owner', resources=['task:A', 'task:B'], operations=['read', 'submit'], can_issue=True, can_export=True)

    def issue(self, **kwargs):
        args = dict(issuer='owner', recipient='grok:cloud', resources=['task:A'], operations=['read'], expires_at=self.now + timedelta(hours=24), provenance='explicit review assignment')
        args.update(kwargs)
        return self.store.issue(**args)

    def test_persistence_recipient_exact_scope_and_default_deny(self):
        grant = self.issue()
        other = ExternalGrantStore(self.path, clock=lambda: self.now)
        self.addCleanup(other.close)
        self.assertTrue(other.decide(grant.id, principal='grok:cloud', resource='task:A', operation='read').allowed)
        for principal, resource, operation in [('grok:local', 'task:A', 'read'), ('grok:cloud', 'task:B', 'read'), ('grok:cloud', 'task:A', 'write'), ('grok:cloud', 'task:A/child', 'read')]:
            self.assertFalse(other.decide(grant.id, principal=principal, resource=resource, operation=operation).allowed)
        self.assertFalse(other.decide('missing', principal='grok:cloud', resource='task:A', operation='read').allowed)
        self.assertEqual(len(other.audit()), 7)

    def test_independent_issuer_resource_and_export_authorities(self):
        for issue, export, resources, operations in [(False, True, ['task:A'], ['read']), (True, False, ['task:A'], ['read']), (True, True, ['task:B'], ['read']), (True, True, ['task:A'], ['submit'])]:
            self.store.set_authority('reader', resources=resources, operations=operations, can_issue=issue, can_export=export)
            with self.assertRaises(PermissionError):
                self.issue(issuer='reader')
        with self.assertRaises(PermissionError):
            self.issue(issuer='unknown')

    def test_expiry_boundary_and_revoke_persist(self):
        grant = self.issue()
        self.now = grant.expires_at
        self.assertFalse(self.store.decide(grant.id, principal='grok:cloud', resource='task:A', operation='read').allowed)
        self.now -= timedelta(hours=1)
        with self.assertRaises(PermissionError):
            self.store.revoke(grant.id, actor='grok:local')
        self.store.revoke(grant.id, actor='owner')
        self.assertIsNotNone(self.store.get(grant.id).revoked_at)
        reopened = ExternalGrantStore(self.path, clock=lambda: self.now)
        self.addCleanup(reopened.close)
        self.assertFalse(reopened.decide(grant.id, principal='grok:cloud', resource='task:A', operation='read').allowed)
        self.assertEqual([row['event'] for row in reopened.audit()], ['created', 'access', 'revoked', 'access'])

    def test_authority_removal_and_exclusion_take_effect_at_access(self):
        grant = self.issue()
        self.store.set_excluded('task:A', True)
        self.assertFalse(self.store.decide(grant.id, principal='grok:cloud', resource='task:A', operation='read').allowed)
        with self.assertRaises(PermissionError):
            self.issue()
        self.store.set_excluded('task:A', False)
        self.store.set_authority('owner', resources=['task:A'], operations=['read'], can_issue=True, can_export=False)
        self.assertFalse(self.store.decide(grant.id, principal='grok:cloud', resource='task:A', operation='read').allowed)

    def test_child_nonexpansion_and_ancestor_revocation(self):
        parent = self.issue()
        self.store.set_authority('grok:cloud', resources=['task:A', 'task:B'], operations=['read', 'submit'], can_issue=True, can_export=True)
        args = dict(issuer='grok:cloud', recipient='reviewer', parent_id=parent.id)
        # Ordinary reading does not authorize onward delegation.
        with self.assertRaises(PermissionError):
            self.issue(**args)
        self.store.set_authority('owner', resources=['task:A', 'task:B'], operations=['read', 'delegate'], can_issue=True, can_export=True)
        parent = self.issue(operations=['read', 'delegate'])
        args['parent_id'] = parent.id
        child = self.issue(**args)
        for change in [dict(resources=['task:B']), dict(operations=['submit']), dict(expires_at=parent.expires_at + timedelta(seconds=1)), dict(issuer='owner')]:
            with self.assertRaises(PermissionError):
                self.issue(**(args | change))
        self.assertTrue(self.store.decide(child.id, principal='reviewer', resource='task:A', operation='read').allowed)
        self.store.revoke(parent.id, actor='owner')
        self.assertFalse(self.store.decide(child.id, principal='reviewer', resource='task:A', operation='read').allowed)

    def test_invalid_inputs_are_not_ambient_scope(self):
        for change in [dict(resources=[]), dict(resources=['*']), dict(operations=[]), dict(operations=['*']), dict(recipient=''), dict(provenance=''), dict(expires_at=self.now), dict(expires_at=datetime(2027, 1, 1)), dict(resources='task:A')]:
            with self.assertRaises(ValueError):
                self.issue(**change)
        grant = self.issue(expires_at=self.now.astimezone(timezone(timedelta(hours=3))) + timedelta(hours=1))
        self.assertEqual(grant.expires_at.utcoffset(), timedelta(0))


if __name__ == '__main__':
    unittest.main()
