"""Synthetic boundary fixtures; no production identity or grant records."""
from datetime import UTC, datetime, timedelta
import unittest
from arvyx_control.external_gateway import (
    ExternalGateway, ExternalIdentity, Resource, AccessDenied,
)


class Grants:
    def __init__(self):
        self.rules = set()
        self.revoked = False
        self.now = datetime(2026, 1, 1, tzinfo=UTC)
        self.expires = self.now + timedelta(hours=24)
        self.calls = []

    def allows(self, *, principal, resource, operation, tool):
        self.calls.append((principal, resource, operation, tool))
        return (not self.revoked and self.now < self.expires
                and (principal, resource, operation, tool) in self.rules)


class Backend:
    def __init__(self):
        self.calls = []

    def lookup(self,*,resource,actor):
        self.calls.append(('lookup',resource,actor))
        return {'title':resource.identifier}

    def read(self, *, resource, actor):
        self.calls.append(('read', resource, actor))
        return {'title': resource.identifier}

    def write(self, *, resource, actor, payload):
        self.calls.append(('write', resource, actor, payload))
        return {'ok': True}


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.identity = ExternalIdentity('grok-cloud')
        self.resource = Resource('task', 'A')
        self.other = Resource('task', 'B')
        self.grants = Grants()
        self.backend = Backend()
        self.gateway = ExternalGateway(self.grants, self.backend)

    def allow(self, operation, resource=None, tool=None):
        self.grants.rules.add(('grok-cloud', resource or self.resource,
                               operation, tool or 'external.' + operation))

    def test_authenticated_identity_has_no_ambient_access(self):
        for operation in ('lookup', 'read', 'write'):
            with self.subTest(operation=operation), self.assertRaises(AccessDenied):
                self.gateway.access(self.identity, self.resource, operation)
        self.assertEqual([], self.gateway.discover(self.identity, [self.resource, self.other]))
        self.assertEqual([], self.backend.calls)

    def test_exact_lookup_and_read_are_distinct(self):
        self.allow('lookup')
        self.assertEqual({'title': 'A'}, self.gateway.access(self.identity, self.resource, 'lookup'))
        for resource, operation in [(self.other, 'lookup'), (self.resource, 'read')]:
            with self.assertRaises(AccessDenied):
                self.gateway.access(self.identity, resource, operation)

    def test_list_and_search_filter_before_read_and_have_no_totals(self):
        for operation in ('list', 'search'):
            self.backend.calls.clear()
            self.allow(operation)
            self.allow('read', tool='external.' + operation)
            result = self.gateway.discover(self.identity, [self.resource, self.other],
                                           operation=operation, query='A')
            self.assertEqual([{'title': 'A'}], result)
            self.assertEqual([('read', self.resource, 'grok-cloud')], self.backend.calls)
        self.assertEqual([], self.gateway.discover(self.identity, [self.resource],
                                                   operation='search', query='missing'))

    def test_read_does_not_imply_list_search_or_write(self):
        self.allow('read')
        self.assertEqual({'title': 'A'}, self.gateway.access(self.identity, self.resource, 'read'))
        for operation in ('list', 'search'):
            self.assertEqual([], self.gateway.discover(self.identity, [self.resource], operation=operation))
        with self.assertRaises(AccessDenied):
            self.gateway.access(self.identity, self.resource, 'write')

    def test_write_binds_actor_and_does_not_mutate_payload(self):
        self.allow('write')
        payload = {'actor': 'operator', 'author': 'someone', 'result': 'done'}
        with self.assertRaises(AccessDenied):
            self.gateway.access(self.identity, self.resource, 'write', payload=payload)
        self.gateway.access(self.identity, self.resource, 'write', payload={'result': 'done'})
        self.assertEqual(('write', self.resource, 'grok-cloud', {'result': 'done'}), self.backend.calls[-1])
        self.assertEqual('operator', payload['actor'])

    def test_cloud_and_local_are_separate_principals(self):
        self.allow('read')
        with self.assertRaises(AccessDenied):
            self.gateway.access(ExternalIdentity('grok-local'), self.resource, 'read')

    def test_revocation_and_expiry_rechecked_for_every_operation(self):
        for operation in ('lookup', 'read', 'write', 'list', 'search'):
            self.allow(operation)
            self.allow('read', tool='external.' + operation)
        for reason in ('revoked', 'expired'):
            self.grants.revoked = reason == 'revoked'
            self.grants.now = self.grants.expires if reason == 'expired' else self.grants.expires - timedelta(seconds=1)
            self.backend.calls.clear()
            for operation in ('lookup', 'read', 'write'):
                with self.assertRaises(AccessDenied):
                    self.gateway.access(self.identity, self.resource, operation)
            for operation in ('list', 'search'):
                self.assertEqual([], self.gateway.discover(self.identity, [self.resource], operation=operation))
            self.assertEqual([], self.backend.calls)

    def test_unknown_operations_tools_and_resources_fail_closed(self):
        self.allow('read')
        for operation in ('control.read', 'memory.read', 'revoke', 'shell', 'list'):
            with self.assertRaises(AccessDenied):
                self.gateway.access(self.identity, self.resource, operation)
        for kind, identifier in [('memory', 'A'), ('squad', 'A'), ('task', '*'), ('artifact', '../secret'), ('workspace', '/etc')]:
            with self.assertRaises(ValueError):
                Resource(kind, identifier)
        for identity in (None, object()):
            with self.assertRaises(AccessDenied):
                self.gateway.access(identity, self.resource, 'read')

    def test_tool_grants_are_exact_not_scope_aliases(self):
        self.allow('read', tool='control.read')
        self.allow('read', tool='memory.read')
        self.allow('read', tool='external.lookup')
        with self.assertRaises(AccessDenied):
            self.gateway.access(self.identity, self.resource, 'read')
        self.allow('read')
        self.gateway.access(self.identity, self.resource, 'read')
        self.assertEqual(('grok-cloud', self.resource, 'read', 'external.read'), self.grants.calls[-1])

    def test_discovery_requires_both_permissions_and_deduplicates(self):
        self.allow('list')
        self.assertEqual([], self.gateway.discover(self.identity, [self.resource]))
        self.assertEqual([], self.backend.calls)
        self.allow('read', tool='external.list')
        self.assertEqual([{'title': 'A'}], self.gateway.discover(self.identity, [self.resource, self.resource]))
        self.assertEqual(1, len(self.backend.calls))

    def test_expiry_is_live_and_not_cached(self):
        self.allow('read')
        self.gateway.access(self.identity, self.resource, 'read')
        self.grants.now = self.grants.expires
        with self.assertRaises(AccessDenied):
            self.gateway.access(self.identity, self.resource, 'read')
        self.grants.now -= timedelta(seconds=1)
        self.gateway.access(self.identity, self.resource, 'read')
        self.grants.revoked = True
        with self.assertRaises(AccessDenied):
            self.gateway.access(self.identity, self.resource, 'read')
        self.assertEqual(2, len(self.backend.calls))

    def test_checker_failure_and_non_boolean_allow_deny(self):
        for value in (1, 'yes', None):
            class Checker:
                def allows(self, **kwargs):
                    return value
            with self.assertRaises(AccessDenied):
                ExternalGateway(Checker(), self.backend).access(self.identity, self.resource, 'read')
        class Broken:
            def allows(self, **kwargs):
                raise RuntimeError('private internal error')
        with self.assertRaisesRegex(AccessDenied, '^access denied$'):
            ExternalGateway(Broken(), self.backend).access(self.identity, self.resource, 'read')
        self.assertEqual([], self.backend.calls)


if __name__ == '__main__':
    unittest.main()
