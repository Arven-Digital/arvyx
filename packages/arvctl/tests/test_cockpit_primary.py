import concurrent.futures
import json
import tempfile
import unittest
from pathlib import Path

from arvyx_control.auth import issue_token, revoke_token
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_primary import PrimaryAgentRegistry


class PrimaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.vault = self.base / 'vault'
        self.headers = {}
        for agent in ('alpha', 'beta'):
            path = self.vault / 'registry' / 'agents' / (agent + '.json')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({'id': agent, 'display_name': 'Same name', 'scopes': ['control.read']}))
            self.headers[agent] = 'Bearer ' + issue_token(self.vault, agent).token
        self.owner = LocalCockpit(self.base / 'runtime', self.vault, self.base / 'events.jsonl', 'host')
        self.addCleanup(self.owner.close)
        self.path = self.base / 'primary.sqlite'
        self.registry = self.make_registry()
        self.human = 'Bearer fixture-human-secret'

    def make_registry(self):
        obj = PrimaryAgentRegistry(self.owner, self.path, shared_secret='fixture-human-secret')
        self.addCleanup(obj.close)
        return obj

    def connect(self, agent, registry=None):
        return (registry or self.registry).connect(authorization=self.headers[agent])

    def test_first_valid_connection_wins_and_disconnect_never_fails_over(self):
        self.assertIsNone(self.registry.snapshot()['agent_id'])
        a = self.connect('alpha')
        self.connect('beta')
        self.assertEqual(self.registry.snapshot()['agent_id'], 'alpha')
        self.registry.disconnect(a['connection_id'], authorization=self.headers['alpha'])
        self.assertEqual(self.registry.snapshot()['agent_id'], 'alpha')
        self.assertFalse(self.registry.snapshot()['connected'])
        self.assertEqual(self.make_registry().snapshot()['agent_id'], 'alpha')
        self.connect('beta')
        self.assertEqual(self.registry.snapshot()['agent_id'], 'alpha')

    def test_only_authenticated_human_can_select_exact_registered_connected_id(self):
        self.connect('alpha')
        self.connect('beta')
        for auth in (None, 'Bearer operator', self.headers['alpha'], {'role': 'operator'}):
            with self.subTest(auth=auth), self.assertRaises(PermissionError):
                self.registry.select('beta', revision=1, authorization=auth)
        selected = self.registry.select('beta', revision=1, authorization=self.human)
        self.assertEqual((selected['agent_id'], selected['revision']), ('beta', 2))
        with self.assertRaises(ValueError):
            self.registry.select('alpha', revision=1, authorization=self.human)
        for agent in ('Same name', ' beta', 'unknown'):
            with self.assertRaises(ValueError):
                self.registry.select(agent, revision=2, authorization=self.human)
        self.assertEqual(self.registry.snapshot()['agent_id'], 'beta')

    def test_invalid_revoked_unregistered_and_operator_connections_cannot_initialize(self):
        for auth in (None, 'Bearer bogus', 'operator', {'role': 'agent'}, 'Bearer fixture-human-secret'):
            with self.assertRaises(PermissionError):
                self.registry.connect(authorization=auth)
        revoke_token(self.vault, 'alpha')
        with self.assertRaises(PermissionError):
            self.connect('alpha')
        (self.vault / 'registry/agents/beta.json').unlink()
        with self.assertRaises(ValueError):
            self.connect('beta')
        self.assertEqual(self.registry.snapshot()['revision'], 0)

    def test_connection_cannot_be_rebound_or_disconnected_by_other_agent(self):
        a = self.connect('alpha')
        with self.assertRaises(PermissionError):
            self.registry.disconnect(a['connection_id'], authorization=self.headers['beta'])
        self.assertTrue(self.registry.snapshot()['connected'])
        self.registry.disconnect(a['connection_id'], authorization=self.headers['alpha'])
        with self.assertRaises(ValueError):
            self.registry.select('alpha', revision=1, authorization=self.human)

    def test_multiple_connections_preserve_presence_until_last_disconnect(self):
        first, second = self.connect('alpha'), self.connect('alpha')
        self.registry.disconnect(first['connection_id'], authorization=self.headers['alpha'])
        self.assertTrue(self.registry.snapshot()['connected'])
        self.registry.disconnect(second['connection_id'], authorization=self.headers['alpha'])
        self.assertFalse(self.registry.snapshot()['connected'])

    def test_atomic_first_wins_across_independent_connections(self):
        registries = [self.make_registry() for _ in range(12)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda pair: self.connect('alpha' if pair[0] % 2 else 'beta', pair[1]), enumerate(registries)))
        snapshots = [r.snapshot() for r in registries]
        self.assertEqual({s['revision'] for s in snapshots}, {1})
        self.assertEqual(len({s['agent_id'] for s in snapshots}), 1)
        self.assertEqual(len({r['connection_id'] for r in results}), 12)

    def test_registry_id_rebinding_and_malformed_revisions_are_rejected(self):
        self.connect('alpha')
        self.connect('beta')
        for revision in (True, -1, '1', None):
            with self.assertRaises(ValueError):
                self.registry.select('beta', revision=revision, authorization=self.human)
        path = self.vault / 'registry/agents/beta.json'
        path.write_text(json.dumps({'id': 'alpha'}))
        with self.assertRaises(ValueError):
            self.connect('beta')
        with self.assertRaises(ValueError):
            self.registry.select('beta', revision=1, authorization=self.human)
        self.assertEqual(self.registry.snapshot()['agent_id'], 'alpha')

    def test_concurrent_human_changes_use_compare_and_set(self):
        self.connect('alpha')
        self.connect('beta')
        registries = [self.make_registry() for _ in range(8)]
        def change(registry):
            try:
                return registry.select('beta', revision=1, authorization=self.human)['revision']
            except ValueError:
                return 'stale'
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(change, registries))
        self.assertEqual(results.count(2), 1)
        self.assertEqual(results.count('stale'), 7)

    def test_global_store_rejects_other_authority_binding(self):
        other = LocalCockpit(self.base / 'other-runtime', self.vault, self.base / 'other-events', 'other')
        self.addCleanup(other.close)
        with self.assertRaises(ValueError):
            PrimaryAgentRegistry(other, self.path)
