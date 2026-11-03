"""Actual local endpoint regressions, disposable cat owner only."""
import sqlite3
from contextlib import closing
from unittest.mock import patch
import test_cockpit_human_binding as base
from arvyx_control.cockpit_primary import PrimaryAgentRegistry

class DurableBindingTests(base.HumanBindingTests):
    def test_bind_disconnect_before_first_read_survives_restart_and_later_native(self):
        payload = self.prepare()
        self.assertEqual(self.http('/api/local-bindings', payload)[0], 200)
        self.owner.end(payload['session'], actor='operator')
        # B was already running but never observed by primary. A must remain.
        self.server.primary.source = lambda: ['beta']
        state = self.http('/api/primary-agent')[1]
        self.assertEqual(state['primary_agent_id'], 'alpha')
        self.assertFalse(state['primary_connected'])
        other = PrimaryAgentRegistry(self.server.primary.registry.owner,
            self.home/'events.jsonl.primary.sqlite', shared_secret='existing-operator-test')
        try:
            self.assertEqual(other.snapshot()['agent_id'], 'alpha')
            self.assertEqual(other.db.execute('SELECT COUNT(*) FROM primary_events').fetchone()[0], 1)
        finally: other.close()

    def test_primary_write_failure_rolls_back_binding_and_audit(self):
        payload = self.prepare()
        registry = self.server.primary.registry
        registry.db.execute("CREATE TRIGGER fail_election BEFORE UPDATE ON primary_agent BEGIN SELECT RAISE(ABORT, 'injected disk failure'); END")
        self.assertEqual(self.http('/api/local-bindings', payload)[0], 503)
        with closing(sqlite3.connect(self.server.bindings.path)) as db, db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM bindings').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0], 0)
        registry.db.execute('DROP TRIGGER fail_election')
        self.assertEqual(self.http('/api/local-bindings', payload)[0], 200)
        self.assertEqual(registry.snapshot()['agent_id'], 'alpha')
