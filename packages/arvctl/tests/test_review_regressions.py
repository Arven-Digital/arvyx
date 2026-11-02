import json, threading, time
from test_cockpit_local import HarmlessOwnerConnectionTests
from test_primary_integration import IntegratedPrimaryTests

class LegacyIdentityRegression(HarmlessOwnerConnectionTests):
    def test_legacy_runtime_mismatch_is_not_eligible(self):
        (self.home/'vault/registry/runtimes/shell-only.json').write_text(json.dumps(dict(id='shell-only',harness='codex')))
        state=self.http('/api/primary-agent')[1]
        # The authenticated first connection already elected alpha in setUp.
        # Losing compatibility revokes presence, not the durable human selection.
        self.assertEqual(state['primary_agent_id'], 'alpha')
        self.assertFalse(state['primary_connected'])
        self.assertFalse(any(agent['connected'] for agent in state['agents']))
        from arvyx_control.cockpit_local import inspect_existing_owner
        self.assertEqual(inspect_existing_owner(self.connection)['eligible_agents'], [])
        self.assertNotEqual(self.http('/api/primary-agent', dict(agent_id='beta', revision=state['revision']))[0], 200)

class ReconciliationRegression(IntegratedPrimaryTests):
    def test_source_observations_serialized_with_selection(self):
        entered=threading.Event(); release=threading.Event(); second=threading.Event()
        lock=threading.Lock(); calls=[]
        def source():
            with lock:
                n=len(calls); calls.append(n)
            if n==0:
                entered.set(); release.wait(3); return ['alpha']
            second.set(); return []
        self.authority.source=source
        outcomes=[]
        first=threading.Thread(target=lambda:outcomes.append(self.authority.read()))
        later=threading.Thread(target=lambda:outcomes.append(self.authority.read()))
        first.start(); self.assertTrue(entered.wait(2)); later.start()
        premature=second.wait(.15)
        release.set(); first.join(4); later.join(4)
        self.assertFalse(premature, 'newer source must not overtake older observation')
        self.assertFalse(self.authority.registry.snapshot()['connected'])
