from test_cockpit_local import HarmlessOwnerConnectionTests
import json
import threading

class PrimaryReviewRegressionTests(HarmlessOwnerConnectionTests):
    def test_native_identity_mismatch_cannot_elect(self):
        host=self.owner.snapshot(actor='operator')['host']
        base=self.home/'vault/registry'
        for agent in ('alpha','beta'):
            (base/('agents/'+agent+'.json')).write_text(json.dumps(dict(id=agent,machine_id=host,runtime_id='codex-demo')))
        state=self.http('/api/primary-agent')[1]
        self.assertEqual(state['primary_agent_id'],'alpha')
        self.assertFalse(state['primary_connected'])

    def test_presence_observation_is_serialized(self):
        a_started, release, b_sampled=threading.Event(), threading.Event(), threading.Event()
        authority=self.server.primary
        def source():
            if threading.current_thread().name=='observation-A':
                a_started.set(); release.wait(2); return ['alpha']
            b_sampled.set(); return []
        authority.source=source
        errors=[]
        def read():
            try: authority.read()
            except Exception as e: errors.append(e)
        a=threading.Thread(target=read,name='observation-A')
        b=threading.Thread(target=read,name='observation-B')
        a.start(); self.assertTrue(a_started.wait(1)); b.start()
        sampled_before_release=b_sampled.wait(.2)
        release.set(); a.join(3); b.join(3)
        self.assertFalse(errors)
        self.assertFalse(sampled_before_release,'a newer observation must not commit before older sample')
        self.assertFalse(authority.registry.snapshot()['connected'])
