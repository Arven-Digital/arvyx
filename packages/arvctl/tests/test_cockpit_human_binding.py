from contextlib import closing
import json
from test_cockpit_local import HarmlessOwnerConnectionTests

class HumanBindingTests(HarmlessOwnerConnectionTests):
    def prepare(self):
        # Independent binding scenario: reset only disposable coordination state.
        registry = self.server.primary.registry
        with registry._transaction():
            registry.db.execute('DELETE FROM primary_events')
            registry.db.execute('DELETE FROM primary_connections')
            registry.db.execute('UPDATE primary_agent SET agent_id=NULL,revision=0')
        # Isolated harmless owner: remove organizer identity metadata only in test.
        self.owner.db.execute('DELETE FROM native_organizers')
        self.owner.db.commit()
        sessions, _ = self.server.bindings.facts()
        self.facts = sessions[0]
        vault=self.home/'vault/registry'
        (vault/'runtimes').mkdir(exist_ok=True)
        (vault/'machines').mkdir(exist_ok=True)
        (vault/'machines'/(self.facts['host']+'.json')).write_text(json.dumps(dict(id=self.facts['host'])))
        (vault/'runtimes/gemini-test.json').write_text(json.dumps(dict(id='gemini-test',harness='gemini')))
        for agent in ('alpha','beta'):
            (vault/'agents'/ (agent+'.json')).write_text(json.dumps(dict(id=agent,machine_id=self.facts['host'],runtime_id='gemini-test')))
        return dict(self.facts,agent_id='alpha',revision=0)

    def test_missing_machine_registry_rejected(self):
        payload=self.prepare()
        (self.home/'vault/registry/machines'/(self.facts['host']+'.json')).unlink()
        self.assertEqual(self.http('/api/local-bindings',payload)[0],409)

    def test_bind_first_primary_no_native_change(self):
        payload=self.prepare()
        before=self.owner.snapshot(actor='operator')['sessions']
        self.assertEqual(self.http('/api/local-bindings',payload)[0],200)
        self.assertEqual(self.http('/api/primary-agent')[1]['primary_agent_id'],'alpha')
        self.assertEqual(self.owner.snapshot(actor='operator')['sessions'],before)
        self.assertEqual(self.server.bindings.read()['bindings'][0]['agent_id'],'alpha')

    def test_wrong_session_host_agent_runtime_rejected(self):
        payload=self.prepare()
        for field,value in [('session','wrong'),('host','wrong'),('agent_id','missing'),('tool','hermes'),('pid',1)]:
            self.assertEqual(self.http('/api/local-bindings',dict(payload,**{field:value}))[0],409)
        path=self.home/'vault/registry/agents/alpha.json'
        path.write_text(json.dumps(dict(id='alpha',machine_id='wrong',runtime_id='gemini-test')))
        self.assertEqual(self.http('/api/local-bindings',payload)[0],409)

    def test_signed_binding_survives_reopen_and_tampering_fails_closed(self):
        from arvyx_control.cockpit_human_binding import HumanBindings
        import sqlite3
        payload=self.prepare()
        self.assertEqual(self.http('/api/local-bindings',payload)[0],200)
        reopened=HumanBindings(self.home,self.server.primary)
        self.assertEqual(reopened.connected(),['alpha'])
        with closing(sqlite3.connect(reopened.path)) as db, db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0],1)
            db.execute('UPDATE bindings SET revision=99')
        self.assertEqual(reopened.connected(),[])

    def test_unauthorized_stale_rebind_disconnect_persist(self):
        payload=self.prepare()
        self.assertEqual(self.http('/api/local-bindings',payload,auth=False)[0],403)
        self.assertEqual(self.http('/api/local-bindings',payload,origin=False)[0],403)
        self.assertEqual(self.http('/api/local-bindings',payload)[0],200)
        self.assertEqual(self.http('/api/local-bindings',payload)[0],409)
        self.assertEqual(self.http('/api/local-bindings',dict(payload,agent_id='beta',revision=1))[0],409)
        self.http('/api/primary-agent')
        self.owner.end(payload['session'],actor='operator')
        state=self.http('/api/primary-agent')[1]
        self.assertEqual(state['primary_agent_id'],'alpha')
        self.assertFalse(state['primary_connected'])
        self.assertEqual(self.server.bindings.read()['bindings'][0]['revision'],1)
