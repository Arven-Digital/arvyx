import json
from test_cockpit_human_binding import HumanBindingTests


class LocalEnrollmentTests(HumanBindingTests):
    def enrollment(self):
        self.prepare()
        return dict(self.facts, display_name='My explicit local agent')

    def test_explicit_registration_then_binding(self):
        payload = self.enrollment()
        before = self.owner.snapshot(actor='operator')['sessions']
        old = (self.home/'vault/registry/agents/alpha.json').read_bytes()
        status, result = self.http('/api/local-enrollments', payload)
        self.assertEqual(status, 201)
        agent = result['agent']
        self.assertNotIn(agent['id'], ('alpha', 'beta', 'operator'))
        self.assertEqual(agent['machine_id'], self.facts['host'])
        self.assertEqual(agent['scopes'], [])
        self.assertEqual(self.http('/api/primary-agent')[1]['primary_agent_id'], None)
        self.assertEqual(self.http('/api/local-bindings', dict(self.facts, agent_id=agent['id'], revision=0))[0], 200)
        self.assertEqual(self.http('/api/primary-agent')[1]['primary_agent_id'], agent['id'])
        self.assertEqual(self.owner.snapshot(actor='operator')['sessions'], before)
        self.assertEqual((self.home/'vault/registry/agents/alpha.json').read_bytes(), old)

    def test_enrollment_requires_auth_origin_exact_facts_and_name(self):
        payload = self.enrollment()
        self.assertEqual(self.http('/api/local-enrollments', payload, auth=False)[0], 403)
        self.assertEqual(self.http('/api/local-enrollments', payload, origin=False)[0], 403)
        for change in (dict(pid=1), dict(host='wrong'), dict(display_name=''), dict(display_name='x\n'), dict(agent_id='alpha')):
            self.assertEqual(self.http('/api/local-enrollments', dict(payload, **change))[0], 409)
        self.assertEqual(self.http('/api/local-enrollments', payload)[0], 201)
        self.assertEqual(self.http('/api/local-enrollments', payload)[0], 409)

    def test_enrollment_is_once_per_session_and_preserves_name(self):
        payload=self.enrollment()
        status,result=self.http('/api/local-enrollments',payload)
        self.assertEqual(status,201)
        self.assertEqual(self.http('/api/local-enrollments',dict(payload,display_name='Different name'))[0],409)
        row=next(a for a in self.http('/api/local-bindings')[1]['agents'] if a['id']==result['agent']['id'])
        self.assertEqual(row['display_name'],payload['display_name'])

    def test_bad_registry_shapes_fail_closed_without_connection_drop(self):
        self.prepare()
        root=self.home/'vault/registry'
        (root/'agents/bad.json').write_text('[]')
        (root/'agents/broken.json').write_text('{broken')
        (root/'runtimes/gemini-test.json').write_text('[]')
        self.assertEqual(self.http('/api/local-bindings')[0],200)
        self.assertEqual(self.server.bindings.connected(),[])

    def test_enrollment_failure_removes_new_runtime_and_agent(self):
        from unittest.mock import patch
        import os
        payload=self.enrollment()
        root=self.home/'vault/registry'
        before={str(p):p.read_bytes() for p in root.rglob('*.json')}
        original=os.open
        def fail_agent(path,*args,**kwargs):
            if '/agents/local-' in str(path):
                raise OSError('injected local publication failure')
            return original(path,*args,**kwargs)
        with patch('arvyx_control.cockpit_human_binding.os.open',side_effect=fail_agent):
            self.assertEqual(self.http('/api/local-enrollments',payload)[0],503)
        self.assertEqual({str(p):p.read_bytes() for p in root.rglob('*.json')},before)

    def test_one_agent_cannot_bind_two_conversations(self):
        payload = self.prepare()
        self.assertEqual(self.http('/api/local-bindings', payload)[0], 200)
        other = next(s for s in self.server.bindings.facts()[0] if s['session'] != self.facts['session'])
        self.assertEqual(self.http('/api/local-bindings', dict(other, agent_id='alpha', revision=0))[0], 409)
