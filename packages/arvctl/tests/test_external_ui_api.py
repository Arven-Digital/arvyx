"""Issuer UI contracts over real ephemeral HTTP; no providers or native owners."""
from datetime import timedelta
import unittest
import test_external_api as helpers


class ExternalUIAPITests(unittest.TestCase):
    setUp = helpers.ExternalAPITests.setUp
    stop = helpers.ExternalAPITests.stop
    request = helpers.ExternalAPITests.request
    issue = helpers.ExternalAPITests.issue

    def test_config_is_live_scoped_and_role_bound(self):
        status, config = self.request('/external/config', 'issuer-token')
        self.assertEqual(status, 200)
        self.assertEqual(config['issuer'], 'marlow')
        self.assertTrue(config['can_export'])
        self.assertEqual(config['ttl_hours'], 24)
        self.assertEqual({x['id'] for x in config['recipients']}, {'grok-cloud','grok-local'})
        self.assertEqual({x['key'] for x in config['resources']}, set(self.resources))
        self.store.set_excluded('workspace:review')
        self.assertEqual(self.request('/external/config','issuer-token')[1]['resources'],
                         [{'key':'task:A','kind':'task','id':'A'}])
        denied = self.request('/external/config','reader-token')[1]
        self.assertFalse(denied['can_export'])
        self.assertEqual(denied['resources'], [])
        for token in ('cloud-token','observer-token','bad-token'):
            self.assertEqual(self.request('/external/config',token)[0],403)

    def test_create_24h_readback_revoke_and_metadata_isolation(self):
        grant = self.issue()
        path = '/external/grants/'+grant
        status, record = self.request(path,'issuer-token')
        self.assertEqual(status,200)
        self.assertEqual(record['issuer'],'marlow')
        self.assertEqual(record['recipient'],'grok-cloud')
        self.assertEqual(record['resources'], sorted(self.resources))
        self.assertEqual(record['state'],'active')
        self.assertEqual(record['expires_at'],(self.now+timedelta(hours=24)).isoformat())
        self.assertEqual(self.request('/external/grants','issuer-token'),(200,[record]))
        self.assertEqual(self.request(path+'/resources/workspace/review')[0],200)
        for token in ('reader-token','cloud-token','local-token','observer-token'):
            self.assertEqual(self.request(path,token)[0],403)
        self.assertEqual(self.request('/external/grants','reader-token'),(200,[]))
        self.assertEqual(self.request('/external/grants','cloud-token')[0],403)
        self.assertEqual(self.request(path+'/revoke','issuer-token',{})[0],200)
        revoked = self.request(path,'issuer-token')[1]
        self.assertEqual(revoked['state'],'revoked')
        self.assertIsNotNone(revoked['revoked_at'])
        self.assertEqual(self.request(path+'/resources/workspace/review')[0],403)
        self.assertEqual(self.request('/external/grants','issuer-token'),(200,[revoked]))

    def test_metadata_state_tracks_expiry_and_authority_without_disclosing_content(self):
        grant = self.issue()
        path = '/external/grants/'+grant
        self.store.set_excluded('task:A')
        self.assertEqual(self.request(path,'issuer-token')[1]['state'],'unavailable')
        self.now += timedelta(hours=24)
        self.assertEqual(self.request(path,'issuer-token')[1]['state'],'expired')
        self.assertEqual(self.request(path+'/resources/workspace/review','issuer-token')[0],403)
        self.assertEqual(self.request('/external/grants/missing','issuer-token')[0],403)

    def test_unknown_recipient_and_foreign_grants_never_leak(self):
        body = dict(recipient='unknown',resources=self.resources,operations=['read'],provenance='fixture')
        self.assertEqual(self.request('/external/grants','issuer-token',body)[0],403)
        self.store.set_authority('other',resources=self.resources,operations=self.ops,can_issue=True,can_export=True)
        self.store.issue(issuer='other',recipient='grok-local',resources=self.resources,
                        operations=['read'],expires_at=self.now+timedelta(hours=1),provenance='private-other')
        self.assertEqual(self.request('/external/grants','issuer-token'),(200,[]))
