"""Synthetic regression specifications; not executed in the static-only repair."""
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import test_external_api as helpers
from arvyx_control.public_onboarding_api import PublicOnboardingAPI, assert_request_active, _request_deadline


class ManifestDisclosureTests(unittest.TestCase):
    setUp = helpers.ExternalAPITests.setUp
    stop = helpers.ExternalAPITests.stop
    request = helpers.ExternalAPITests.request

    def test_exact_manifest_has_byte_units_hashes_and_opaque_exclusions(self):
        status, config = self.request('/external/config', 'issuer-token')
        self.assertEqual(status, 200)
        manifest = next(r['manifest'] for r in config['resources'] if r['kind']=='workspace')
        self.assertEqual(manifest['coverage'], 'selection')
        self.assertFalse(manifest['complete'])
        data = b'selected review bytes'
        self.assertEqual(manifest['files'], [dict(path='safe.txt',size_bytes=len(data),sha256=hashlib.sha256(data).hexdigest())])
        self.assertEqual(manifest['excluded'], [dict(path='.env',reason='secret-or-private')])
        self.assertNotIn('root', manifest)
        body = dict(recipient='grok-cloud', resources=['workspace:review'],operations=['read'],provenance='synthetic review',reviewed_manifests={'workspace:review':manifest})
        self.assertEqual(self.request('/external/grants','issuer-token',body)[0],201)
        body['reviewed_manifests'] = {}
        self.assertEqual(self.request('/external/grants','issuer-token',body)[0],400)


class ServerNameAndDeadlineTests(unittest.TestCase):
    def test_name_check_uses_creation_unicode_casefold_contract(self):
        api = PublicOnboardingAPI(credentials={},owners={})
        owner = SimpleNamespace(extension=None,creation=SimpleNamespace(list_agents=lambda:[SimpleNamespace(name='Straße'),SimpleNamespace(name='Nova')]))
        for name in ('STRASSE','ＳＴＲＡＳＳＥ','Ｎova'):
            self.assertEqual(api._route('synthetic',owner,'POST','agents/name-check',dict(name=name)),(409,dict(error='duplicate_agent_name',field='name')))
        self.assertEqual(api._route('synthetic',owner,'POST','agents/name-check',dict(name='Distinct')),(200,dict(available=True)))

    def test_expired_listener_deadline_refuses_admission(self):
        _request_deadline.expires = 10
        try:
            with patch('arvyx_control.public_onboarding_api.time.monotonic', return_value=10):
                with self.assertRaises(TimeoutError):
                    assert_request_active()
        finally:
            del _request_deadline.expires
        assert_request_active()  # Direct trusted calls have no listener deadline.
