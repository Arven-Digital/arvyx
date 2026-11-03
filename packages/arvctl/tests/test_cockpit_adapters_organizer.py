"""Organizer context delegates to existing authenticated AMC session authority."""
import os
import unittest
from arvyx_control.api import handle_api_request
import test_cockpit_surface as fixtures


@unittest.skipUnless(os.name == 'posix', 'the PTY owner fixture (host-environment natives) is POSIX-only')
class OrganizerTests(unittest.TestCase):
    setUp = fixtures.SurfaceTests.setUp

    def test_existing_session_authority_roundtrip_and_explicit_content_consent(self):
        from arvyx_control.cockpit_adapters_organizer import OrganizerContext
        def api(method, route, body):
            return handle_api_request(method, route, body, vault=self.root / 'vault', state=self.root / 'events.jsonl',
                                      bearer_secret='fixture-only', authorization='Bearer fixture-only', allow_unauthenticated_demo=False)
        organizer = OrganizerContext(api)
        with self.assertRaisesRegex(ValueError, 'consent'):
            organizer.write('demobot', 'fixture organizer context', consent=False, idempotency_key='test-000000000001')
        result = organizer.write('demobot', 'fixture organizer context', consent=True, idempotency_key='test-000000000001')
        self.assertEqual(result.status, 201, result.body)
        result = organizer.read('demobot')
        self.assertEqual(result.status, 200, result.body)
        self.assertIn('fixture organizer context', str(result.body))

    def test_missing_identity_does_not_fall_back_to_direct_session_writer(self):
        from arvyx_control.cockpit_adapters_organizer import OrganizerContext
        def api(method, route, body):
            return handle_api_request(method, route, body, vault=self.root / 'vault', state=self.root / 'events.jsonl', allow_unauthenticated_demo=False)
        result = OrganizerContext(api).write('demobot', 'denied', consent=True, idempotency_key='fixture-organizer-denied')
        self.assertEqual(result.status, 401)

    def test_owner_without_configured_identity_reports_unavailable(self):
        with self.assertRaisesRegex(ValueError, 'identity unavailable'):
            self.service.organizer('demobot', actor='operator')
        with self.assertRaises(PermissionError):
            self.service.organizer('demobot', actor='agent')

    def test_configured_owner_uses_same_existing_authority(self):
        from types import SimpleNamespace
        def api(method, route, body):
            return handle_api_request(method, route, body, vault=self.root / 'vault', state=self.root / 'events.jsonl',
                                      bearer_secret='fixture-only', authorization='Bearer fixture-only', allow_unauthenticated_demo=False)
        self.service.team = SimpleNamespace(_call=api)
        result = self.service.organizer('demobot', actor='operator', content='owner fixture', consent=True, idempotency_key='owner-organizer-1')
        self.assertEqual(result['status'], 201, result)
        self.assertIn('owner fixture', str(self.service.organizer('demobot', actor='operator')['body']))
