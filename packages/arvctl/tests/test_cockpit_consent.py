"""Consent binds exact bytes; reconnect never sends a draft."""
import os
import unittest
from unittest.mock import patch
import test_cockpit_surface as fixtures


@unittest.skipUnless(os.name == 'posix', 'the PTY owner fixture (host-environment natives) is POSIX-only')
class ConsentTests(unittest.TestCase):
    setUp = fixtures.SurfaceTests.setUp
    session = fixtures.SurfaceTests.session

    def test_draft_is_durable_and_exact_content_consent_required(self):
        from arvyx_control.cockpit_consent import stage_draft, send_draft, drafts
        first = self.session('first')
        draft = stage_draft(self.service, first['id'], 'hello', actor='operator')
        self.assertEqual(drafts(self.service, first['id'], actor='operator')[0]['status'], 'draft')
        self.service.start(first['id'], actor='operator', environment='host')
        lease = self.service.attach(first['id'], actor='operator')
        with self.assertRaisesRegex(ValueError, 'consent'):
            send_draft(self.service, draft['id'], consent='wrong', attachment=lease['attachment'], actor='operator')
        with patch.object(self.service, 'write', side_effect=OSError('lost ACK')) as write:
            with self.assertRaises(OSError):
                send_draft(self.service, draft['id'], consent=draft['sha256'], attachment=lease['attachment'], actor='operator')
            with self.assertRaisesRegex(ValueError, 'ambiguous'):
                send_draft(self.service, draft['id'], consent=draft['sha256'], attachment=lease['attachment'], actor='operator')
            self.assertEqual(write.call_count, 1)

    def test_context_requires_separate_explicit_recall_consent(self):
        from arvyx_control.cockpit_consent import stage_draft
        first = self.session('first')
        with self.assertRaisesRegex(ValueError, 'context consent'):
            stage_draft(self.service, first['id'], 'hello', context='recalled facts', actor='operator')
        draft = stage_draft(self.service, first['id'], 'hello', context='recalled facts', context_consent=True, actor='operator')
        self.assertEqual(draft['text'], 'recalled facts\n\nhello')

    def test_drafts_page_beyond_fifty_and_exact_selection_never_lists_history(self):
        from arvyx_control.cockpit_consent import stage_draft, drafts, send_draft
        first = self.session('first')['id']
        other = self.session('other')['id']
        staged = [stage_draft(self.service, first, f'draft {n}', actor='operator') for n in range(51)]
        page = drafts(self.service, first, actor='operator')
        self.assertEqual(len(page), 50)
        final = drafts(self.service, first, actor='operator', after=page[-1]['cursor'])
        self.assertEqual([row['id'] for row in final], [staged[-1]['id']])
        selected = drafts(self.service, first, actor='operator', identifier=staged[-1]['id'])
        self.assertEqual(selected[0]['id'], staged[-1]['id'])
        with patch.object(self.service, 'write') as write:
            with self.assertRaisesRegex(ValueError, 'exact fleet session'):
                send_draft(self.service, staged[-1]['id'], sid=other,
                    consent=staged[-1]['sha256'], attachment='fixture', actor='operator')
            write.assert_not_called()

    def test_archive_deduplicates_exact_events_and_rejects_secret_literals(self):
        from arvyx_control.cockpit_archive import append_record, records
        first = self.session('first')
        record = append_record(self.service, first['id'], event_id='event-one', source='native-transcript', text='fixture result', actor='operator')
        self.assertEqual(append_record(self.service, first['id'], event_id='event-one', source='native-transcript', text='fixture result', actor='operator'), record)
        self.assertEqual(len(records(self.service, first['id'], actor='operator')['records']), 1)
        with self.assertRaisesRegex(ValueError, 'conflict'):
            append_record(self.service, first['id'], event_id='event-one', source='native-transcript', text='changed', actor='operator')
        with self.assertRaises(ValueError):
            # Assemble an unmistakably synthetic marker at runtime so the
            # repository scanner need not waive a committed PEM-shaped block.
            kind = 'PRIVATE' + ' KEY'
            marker = '-----BEGIN ' + kind + '-----\nfixture\n-----END ' + kind + '-----'
            append_record(self.service, first['id'], event_id='event-two', source='native-transcript', text=marker, actor='operator')
        self.assertEqual(len(records(self.service, first['id'], actor='operator')['records']), 1)
