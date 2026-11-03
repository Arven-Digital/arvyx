from arvyx_control.local_executor import ExecutionPolicy
"""Shared layout contracts; no provider or remote resources required."""
import os
import unittest
import test_cockpit_surface as fixtures


@unittest.skipUnless(os.name == 'posix', 'the PTY owner fixture (host-environment natives) is POSIX-only')
class SharedLayoutTests(unittest.TestCase):
    setUp = fixtures.SurfaceTests.setUp
    session = fixtures.SurfaceTests.session

    def test_layout_is_shared_revisioned_and_survives_owner_restart(self):
        from arvyx_control.cockpit import LocalCockpit
        first, second = self.session('first'), self.session('second')
        before = self.service.view()
        result = self.service.layout([first['id'], second['id']], selected=second['id'],
                                     revision=before['revision'], actor='operator')
        self.assertEqual(result['panels'], [first['id'], second['id']])
        self.assertEqual(result['selected'], second['id'])
        with self.assertRaisesRegex(ValueError, 'stale'):
            self.service.select(first['id'], revision=before['revision'], actor='operator')
        self.service.close()
        self.service = LocalCockpit(self.root / 'runtime', self.root / 'vault', self.root / 'events.jsonl', 'laptop-a', execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))
        self.assertEqual(self.service.view(), result)

    def test_bad_layout_is_atomic(self):
        first = self.session('first')
        for panels, selected in [([], first['id']), ([first['id']] * 2, first['id']),
                                 (['unknown'], 'unknown'), ([first['id']], 'unknown'),
                                 ('not-a-list', None)]:
            before = self.service.view()
            with self.assertRaises(ValueError):
                self.service.layout(panels, selected=selected, revision=before['revision'], actor='operator')
            self.assertEqual(self.service.view(), before)

    def test_selection_adds_panel_and_detach_does_not_remove_it(self):
        first = self.session('first')
        result = self.service.select(first['id'], revision=0, actor='operator')
        self.assertEqual(result['panels'], [first['id']])
        self.service.start(first['id'], actor='operator', environment='host')
        lease = self.service.attach(first['id'], actor='operator')
        self.service.detach(first['id'], attachment=lease['attachment'], actor='operator')
        self.assertEqual(self.service.view(), result)

    def test_layout_requires_human_and_strict_revision(self):
        for revision in [True, -1, '0']:
            with self.assertRaises(ValueError):
                self.service.layout([], selected=None, revision=revision, actor='operator')
        with self.assertRaises(PermissionError):
            self.service.layout([], selected=None, revision=0, actor='agent')
