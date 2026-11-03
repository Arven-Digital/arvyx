from arvyx_control.local_executor import ExecutionPolicy
"""Native conversation bindings: directory reopening is never resume."""
import sys
import time
import os
import unittest
from pathlib import Path
import test_cockpit_surface as fixtures


@unittest.skipUnless(os.name == 'posix', 'the PTY owner fixture (host-environment natives) is POSIX-only')
class AdapterTests(unittest.TestCase):
    setUp = fixtures.SurfaceTests.setUp
    session = fixtures.SurfaceTests.session

    def test_resume_argv_is_exact_and_never_shell_text(self):
        from arvyx_control.cockpit_adapters import resume_plan
        self.assertEqual(resume_plan('codex', 'abc-123'), ['codex', 'resume', 'abc-123'])
        self.assertEqual(resume_plan('claude', 'abc-123'), ['claude', '--resume', 'abc-123'])
        for identity in ['', '--last', 'a\nb', 'a;rm', '../session']:
            with self.assertRaises(ValueError):
                resume_plan('codex', identity)
        with self.assertRaises(ValueError):
            resume_plan('unknown', 'abc')

    def test_native_binding_survives_restart_and_requires_explicit_resume(self):
        from arvyx_control.cockpit import LocalCockpit
        first = self.session('first')
        binding = self.service.bind_native(first['id'], tool='codex', conversation='native-123', actor='operator')
        self.assertEqual(binding['conversation'], 'native-123')
        with self.assertRaisesRegex(ValueError, 'native'):
            self.service.start(first['id'], actor='operator', environment='host')
        self.service.close()
        self.service = LocalCockpit(self.root / 'runtime', self.root / 'vault', self.root / 'events.jsonl', 'laptop-a', execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))
        self.assertEqual(self.service.native(first['id'], actor='operator'), binding)
        self.assertEqual(self.service.list()[0]['status'], 'stopped')
        with self.assertRaises(PermissionError):
            self.service.bind_native(first['id'], tool='codex', conversation='other', actor='agent')
        with self.assertRaisesRegex(ValueError, 'fixed'):
            self.service.bind_native(first['id'], tool='claude', conversation='other', actor='operator')

    def test_fixture_native_process_reports_same_conversation_after_resume(self):
        first = self.session('first')
        self.service.bind_native(first['id'], tool='fixture', conversation='fixture-123', actor='operator')
        self.service.start_native(first['id'], actor='operator', fixture=True)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            output = self.service.read(first['id'], actor='operator')['output']
            if 'fixture-123' in output:
                break
            time.sleep(.02)
        self.assertIn('NATIVE fixture-123', output)
        self.assertEqual(self.service.native(first['id'], actor='operator')['conversation'], 'fixture-123')
        self.assertEqual(list(Path(first['workspace']).iterdir()), [])

    def test_fixture_is_not_available_without_explicit_fixture_flag(self):
        first = self.session('first')
        self.service.bind_native(first['id'], tool='fixture', conversation='fixture-123', actor='operator')
        with self.assertRaisesRegex(ValueError, 'fixture'):
            self.service.start_native(first['id'], actor='operator', environment='host')
        self.assertEqual(self.service.list()[0]['status'], 'stopped')
