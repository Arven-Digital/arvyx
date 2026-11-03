"""Authored boundary regressions, NOT EXECUTED; not product acceptance.

Explicit selection is required after integration and execution authorization.
These tests do not provide the missing live runtime, private input, 31-hit
replacement audit, or aggregate seven-failure reconciliation.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import tempfile
import unittest


class Focus75Agent10Boundaries(unittest.TestCase):
    def test_rev0138_metadata_selection_never_launches(self):
        from arvyx_control.hermes_history import HermesHistory
        from arvyx_control.agent_sessions import RoutingError
        target = object()
        owner = SimpleNamespace(target=target, exact=Mock(return_value={'id': 'synthetic-session'}))
        guard = Mock()
        with patch('arvyx_control.hermes_history.subprocess.call') as spawn:
            result = HermesHistory.perform(owner, target, 'select', 'synthetic-session', publication_guard=guard)
            self.assertEqual(result, {'id': 'synthetic-session'})
            owner.exact.assert_called_once_with('synthetic-session')
            guard.assert_called_once_with()
            owner.exact.reset_mock()
            with self.assertRaises(RoutingError):
                HermesHistory.perform(owner, target, 'launch', 'synthetic-session')
            with self.assertRaises(RoutingError):
                HermesHistory.perform(owner, object(), 'select', 'synthetic-session')
            owner.exact.assert_not_called()
            spawn.assert_not_called()

    def test_rev0139_unprovisioned_owner_advertises_no_executor(self):
        from arvyx_control.local_onboarding import LocalOnboarding
        owner = SimpleNamespace(delegations=None, native=None, workspace_roots={}, pairing=None, sources={})
        result = LocalOnboarding.capabilities(owner)
        self.assertEqual(result['delegation_targets'], [])
        self.assertFalse(result['native_lifecycle'])
        self.assertFalse(result['pairing'])
        modes = {mode['id']: mode['available'] for mode in result['environments']}
        self.assertEqual(modes, {'metadata': True, 'sandbox': False, 'host': False, 'root': False})
        # Pairing becoming available must not promote any executor mode.
        owner.pairing = object()
        paired = LocalOnboarding.capabilities(owner)
        self.assertTrue(paired['pairing'])
        self.assertEqual(paired['environments'], result['environments'])

    def test_rev0150_absent_private_input_vetoes_audit(self):
        from arvyx_control import audit
        # No environment lookup or real denylist read: simulate an empty scan.
        with patch.object(audit, 'scan_private_context', return_value=(set(), 0, False, 0)):
            check = audit._private_context_check(Path('synthetic-unused-root'))
        self.assertFalse(check.ok)
        self.assertIn('private context denylist was not loaded', check.findings)
        self.assertIn('audit check failed: private_context', audit._failed_check_blockers([check]))

    def test_rev0151_unknown_font_and_moved_fingerprint_fail_closed(self):
        from arvyx_control.security import is_verified_font, reviewed_line_fingerprint
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic.woff2'
            raw = bytearray(48)
            raw[:4] = b'wOF2'
            raw[8:12] = len(raw).to_bytes(4, 'big')
            path.write_bytes(raw)
            self.assertFalse(is_verified_font(path))
            path.write_bytes(raw + b'appended synthetic data')
            self.assertFalse(is_verified_font(path))
        line = 'synthetic harmless fixture text'
        self.assertNotEqual(reviewed_line_fingerprint(Path('fixture-a.txt'), line),
                            reviewed_line_fingerprint(Path('fixture-b.txt'), line))
        self.assertNotEqual(reviewed_line_fingerprint(Path('fixture-a.txt'), line),
                            reviewed_line_fingerprint(Path('fixture-a.txt'), line + ' changed'))

    def test_rev0152_aggregate_preserves_strict_scan_and_all_test_lanes(self):
        # This protects wiring only; it does NOT prove any CI result.
        root = Path(__file__).resolve().parents[3]
        lines = (root / 'Makefile').read_text(encoding='utf-8').splitlines()
        ci = next(line for line in lines if line.startswith('ci:')).split(':', 1)[1].split()
        tests = next(line for line in lines if line.startswith('test:')).split(':', 1)[1].split()
        self.assertIn('release-scan', ci)
        self.assertIn('test', ci)
        self.assertNotIn('scan-shapes', ci)
        self.assertEqual(set(tests), {'test-python', 'test-frontend', 'test-npm'})
        index = lines.index('release-scan:')
        self.assertEqual(lines[index + 1].strip(), '$(PYTHON) scripts/private_context_scan.py')
