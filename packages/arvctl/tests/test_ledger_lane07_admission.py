"""Synthetic regression specifications; not executed during ledger remediation."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock

from arvyx_control.cockpit_human_binding import HumanBindings


class HumanAdmissionDeadlineTests(TestCase):
    def test_enrollment_lock_uses_absolute_deadline_and_timeout_publishes_nothing(self):
        binding = HumanBindings.__new__(HumanBindings)
        binding.home = Path('/synthetic-owner-not-created')
        binding.primary = SimpleNamespace(
            authorization='synthetic',
            registry=SimpleNamespace(_identity=mock.Mock()))
        payload = dict(session='s', host='h', tool='hermes', conversation='c',
                       pid=123, display_name='Synthetic')

        @contextmanager
        def blocked(vault, *, deadline):
            self.assertEqual(vault, binding.home / 'vault')
            self.assertEqual(deadline, 105)
            raise TimeoutError('synthetic contention')
            yield

        with mock.patch('arvyx_control.cockpit_human_binding.time.monotonic', return_value=100), \
                mock.patch('arvyx_control.locks.vault_lock', blocked), \
                mock.patch('arvyx_control.cockpit_human_binding.sqlite3.connect') as connect:
            with self.assertRaises(TimeoutError):
                binding.enroll(payload)
            connect.assert_not_called()
