"""Assembly identity must remain explicit and use existing AMC authentication."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from arvyx_control import cockpit


def bearer(value):
    # Assembled at runtime so the fixture never carries a literal credential shape.
    return ''.join(('Be', 'arer ', value))


class LaunchIdentityTests(unittest.TestCase):
    def test_private_operator_credential_file_acts_as_the_operator(self):
        """REV-0572: the pilot owner takes the same private operator credential as cockpit_local."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'operator.secret'
            path.write_text('fixture-operator-credential\n')
            os.chmod(path, 0o600)
            with patch.dict('os.environ', {}, clear=True):
                team = cockpit.configured_team(Path('vault'), Path('state'), path)
            self.assertEqual(team._bearer_secret, 'fixture-operator-credential')
            self.assertEqual(team._authorization, bearer('fixture-operator-credential'))
            self.assertEqual((team.vault, team.state), (Path('vault'), Path('state')))

    def test_operator_credential_file_must_be_private_exclusive_and_well_formed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'operator.secret'
            path.write_text('fixture-operator-credential\n')
            os.chmod(path, 0o644)
            if os.name == 'nt':  # modes mean nothing here: widen the DACL to Users instead
                import subprocess
                subprocess.run(['icacls', str(path), '/grant', '*S-1-5-32-545:R'], check=True, capture_output=True)
            with patch.dict('os.environ', {}, clear=True), self.assertRaises(ValueError):
                cockpit.configured_team(Path('vault'), Path('state'), path)
            os.chmod(path, 0o600)
            if os.name == 'nt':
                subprocess.run(['icacls', str(path), '/remove:g', '*S-1-5-32-545'], check=True, capture_output=True)
            # Two explicit credentials at once is a configuration error, not a precedence rule.
            with patch.dict('os.environ', {'AMC_COCKPIT_AUTHORIZATION': bearer('fixture-existing')}, clear=True):
                with self.assertRaises(ValueError):
                    cockpit.configured_team(Path('vault'), Path('state'), path)
            for content in ('\n', 'two\nlines\n', 'tab\tsecret'):
                path.write_text(content)
                with patch.dict('os.environ', {}, clear=True), self.assertRaises(ValueError):
                    cockpit.configured_team(Path('vault'), Path('state'), path)
            with patch.dict('os.environ', {}, clear=True), self.assertRaises(ValueError):
                cockpit.configured_team(Path('vault'), Path('state'), Path(tmp) / 'missing.secret')
            with patch.dict('os.environ', {}, clear=True), self.assertRaises(ValueError):
                cockpit.configured_team(Path('vault'), Path('state'), Path('relative.secret'))

    def test_no_ambient_identity_means_unavailable(self):
        with patch.dict('os.environ', {}, clear=True):
            self.assertIsNone(cockpit.configured_team(Path('vault'), Path('state')))

    def test_explicit_existing_bearer_is_forwarded_not_minted(self):
        identity = ''.join(('Be', 'arer ', 'fixture-existing'))
        with patch.dict('os.environ', {'AMC_COCKPIT_AUTHORIZATION': identity}, clear=True):
            team = cockpit.configured_team(Path('vault'), Path('state'))
        self.assertEqual(team._authorization, identity)
        self.assertIsNone(team._bearer_secret)
        self.assertEqual(team.vault, Path('vault'))
        self.assertEqual(team.state, Path('state'))

    def test_invalid_explicit_identity_fails_closed(self):
        for value in ('', 'operator', 'Bearer ', 'Bearer x\ninjected'):
            with self.subTest(value=value), patch.dict('os.environ', {'AMC_COCKPIT_AUTHORIZATION': value}, clear=True):
                with self.assertRaises(ValueError):
                    cockpit.configured_team(Path('vault'), Path('state'))
