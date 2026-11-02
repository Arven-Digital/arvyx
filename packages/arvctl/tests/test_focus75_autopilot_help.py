"""Help contract regressions. Authored offline; NOT_EXECUTED in focus75."""
import subprocess
import sys

import pytest


@pytest.mark.parametrize('arguments', [['--help'], ['autopilot', '--help']])
def test_delegation_help_distinguishes_default_from_configured_driver(arguments):
    result = subprocess.run(
        [sys.executable, '-m', 'arvyx_control.cockpit_client', *arguments],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stderr
    text = ' '.join(result.stdout.split())
    assert 'no runner by default' in text
    assert 'explicitly configured operator driver' in text
    assert 'assignment does not configure a driver or authorize provider access' in text
    assert 'no prompt runner or provider invocation' not in text
