"""Authored regressions; NOT_EXECUTED under the Focus75 static-only scope.

Run only after overlay integration and explicit targeted-test authorization.
These checks do not approve a native artifact or establish installed acceptance.
"""
from pathlib import Path
from unittest.mock import patch
import pytest


def test_native_check_preserves_requested_capability(monkeypatch):
    from arvyx_control import native_install
    observed = []
    monkeypatch.setattr(native_install, 'check', lambda destination, **kwargs: observed.append((destination, kwargs)) or {})
    assert native_install.main(['--check', '/explicit/native', '--require-capability', 'onboarding-v1']) == 0
    assert observed == [(Path('/explicit/native'), {'required_capability': 'onboarding-v1'})]


def test_native_check_forwards_capability_to_byte_policy(tmp_path, monkeypatch):
    from arvyx_control import native_install
    directory = tmp_path / 'native'
    directory.mkdir(mode=0o700)
    (directory / 'native-install.json').write_text('{"binary_sha256":"not-an-approval"}')
    monkeypatch.setattr(native_install, 'read_native_bytes', lambda binary: b'unapproved')
    observed = []
    def refuse(data, metadata, *, required_capability):
        observed.append(required_capability)
        raise ValueError('approved native artifact lacks the requested capability')
    monkeypatch.setattr(native_install, 'verify_native_bytes', refuse)
    with pytest.raises(ValueError, match='lacks the requested capability'):
        native_install.check(directory, required_capability='onboarding-v1')
    assert observed == ['onboarding-v1']


@pytest.mark.parametrize('options', [
    {'native_frontend': '/explicit/frontend'},
    {'native_binary': '/explicit/binary'},
    {'native_frontend': '/explicit/frontend', 'native_binary': '/explicit/binary'},
    {'external': object(), 'external_config': '/explicit/config'},
])
def test_local_composition_rejects_invalid_options_before_owner_or_listener(options):
    from arvyx_control import cockpit_local
    with patch.object(cockpit_local, 'inspect_existing_owner') as inspect, patch.object(cockpit_local, 'LocalServer') as server:
        with pytest.raises(ValueError):
            cockpit_local.build_local_server('/unused/connection', '/unused/frontend', operator_secret='local-test-only', **options)
        inspect.assert_not_called()
        server.assert_not_called()
