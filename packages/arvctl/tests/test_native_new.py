"""First-session boundary evidence; never dispatch a provider or native process."""
import sqlite3
from unittest.mock import Mock, patch

import pytest
from arvyx_control.cockpit_arvyx import _open_frontend
from arvyx_control.cockpit_native_runtime import NativeRuntime


def test_frontend_requires_real_tty_before_owner_read_or_creation(tmp_path):
    frontend = tmp_path / 'frontend'
    with patch('os.isatty', return_value=False), patch('arvyx_control.cockpit_client.request') as request:
        with pytest.raises(ValueError, match='interactive terminal required'):
            _open_frontend(tmp_path, frontend, Mock())
    request.assert_not_called()
    assert not frontend.exists()


def test_blank_profile_cannot_initialize_owner_new_protocol(tmp_path):
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    binary = tmp_path / 'hermes'
    binary.write_text('#!/bin/sh\nexit 99\n')
    from arvyx_control import private_paths
    private_paths.make_private(path=binary, mode=0o700)
    # NativeRuntime requires an existing metadata store before plan_new can run.
    with pytest.raises(FileNotFoundError):
        NativeRuntime(tool='hermes', executable=binary, home=profile,
                      store=profile / 'state.db', new_protocol='hermes-titled-create-v1')
    assert not (profile / 'state.db').exists()


def test_empty_placeholder_database_is_not_a_bootstrap(tmp_path):
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    (profile / 'state.db').touch(mode=0o600)
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    binary = tmp_path / 'hermes'
    binary.write_text('#!/bin/sh\nexit 99\n')
    from arvyx_control import private_paths
    private_paths.make_private(path=binary, mode=0o700)
    runtime = NativeRuntime(tool='hermes', executable=binary, home=profile,
                            store=profile / 'state.db', new_protocol='hermes-titled-create-v1')
    # Native planning is read-only: it must not invent the Hermes schema.
    with pytest.raises(sqlite3.OperationalError, match='no such table: sessions'):
        runtime.plan_new('arvyx-new-' + 'a' * 32, workspace)


@pytest.mark.parametrize('allowed', [False, True])
def test_runtime_executable_uses_platform_write_policy(tmp_path, monkeypatch, allowed):
    """Mode bits are not Windows ACLs; use the shared platform policy."""
    import sys
    from pathlib import Path
    from arvyx_control import private_paths
    home = tmp_path / 'profile'
    home.mkdir(mode=0o700)
    (home / 'state.db').touch(mode=0o600)
    executable = Path(sys.executable).resolve()
    checked = Mock(return_value=allowed)
    monkeypatch.setattr(private_paths, 'not_writable_by_others', checked)
    def construct():
        return NativeRuntime(tool='hermes', executable=executable, home=home,
                             store=home / 'state.db')
    if allowed:
        assert construct().executable == executable
    else:
        with pytest.raises(ValueError, match='native executable/home references'):
            construct()
    checked.assert_called_once()
    assert checked.call_args.kwargs['path'] == executable


def test_direct_native_new_is_not_exposed(capsys):
    from arvyx_control.onboarding_cli import main
    with pytest.raises(SystemExit) as stopped:
        main(['native-new'])
    assert stopped.value.code == 2
    assert 'invalid choice' in capsys.readouterr().err
