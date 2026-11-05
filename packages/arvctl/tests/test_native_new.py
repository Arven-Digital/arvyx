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
    binary.chmod(0o700)
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
    binary.chmod(0o700)
    runtime = NativeRuntime(tool='hermes', executable=binary, home=profile,
                            store=profile / 'state.db', new_protocol='hermes-titled-create-v1')
    # Native planning is read-only: it must not invent the Hermes schema.
    with pytest.raises(sqlite3.OperationalError, match='no such table: sessions'):
        runtime.plan_new('arvyx-new-' + 'a' * 32, workspace)


def test_direct_native_new_is_not_exposed(capsys):
    from arvyx_control.onboarding_cli import main
    with pytest.raises(SystemExit) as stopped:
        main(['native-new'])
    assert stopped.value.code == 2
    assert 'invalid choice' in capsys.readouterr().err
