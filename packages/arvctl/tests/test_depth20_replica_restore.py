"""Unexecuted depth20 regressions; all Docker effects are mocked."""
import ast
from pathlib import Path
from unittest.mock import Mock

import pytest
from arvyx_control import replica
from arvyx_control import cockpit_archive_authority as archive

ROOT = Path(__file__).resolve().parents[3]


def test_unowned_authority_rejected_before_any_effect(tmp_path, monkeypatch):
    state = tmp_path / 'primary-state'
    state.mkdir()
    control = state / 'control-events.jsonl'
    control.write_bytes(b'captured\nnewer-append\n')
    audit = state / 'audit-log.jsonl'
    audit.write_bytes(b'audit-newer\n')
    lock = Mock(side_effect=AssertionError('no lock creation allowed'))
    monkeypatch.setattr(replica, 'vault_lock', lock)
    monkeypatch.setattr(replica, 'exclusive_lock', lock)
    monkeypatch.setattr(replica, '_get_json', Mock(side_effect=AssertionError('no network')))
    with pytest.raises(ValueError, match='unowned'):
        replica.sync_replica('http://source', tmp_path / 'new-replica', state_dir=state)
    assert control.read_bytes() == b'captured\nnewer-append\n'
    assert audit.read_bytes() == b'audit-newer\n'
    assert not (tmp_path / 'new-replica').exists()
    lock.assert_not_called()


def test_state_owner_exact_vault_and_source(tmp_path):
    import json
    state = tmp_path / 'state'
    state.mkdir()
    vault = tmp_path / 'replica'
    (state / '.arvyx-replica-state.json').write_text(json.dumps(
        replica._replica_state_owner(vault, 'http://source')))
    replica._validate_replica_state_owner(state, vault, 'http://source')
    for other_vault, source in [(tmp_path / 'other', 'http://source'), (vault, 'http://other')]:
        with pytest.raises(ValueError, match='another replica'):
            replica._validate_replica_state_owner(state, other_vault, source)


def test_archive_ancestor_failure_prevents_receipt(tmp_path, monkeypatch):
    from contextlib import nullcontext
    vault = tmp_path / 'vault'
    registry = vault / 'registry/agents'
    registry.mkdir(parents=True)
    (registry / 'agent.json').write_text('{}')
    monkeypatch.setattr(archive.control, '_locked_state', lambda state: nullcontext())
    monkeypatch.setattr(archive.control, 'list_tasks', lambda state: type('Tasks', (), {'tasks': []})())
    monkeypatch.setattr(archive.control, '_idempotent_event', lambda *args: None)
    append = Mock()
    monkeypatch.setattr(archive.control, '_append_event_unlocked', append)
    monkeypatch.setattr(archive, 'durable_mkdir', Mock(side_effect=OSError('ancestor fsync')))
    payload = dict(event_id='event', session='session', run='run', text='bounded work',
                   project='', task='', host='host', kind='organizer', agent='agent')
    with pytest.raises(OSError, match='ancestor fsync'):
        archive.append_transcript(vault, tmp_path / 'control', payload, actor='agent')
    append.assert_not_called()


def test_restore_barrier_is_after_shutdown_before_cutover():
    # Source contract complements fault injection without starting/importing Docker.
    source = (ROOT / 'scripts/backup_restore.py').read_text()
    tree = ast.parse(source)
    restore = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_restore_private')
    calls = [n for n in ast.walk(restore) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
    barrier = next(n.lineno for n in calls if n.func.id == '_persist_candidate_volume')
    pointer = next(n.lineno for n in calls if n.func.id == '_atomic_update_active_volume')
    assert barrier < pointer
    before = source.splitlines()[:barrier - 1]
    assert any('staging_cleanup_owned = False' in line for line in before[-12:])


def _load_backup_script():
    import importlib.util
    spec = importlib.util.spec_from_file_location('depth20_backup_restore', ROOT / 'scripts/backup_restore.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('interrupted', [False, True])
@pytest.mark.parametrize('restart_fails', [False, True])
def test_failed_stop_effect_is_reconciled(tmp_path, monkeypatch, interrupted, restart_fails):
    import subprocess
    from types import SimpleNamespace
    module = _load_backup_script()
    monkeypatch.setattr(module, '_assert_data_volume', Mock())
    monkeypatch.setattr(module, '_expected_data_volume', lambda *args: 'volume')
    healthy = Mock(return_value='original')
    monkeypatch.setattr(module, '_wait_healthy', healthy)
    events = []
    running = True
    original_error = KeyboardInterrupt() if interrupted else subprocess.CalledProcessError(1, ['compose', 'stop'])

    def run(command, **kwargs):
        nonlocal running
        if 'inspect' in command:
            return SimpleNamespace(stdout='true' if running else 'false')
        if 'ps' in command:
            return SimpleNamespace(stdout='original')
        if 'stop' in command:
            running = False
            raise original_error
        if command[:2] == ['docker', 'start']:
            events.append(command)
            if restart_fails:
                raise OSError('restart failed')
            running = True
        return SimpleNamespace(stdout='')

    monkeypatch.setattr(module, '_run', run)
    with pytest.raises(type(original_error)) as caught:
        module.backup.__wrapped__(project='synthetic', backup_dir=tmp_path / 'backups',
                                  off_host_dir=None, local_only=True, retention=1)
    assert caught.value is original_error
    assert events == [['docker', 'start', 'original']]
    if restart_fails:
        assert caught.value.restart_failed is True
        assert isinstance(caught.value.reconciliation_error, OSError)
    else:
        healthy.assert_called_once()
        assert running


def test_barrier_failure_propagates_and_is_ownership_bound(monkeypatch):
    module = _load_backup_script()
    ownership = Mock()
    monkeypatch.setattr(module, '_verify_candidate_volume_ownership', ownership)
    run = Mock(side_effect=OSError('file or directory fsync failed'))
    monkeypatch.setattr(module, '_run', run)
    with pytest.raises(OSError, match='fsync failed'):
        module._persist_candidate_volume(candidate_volume='candidate', project='project',
                                        ownership_token='operation', production_env={})
    ownership.assert_called_once()
    command = run.call_args.args[0]
    assert '--network' in command and 'none' in command
    assert 'type=volume,src=candidate,dst=/candidate' in command


@pytest.mark.parametrize('restart_failed', [False, True])
def test_backup_cli_redacts_subprocess_argv_and_preserves_reconciliation(monkeypatch, restart_failed):
    import json
    import subprocess
    import sys
    module = _load_backup_script()
    error = subprocess.CalledProcessError(7, ['docker', '-c', 'private embedded program'],
                                          stderr='private daemon output')
    if restart_failed:
        error.restart_failed = True
    monkeypatch.setattr(module, 'backup', Mock(side_effect=error))
    monkeypatch.setattr(sys, 'argv', ['backup_restore.py', 'backup', '--backup-dir', 'unused', '--local-only'])
    printed = Mock()
    monkeypatch.setattr('builtins.print', printed)
    assert module.main() == 1
    payload = json.loads(printed.call_args.args[0])
    assert payload['message'] == 'external command failed with exit status 7'
    assert 'private' not in json.dumps(payload)
    assert payload.get('restart_failed', False) is restart_failed
    assert payload.get('reconciliation_required', False) is restart_failed


def test_initially_stopped_backup_uses_all_container_discovery_and_never_starts(tmp_path, monkeypatch):
    from types import SimpleNamespace
    module = _load_backup_script()
    monkeypatch.setattr(module, '_assert_data_volume', Mock())
    monkeypatch.setattr(module, '_expected_data_volume', lambda *args: 'volume')
    commands = []
    failure = OSError('capture failed')

    def run(command, **kwargs):
        commands.append(command)
        if 'ps' in command:
            assert '-aq' in command
            return SimpleNamespace(stdout='original')
        return SimpleNamespace(stdout='false' if 'inspect' in command else '')

    monkeypatch.setattr(module, '_run', run)
    monkeypatch.setattr(module, '_capture_container_data', Mock(side_effect=failure))
    healthy = Mock(side_effect=AssertionError('stopped service must remain stopped'))
    monkeypatch.setattr(module, '_wait_healthy', healthy)
    with pytest.raises(OSError) as caught:
        module.backup.__wrapped__(project='synthetic', backup_dir=tmp_path / 'backups',
                                  off_host_dir=None, local_only=True, retention=1)
    assert caught.value is failure
    assert not any(command[:2] == ['docker', 'start'] for command in commands)
    healthy.assert_not_called()


def test_candidate_program_descriptor_and_directory_barriers():
    tree = ast.parse((ROOT / 'scripts/backup_restore.py').read_text())
    value = next(n.value.value for n in tree.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == '_CANDIDATE_FSYNC_PROGRAM' for t in n.targets))
    ast.parse(value)
    assert 'os.O_NOFOLLOW' in value
    assert 'os.fsync(child)' in value
    assert 'os.fsync(fd)' in value
    assert value.index('flush_directory(child)') < value.index('os.fsync(fd)')
