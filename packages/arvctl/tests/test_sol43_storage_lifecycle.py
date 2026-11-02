from arvyx_control.replica_authority import authority_context
"""Storage lifecycle regression source. NOT_EXECUTED in this static round."""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from arvyx_control import control, filesystem, forget, promotion_transaction as tx
from arvyx_control.vault import init_vault
from arvyx_control.writes import suggest_memory, promote_memory


def test_interrupted_forget_fences_parent_promotion_and_all_mutations(tmp_path, monkeypatch):
    vault = tmp_path / 'vault'
    init_vault(vault)
    parent = vault / 'projects/demo-agent/notes/parent.md'
    parent.parent.mkdir(parents=True, exist_ok=True)
    parent.write_text('---\nstatus: curated\n---\nOriginal parent\n')
    from arvyx_control.writes import suggest_memory_batch
    pending = suggest_memory_batch(vault=vault, project='demo-agent', author='operator',
        payload={'memories': [{'title': 'Replacement', 'content': 'replacement',
            'content_class': 'durable_fact', 'memory_class': 'dynamic',
            'future_job': 'Preserve curated relation behavior during memory review.',
            'assistant_suggestion_accepted': False,
            'relations': [{'type': 'updates', 'parent_source_path': parent.relative_to(vault).as_posix()}]}]}).suggestions[0]
    original = parent.read_bytes()
    real_json = forget._atomic_json

    def interrupt(path, payload):
        if str(path).endswith('.tombstone.json'):
            raise OSError('tombstone interrupted')
        return real_json(path, payload)

    args = (vault, 'demo-agent', parent.relative_to(vault).as_posix(),
            'incorrect', 'batch-43', 'operator', 'forget-candidate-43')
    with monkeypatch.context() as m:
        m.setattr(forget, '_atomic_json', interrupt)
        with pytest.raises(OSError, match='tombstone interrupted'):
            forget.soft_forget(*args)
    with pytest.raises(RuntimeError, match='unfinished'):
        promote_memory(vault, 'demo-agent', pending.path, 'operator')
    with pytest.raises(RuntimeError, match='unfinished'):
        suggest_memory(vault, 'demo-agent', 'Other', 'other', 'operator')
    with pytest.raises(RuntimeError, match='unfinished'):
        with tx.memory_mutation(vault, forget_recovery=('forget-candidate-43', '0' * 64)):
            pytest.fail('different request must not enter')
    assert parent.read_bytes() == original
    result = forget.soft_forget(*args)
    assert result.status == 'forgotten'
    assert not parent.exists()
    with tx.memory_mutation(vault):
        pass


def test_ownership_precedes_mode_and_file_barrier(tmp_path, monkeypatch):
    stage = tmp_path / 'stage'
    stage.write_bytes(b'original')
    events = []
    infos = iter([SimpleNamespace(st_uid=0, st_gid=0),
                  SimpleNamespace(st_uid=10001, st_gid=10001)])
    monkeypatch.setattr(tx.os, 'fstat', lambda fd: next(infos))
    monkeypatch.setattr(tx.os, 'fchown', lambda fd, uid, gid: events.append(('owner', uid, gid)), raising=False)
    monkeypatch.setattr(tx.os, 'fchmod', lambda fd, mode: events.append(('mode', mode)))
    monkeypatch.setattr(tx.os, 'fsync', lambda fd: events.append('sync'))
    tx.apply_original_metadata(stage, {'uid': 10001, 'gid': 10001, 'mode': 0o600})
    assert events == [('owner', 10001, 10001), ('mode', 0o600), 'sync']


def test_ownership_failure_and_legacy_metadata_fail_closed(tmp_path, monkeypatch):
    stage = tmp_path / 'stage'
    stage.write_bytes(b'original')
    with pytest.raises(OSError, match='ownership missing'):
        tx.apply_original_metadata(stage, {'mode': 0o600})
    monkeypatch.setattr(tx.os, 'fstat', lambda fd: SimpleNamespace(st_uid=0, st_gid=0))
    def denied(*args):
        raise PermissionError('ownership denied')
    monkeypatch.setattr(tx.os, 'fchown', denied, raising=False)
    monkeypatch.setattr(tx.os, 'fchmod', lambda *args: pytest.fail('mode before ownership'))
    with pytest.raises(PermissionError, match='ownership denied'):
        tx.apply_original_metadata(stage, {'uid': 10001, 'gid': 10001, 'mode': 0o600})


def test_windows_control_append_skips_only_directory_barrier(tmp_path, monkeypatch):
    log = tmp_path / 'control.jsonl'
    class Event:
        def to_dict(self):
            return {'type': 'storage-test'}
    real_fsync = os.fsync
    calls = []
    monkeypatch.setattr(filesystem, 'os', SimpleNamespace(**dict(vars(os),name='nt')))
    def syncing(fd):
        calls.append(fd)
        return real_fsync(fd)
    monkeypatch.setattr(control.os, 'fsync', syncing)
    with authority_context(tmp_path / "authority-vault", log):
        control._append_event_unlocked(log, Event())
    assert calls
    assert log.read_bytes().endswith(b'\n')


def test_posix_directory_barrier_failures_propagate(tmp_path, monkeypatch):
    def denied(*args):
        raise OSError('directory denied')
    monkeypatch.setattr(filesystem, 'os', SimpleNamespace(name='posix', O_RDONLY=0,
                        O_DIRECTORY=0, open=denied))
    with pytest.raises(OSError, match='directory denied'):
        filesystem.fsync_directory(tmp_path)


def test_snapshot_unit_has_only_original_vault_data_exception():
    repo = Path(__file__).resolve().parents[3]
    if not (repo / 'deploy/systemd/arvyx-v2-snapshot.service').is_file():
        pytest.skip('deployment units are not part of this checkout (public candidate)')
    unit = (repo / 'deploy/systemd/arvyx-v2-snapshot.service').read_text()
    assert 'ReadOnlyPaths=/srv/arvyx-v2/data\n' in unit
    assert 'ReadWritePaths=/srv/arvyx-v2/data/vault -/srv/arvyx-v2/snapshot-commits /run/arvyx-v2\n' in unit
