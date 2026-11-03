"""Deep20 regression sources. Not executed during the source-only fix round."""
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from arvyx_control import importers as imp
from arvyx_control import promotion_transaction as tx
from arvyx_control.snapshot_guard import snapshot_preparation


def test_import_stage_collision_preserves_unowned_file(tmp_path):
    from contextlib import nullcontext
    from types import SimpleNamespace
    source = tmp_path / 'note.md'
    source.write_text('ordinary body', encoding='utf-8')
    vault = tmp_path / 'vault'
    lane = vault / 'projects/demo/imported'
    lane.mkdir(parents=True)
    collision = lane / '.import-fixed.stage'
    collision.write_bytes(b'other operation')
    with patch.object(imp, 'memory_mutation', lambda _: nullcontext()), patch.object(
            imp.uuid, 'uuid4', return_value=SimpleNamespace(hex='fixed')):
        with pytest.raises(FileExistsError):
            imp.import_markdown(source, vault, 'demo')
    assert collision.read_bytes() == b'other operation'
    assert not (lane / 'note.md').exists()


def test_rejected_filename_does_not_escape_receipt(tmp_path):
    source = tmp_path / 'private-source'
    source.mkdir()
    token = 'ghp_' + 'a' * 36
    (source / (token + '.md')).write_text('ordinary body', encoding='utf-8')
    vault = tmp_path / 'vault'
    vault.mkdir()
    with patch.object(imp, 'memory_mutation', lambda _: __import__('contextlib').nullcontext()):
        result = imp.import_markdown(source, vault, 'demo')
    receipt = (vault / result.manifest_path).read_text()
    assert token not in receipt + result.to_json()
    assert str(source) not in receipt + result.to_json()
    assert len(result.skipped) == 1


def test_failed_stage_never_publishes_markdown(tmp_path):
    source = tmp_path / 'note.md'
    source.write_text('multibyte ' + '\N{SNOWMAN}' * 100, encoding='utf-8')
    vault = tmp_path / 'vault'
    vault.mkdir()
    with patch.object(imp, 'memory_mutation', lambda _: __import__('contextlib').nullcontext()), patch.object(imp.os, 'fsync', side_effect=OSError('disk full')):
        with pytest.raises(OSError):
            imp.import_markdown(source, vault, 'demo')
    assert not list((vault / 'projects').rglob('*.md'))


def test_manifest_directory_barrier_failure_is_not_success(tmp_path):
    lane = tmp_path / 'lane'
    lane.mkdir()
    with patch.object(imp, 'fsync_directory', side_effect=OSError('barrier')):
        with pytest.raises(OSError):
            imp._write_manifest(tmp_path, lane, 'demo', 'imported', [], [], False)


def test_replayed_restoration_repeats_parent_barrier(tmp_path):
    note = tmp_path / 'note.md'
    note.write_bytes(b'original')
    journal = tmp_path / '.arvyx' / 'promotions' / 'one'
    journal.mkdir(parents=True)
    row = dict(path='note.md', backup='original', original=[0, 0, 'old'], published=None,
               uid=note.stat().st_uid, gid=note.stat().st_gid, mode=0o644, source=True)
    note.chmod(0o644)
    (journal / 'original.restored.json').write_text(json.dumps(tx.identity(note)))
    with patch.object(tx, 'sync', side_effect=OSError('barrier')) as barrier:
        assert not tx.rollback(tmp_path, journal, dict(files=[row]))
    barrier.assert_called_once_with(tmp_path)


def test_absent_new_target_repeats_parent_barrier(tmp_path):
    journal = tmp_path / 'journal'
    journal.mkdir()
    row = dict(path='new.md', backup='new', original=None, published=[1, 2, 'digest'])
    with patch.object(tx, 'sync', side_effect=OSError('barrier')):
        assert not tx.rollback(tmp_path, journal, dict(files=[row]))


def test_gc_interruption_never_replays_partial_authority(tmp_path):
    root = tmp_path / '.arvyx' / 'promotions'
    journal = root / 'one'
    journal.mkdir(parents=True)
    (journal / 'manifest.json').write_text(json.dumps(dict(files=[])))
    with patch.object(tx.shutil, 'rmtree', side_effect=OSError('interrupted GC')):
        with pytest.raises(OSError):
            tx.clean(journal, dict(files=[]))
    assert not journal.exists()
    assert (root / '.gc-one' / 'manifest.json').exists()
    with patch.object(tx, 'rollback', side_effect=AssertionError('retired journal replayed')):
        tx.recover(tmp_path)
    assert not list(root.iterdir())


@pytest.mark.skipif(os.name != 'posix', reason='POSIX mode bits and umask')
def test_marker_metadata_uses_journal_authority(tmp_path):
    journal = tmp_path / 'journal'
    journal.mkdir()
    (journal / 'original').write_bytes(b'original')
    info = journal.stat()
    row = dict(backup='original', original=[0, 0, tx.identity(journal / 'original')[2]],
               uid=info.st_uid, gid=info.st_gid, mode=0o600)
    tx.restoration(journal, row)
    marker = journal / 'original.restored.json'
    assert (marker.stat().st_uid, marker.stat().st_gid) == (info.st_uid, info.st_gid)
    assert marker.stat().st_mode & 0o777 == 0o600


def test_explicit_owner_mismatch_creates_no_lock(tmp_path):
    info = tmp_path.stat()
    with pytest.raises(OSError, match='configured authority'):
        with snapshot_preparation(tmp_path, owner=(info.st_uid + 1, info.st_gid)):
            pytest.fail('mismatched authority admitted')
    assert not (tmp_path / '.arvyx').exists()


@pytest.mark.skipif(not hasattr(os, 'geteuid') or os.geteuid() != 0, reason='requires isolated privileged two-UID host')
def test_root_snapshot_preserves_runtime_lock_inode(tmp_path):
    # pytest owns these isolated ancestors; permit traversal by the test UID.
    tmp_path.parent.parent.chmod(0o711)
    tmp_path.parent.chmod(0o711)
    tmp_path.chmod(0o700)
    os.chown(tmp_path, 10001, 10001)
    # Admission is mocked only to isolate lock ownership from registry setup.
    with patch('arvyx_control.replica_authority.assert_mutation_authority'), patch.object(tx, 'assert_copyable_forget_operations'):
        with snapshot_preparation(tmp_path, owner=(10001, 10001)):
            lock = tmp_path / '.arvyx' / 'vault.lock'
            identity = lock.stat().st_ino
            assert lock.stat().st_uid == 10001
        with snapshot_preparation(tmp_path, owner=(10001, 10001)):
            assert lock.stat().st_ino == identity
    assert (tmp_path / '.arvyx').stat().st_uid == 10001
