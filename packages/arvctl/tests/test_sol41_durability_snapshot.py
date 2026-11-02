from arvyx_control.replica_authority import authority_context
"""Candidate 41 scoped regressions. NOT_EXECUTED during the static fix round."""
import os
from pathlib import Path

import pytest

from arvyx_control import control, filesystem, promotion_transaction as promotion


def test_existing_directory_chain_gets_root_to_leaf_barriers(tmp_path, monkeypatch):
    leaf = tmp_path / 'project' / 'notes'
    leaf.mkdir(parents=True)  # A caller created these without namespace barriers.
    calls = []
    monkeypatch.setattr(filesystem, 'fsync_directory', calls.append)
    filesystem.durable_mkdir(leaf)
    expected = list(reversed([leaf, *leaf.parents]))
    assert calls == expected


def test_promotion_barrier_failure_preserves_source(tmp_path, monkeypatch):
    source = tmp_path / 'pending.md'
    source.write_bytes(b'original')
    target = tmp_path / 'project' / 'notes' / 'accepted.md'
    def fail(path, **kwargs):
        raise OSError('directory barrier failed')
    monkeypatch.setattr(promotion, 'durable_mkdir', fail)
    with pytest.raises(OSError, match='directory barrier'):
        promotion.publish(tmp_path, source, target, b'accepted', {}, source_bytes=b'original')
    assert source.read_bytes() == b'original'
    assert not target.exists()


def test_first_control_append_file_sync_precedes_directory_sync(tmp_path, monkeypatch):
    state = tmp_path / 'new' / 'state.jsonl'
    calls = []
    real_sync = os.fsync
    def file_sync(fd):
        calls.append('file')
        real_sync(fd)
    class Event:
        def to_dict(self):
            return {'type': 'test'}
    monkeypatch.setattr(control.os, 'fsync', file_sync)
    monkeypatch.setattr(control, 'fsync_directory', lambda path: calls.append(('directory', path)))
    with authority_context(tmp_path / "authority-vault", state):
        control._append_event_unlocked(state, Event())
    assert calls[-2:] == ['file', ('directory', state.parent)]
    assert state.read_bytes().endswith(b'\n')


def test_control_directory_failure_is_not_acknowledged(tmp_path, monkeypatch):
    class Event:
        def to_dict(self):
            return {'type': 'test'}
    def fail(path):
        raise OSError('namespace barrier failed')
    monkeypatch.setattr(control, 'fsync_directory', fail)
    with pytest.raises(OSError, match='namespace barrier'):
        with authority_context(tmp_path / "authority-vault", tmp_path / 'state.jsonl'):
            control._append_event_unlocked(tmp_path / 'state.jsonl', Event())
