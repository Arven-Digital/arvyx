"""Review50 memory regressions. Authored offline; NOT_EXECUTED."""
import hashlib
import json
import os
from types import SimpleNamespace

import pytest


def test_pending_debris_does_not_consume_authority_budget(tmp_path):
    from arvyx_control.import_publication import recover
    lane = tmp_path / '.arvyx/import-publications'
    lane.mkdir(parents=True)
    for i in range(1001):
        (lane / (f'{i:032x}.pending')).write_bytes(b'torn-not-json')
    unrelated = tmp_path / '.import-unowned.stage'
    unrelated.write_bytes(b'preserve')
    recover(tmp_path)
    assert list(lane.iterdir()) == []
    assert unrelated.read_bytes() == b'preserve'
    recover(tmp_path)


def test_pending_collection_is_bounded_and_retryable(tmp_path):
    from arvyx_control.import_publication import recover
    lane = tmp_path / '.arvyx/import-publications'
    lane.mkdir(parents=True)
    for i in range(2002):
        (lane / (f'{i:032x}.pending')).write_bytes(b'')
    with pytest.raises(ValueError, match='retry'):
        recover(tmp_path)
    assert len(list(lane.iterdir())) < 2002
    recover(tmp_path)
    assert not list(lane.iterdir())


def test_materialized_completed_forget_roundtrip_inventory(tmp_path):
    from arvyx_control.composition_recovery import completed_forget_links, composition_read
    vault = tmp_path / 'vault'
    lane = vault / '.arvyx/forget-operations'
    lane.mkdir(parents=True)
    final = vault / 'archive.md'
    stage = vault / ('.forget-' + 'a' * 32 + '.stage')
    payload = b'archived bytes'
    final.write_bytes(payload)
    stage.write_bytes(payload)
    key = 'completed-forget'
    outcome = dict(status='forgotten', idempotency_key=key, archive_path='archive.md',
                   content_sha256=hashlib.sha256(payload).hexdigest())
    record = dict(result=outcome, request_hash='b' * 64, device=123, inode=456,
                  stage_path=stage.name, publication_path=final.name)
    stem = hashlib.sha256(key.encode()).hexdigest()
    (lane / (stem + '.intent.json')).write_text(json.dumps(record))
    (lane / (stem + '.json')).write_text(json.dumps(dict(request_hash='b' * 64, result=outcome)))
    topology = SimpleNamespace(root=tmp_path, vault='vault')
    for _ in range(2):
        proofs = completed_forget_links(topology)
        assert proofs == {}
        assert composition_read(topology, 'vault/' + stage.name, proofs)[0] == payload
    stage.write_bytes(b'conflict')
    with pytest.raises(ValueError, match='content conflict'):
        completed_forget_links(topology)


def test_suggestion_collision_never_overwrites_or_rolls_back_editor(tmp_path, monkeypatch):
    from arvyx_control import writes
    first = tmp_path / 'first.md'
    editor = tmp_path / 'editor.md'
    editor.write_bytes(b'editor owns this')
    with pytest.raises(OSError):
        writes._publish_suggestions([(tmp_path / '.a', first, 'first'),
                                     (tmp_path / '.b', editor, 'second')])
    assert editor.read_bytes() == b'editor owns this'
    assert not first.exists()
    assert not (tmp_path / '.a').exists()
    assert not (tmp_path / '.b').exists()


@pytest.mark.skipif(os.name != 'posix', reason='simulates a POSIX platform without dir_fd')
def test_unsupported_index_reader_is_not_silent_empty(tmp_path, monkeypatch):
    from arvyx_control.index import _source_snapshot
    monkeypatch.setattr(os, 'supports_dir_fd', set())
    with pytest.raises(RuntimeError, match='unavailable'):
        _source_snapshot(tmp_path, 'projects/demo/notes/test.md')


def test_session_ancestor_barrier_failure_prevents_ack(tmp_path, monkeypatch):
    from arvyx_control import session, filesystem
    from contextlib import nullcontext
    from arvyx_control import replica_authority
    monkeypatch.setattr(session, 'vault_lock', lambda root: nullcontext())
    monkeypatch.setattr(replica_authority, 'assert_mutation_authority', lambda root: None)
    calls = []
    def barrier(path):
        calls.append(path)
        if path == tmp_path / 'agents':
            raise OSError('ancestor barrier failed')
    monkeypatch.setattr(filesystem, 'fsync_directory', barrier)
    with pytest.raises(OSError, match='ancestor barrier'):
        session.set_session(tmp_path, 'agent', 'working')
    assert tmp_path in calls
    assert not (tmp_path / 'agents/agent/SESSION-STATE.md').exists()
