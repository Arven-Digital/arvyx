"""Audit/receipt cut regression source. NOT_EXECUTED in this static fix round."""
import importlib.util
import sqlite3
from contextlib import closing
from pathlib import Path

import os
import pytest
from pathlib import Path as _Path
pytestmark = [pytest.mark.skipif(not (_Path(__file__).resolve().parents[3] / 'deploy').is_dir(), reason='deployment tree is not part of this checkout (public candidate)'), pytest.mark.skipif(os.name != 'posix', reason='the deployment scripts take POSIX locks and fail closed elsewhere')]


@pytest.fixture
def snapshot():
    path = Path(__file__).resolve().parents[3] / 'deploy/systemd/arvyx-v2-snapshot.py'
    spec = importlib.util.spec_from_file_location('sol44_snapshot', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_old_audit_prefix_with_new_written_receipt_is_rejected(tmp_path, monkeypatch, snapshot):
    data = tmp_path / 'source'
    (data / 'audit').mkdir(parents=True)
    (data / 'state').mkdir()
    audit = data / 'audit/audit-log.jsonl'
    audit.write_bytes(b'{"event":"old"}\n')
    db = data / 'state/operations.sqlite3'
    with closing(sqlite3.connect(db)) as connection, connection:
        connection.execute('CREATE TABLE receipts (event TEXT, status TEXT)')
    monkeypatch.setattr(snapshot, 'DATA', data)
    monkeypatch.setattr(snapshot, 'INCLUDES', ('audit', 'state'))
    original_digest = snapshot.digest
    advanced = False

    def append_then_mark_written(path, deadline=None):
        nonlocal advanced
        if path == db and not advanced:
            # Manifest A already observed audit L. The append and receipt commit
            # complete before A observes the operations database.
            audit.write_bytes(audit.read_bytes() + b'{"event":"new"}\n')
            with closing(sqlite3.connect(db)) as connection, connection:
                connection.execute('INSERT INTO receipts VALUES (?, ?)', ('new', 'written'))
            advanced = True
        return original_digest(path, deadline)

    monkeypatch.setattr(snapshot, 'digest', append_then_mark_written)
    a = snapshot.manifest(data)
    stage = tmp_path / 'stage'
    snapshot.copy_tree(stage, a)
    b = snapshot.manifest(data)
    c = snapshot.manifest(stage)
    assert advanced
    assert a['state/operations.sqlite3'] == b['state/operations.sqlite3'] == c['state/operations.sqlite3']
    with closing(sqlite3.connect(stage / 'state/operations.sqlite3')) as connection, connection:
        assert connection.execute('SELECT event, status FROM receipts').fetchall() == [('new', 'written')]
    assert a['audit/audit-log.jsonl'] != b['audit/audit-log.jsonl']
    assert not snapshot.stable_cut(a, b, c)


def test_manifest_and_copy_preserve_complete_audit_bytes(tmp_path, monkeypatch, snapshot):
    data = tmp_path / 'source'
    (data / 'audit').mkdir(parents=True)
    # Even a trailing fragment must not be silently discarded by prefix capture
    # or by verification of the copied/restored generation.
    payload = b'{"event":"old"}\n{"event":'
    (data / 'audit/audit-log.jsonl').write_bytes(payload)
    monkeypatch.setattr(snapshot, 'DATA', data)
    monkeypatch.setattr(snapshot, 'INCLUDES', ('audit',))
    a = snapshot.manifest(data)
    stage = tmp_path / 'stage'
    snapshot.copy_tree(stage, a)
    assert a['audit/audit-log.jsonl']['size'] == len(payload)
    assert (stage / 'audit/audit-log.jsonl').read_bytes() == payload
    assert snapshot.stable_cut(a, snapshot.manifest(data), snapshot.manifest(stage))
    with (stage / 'audit/audit-log.jsonl').open('ab') as stream:
        stream.write(b'"extra"}')
    assert snapshot.manifest(stage) != a


@pytest.mark.parametrize('relative', [
    'state/control-events.jsonl',
    'mirror/receipts.jsonl',
    'mirror/quarantine-receipts.jsonl',
])
def test_receipt_and_control_logs_require_full_generation(tmp_path, monkeypatch, snapshot, relative):
    data = tmp_path / 'source'
    control = data / relative
    control.parent.mkdir(parents=True)
    first = b'{"event":"old"}\n'
    control.write_bytes(first)
    monkeypatch.setattr(snapshot, 'DATA', data)
    monkeypatch.setattr(snapshot, 'INCLUDES', (Path(relative).parts[0],))
    a = snapshot.manifest(data)
    with control.open('ab') as stream:
        stream.write(b'{"event":"new"}\n{"partial":')
    stage = tmp_path / 'stage'
    snapshot.copy_tree(stage, a)
    assert (stage / relative).read_bytes() == control.read_bytes()
    assert not snapshot.stable_cut(a, snapshot.manifest(data), snapshot.manifest(stage))
    current = snapshot.manifest(data)
    assert snapshot.stable_cut(current, current, snapshot.manifest(stage))
    with (stage / relative).open('ab') as stream:
        stream.write(b'"extra"}')
    assert snapshot.manifest(stage) != current


def test_old_control_prefix_with_new_completed_journal_is_rejected(tmp_path, monkeypatch, snapshot):
    data = tmp_path / 'source'
    (data / 'state').mkdir(parents=True)
    (data / 'audit').mkdir()
    control = data / 'state/control-events.jsonl'
    control.write_bytes(b'{"event":"old"}\n')
    journal = data / 'audit/audit-log.jsonl.operations.sqlite3'
    # Minimal on-disk journal fixture: no production API or runtime is invoked.
    with closing(sqlite3.connect(journal)) as connection, connection:
        connection.execute('CREATE TABLE operations (operation_id TEXT, state TEXT)')
    monkeypatch.setattr(snapshot, 'DATA', data)
    # Match production traversal: state is captured before audit/journal.
    monkeypatch.setattr(snapshot, 'INCLUDES', ('state', 'audit'))
    original_digest = snapshot.digest
    advanced = False

    def complete_after_control_capture(path, deadline=None):
        nonlocal advanced
        if path == journal and not advanced:
            with control.open('ab') as stream:
                stream.write(b'{"event":"task.created","id":"new"}\n')
            with closing(sqlite3.connect(journal)) as connection, connection:
                connection.execute('INSERT INTO operations VALUES (?, ?)', ('new', 'completed'))
            advanced = True
        return original_digest(path, deadline)

    monkeypatch.setattr(snapshot, 'digest', complete_after_control_capture)
    a = snapshot.manifest(data)
    stage = tmp_path / 'stage'
    snapshot.copy_tree(stage, a)
    b = snapshot.manifest(data)
    c = snapshot.manifest(stage)
    assert advanced
    rel = 'audit/audit-log.jsonl.operations.sqlite3'
    assert a[rel] == b[rel] == c[rel]
    with closing(sqlite3.connect(stage / rel)) as connection, connection:
        assert connection.execute('SELECT operation_id, state FROM operations').fetchall() == [('new', 'completed')]
    assert a['state/control-events.jsonl'] != b['state/control-events.jsonl']
    assert not snapshot.stable_cut(a, b, c)

