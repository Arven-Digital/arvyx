"""Synthetic lane01 regression source. NOT EXECUTED: explicit no-test contract."""
from arvyx_control import safe_open
import hashlib
import json
import os
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from arvyx_control import cockpit_archive as archive, cockpit_archive_authority as authority
from arvyx_control import control, operator_archive
from arvyx_control.auth import OPERATOR_IDENTITY
from arvyx_control.replica_authority import authority_context


@pytest.fixture
def owner(tmp_path):
    db = sqlite3.connect(':memory:')
    db.row_factory = sqlite3.Row
    sessions = {'session': dict(id='session', project='project', task='task', kind='work')}
    registry = tmp_path / 'registry/projects'
    registry.mkdir(parents=True)
    (registry / 'project.json').write_text(json.dumps({'owner_agent_id': 'operator'}))
    def human(actor):
        if actor != 'operator':
            raise ValueError('human required')
    value = SimpleNamespace(db=db, lock=threading.RLock(), vault=tmp_path, host='host',
                            _get=sessions.__getitem__, _human=human, live={}, archive_sync='pending',
                            sessions=sessions, team=SimpleNamespace())
    with db:
        archive._capture_schema(value)
    yield value
    db.close()


def seed(owner, count):
    with owner.db:
        owner.db.executemany('INSERT INTO work_capture(event_id,session,run,text) VALUES(?,?,?,?)',
                            [(f'event{i}', 'session', 'run', 'synthetic text') for i in range(count)])


def test_sink_never_acks_visible_receipt_after_any_409(owner):
    seed(owner, 1)
    calls = []
    def call(method, path, body=None):
        calls.append(method)
        return SimpleNamespace(status=409, body={'error': 'operation_reconciliation_required'})
    owner.team._call = call
    assert archive.sync_capture(owner, authority.governed_sink(owner)) == 0
    assert calls == ['POST']
    assert len(archive.pending_capture(owner)) == 1


def test_retry_uses_original_payload_even_after_mutable_context_changes(owner):
    seed(owner, 1)
    attempts = []
    def call(method, path, body=None):
        if method == 'POST':
            assert isinstance(body, dict)
            attempts.append(dict(body))
            if len(attempts) == 1:
                return SimpleNamespace(status=503, body={})
            payload = {k: v for k, v in body.items() if k not in {'actor', 'idempotency_key'}}
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
            owner.receipt = dict(event_id=body['event_id'], sha256=digest, recorded=True)
            return SimpleNamespace(status=200, body=owner.receipt)
        return SimpleNamespace(status=200, body=owner.receipt)
    owner.team._call = call
    sink = authority.governed_sink(owner)
    assert archive.sync_capture(owner, sink) == 0
    owner.sessions['session'].update(project='other', task='changed')
    owner.host = 'changed-host'
    assert archive.sync_capture(owner, sink) == 1
    assert attempts[0] == attempts[1]


def test_poison_batch_rotates_without_marking_failed_rows_delivered(owner):
    seed(owner, 101)
    def sink(row):
        if row['event_id'] != 'event100':
            raise ValueError('synthetic permanent refusal')
        return row['event_id']
    assert archive.sync_capture(owner, sink) == 0
    assert archive.sync_capture(owner, sink) == 1
    assert len(archive.pending_capture(owner)) == 100
    assert owner.db.execute('SELECT delivered FROM work_capture WHERE event_id=?', ('event100',)).fetchone()[0] == 1


def test_capacity_expansion_retains_all_history_and_resumes_capture(owner, monkeypatch):
    monkeypatch.setattr(archive, 'CAPTURE_CAPACITY', 1600)
    recorder = archive.WorkCapture(owner, 'session', run='run')
    with pytest.raises(BufferError):
        recorder.feed(b'x' * 2048 + b'\n')
    before = list(owner.db.execute('SELECT * FROM work_capture'))
    with pytest.raises(ValueError):
        archive.raise_capture_capacity(owner, actor='agent', expected_bytes=1600, capacity_bytes=100000, reason='synthetic expansion')
    archive.raise_capture_capacity(owner, actor='operator', expected_bytes=1600, capacity_bytes=100000, reason='synthetic expansion')
    assert list(owner.db.execute('SELECT * FROM work_capture')) == before
    recorder.feed(b'x' * 2048 + b'\n')
    recorder.finish()
    rows = archive.export_capture(owner, actor='operator')['records']
    assert [r['text'] for r in rows] == ['x' * 2048 + '\n']
    with pytest.raises(ValueError, match='stale'):
        archive.raise_capture_capacity(owner, actor='operator', expected_bytes=1600, capacity_bytes=200000, reason='synthetic stale request')


def transcript():
    return dict(event_id='synthetic', session='session', run='run', text='Synthetic work.',
                project='', task='', host='host', kind='organizer', agent='operator')


@pytest.mark.skipif(os.name != 'posix', reason='directory fsync barriers are not performed on Windows and file flushes bypass os.fsync (docs/limitations.md, Windows durability)')
def test_existing_only_transcript_replay_repairs_every_barrier(tmp_path, monkeypatch):
    agents = tmp_path / 'registry/agents'
    agents.mkdir(parents=True)
    (agents / 'operator.json').write_text('{}')
    state = tmp_path / 'events.jsonl'
    payload = transcript()
    with authority_context(tmp_path, state):
        authority.append_transcript(tmp_path, state, payload, actor='operator')
        original = state.read_bytes()
        # Mutable enrollment is not needed to repair an exact historical append.
        (agents / 'operator.json').unlink()
        real_fsync = os.fsync
        calls = []
        def observed(fd):
            calls.append(fd)
            return real_fsync(fd)
        monkeypatch.setattr(os, 'fsync', observed)
        result = authority.append_transcript(tmp_path, state, payload, actor='operator', replay_only=True)
        assert result['recorded'] is True
        assert len(calls) >= 4  # blob + blob parent + state + state parent
        assert state.read_bytes() == original
        monkeypatch.setattr(os, 'fsync', lambda fd: (_ for _ in ()).throw(OSError('synthetic barrier failure')))
        with pytest.raises(OSError, match='barrier'):
            authority.append_transcript(tmp_path, state, payload, actor='operator', replay_only=True)
        with pytest.raises(ValueError, match='existing exact'):
            authority.append_transcript(tmp_path, state, dict(payload, event_id='absent'), actor='operator', replay_only=True)


@pytest.mark.skipif(os.name != 'posix', reason='directory fsync barriers are not performed on Windows and file flushes bypass os.fsync (docs/limitations.md, Windows durability)')
@pytest.mark.parametrize('failed_target', ['log', 'parent'])
def test_uncertain_initial_transcript_append_requires_successful_repair(tmp_path, monkeypatch, failed_target):
    agents = tmp_path / 'registry/agents'
    agents.mkdir(parents=True)
    (agents / 'operator.json').write_text('{}')
    state = tmp_path / 'events.jsonl'
    real_fsync = os.fsync
    target = str(state if failed_target == 'log' else state.parent)
    failed = False
    def fail_selected(fd):
        nonlocal failed
        if (not failed and state.exists() and state.stat().st_size > 0
                and safe_open.descriptor_path(fd) == target):
            failed = True
            raise OSError('synthetic uncertain append')
        return real_fsync(fd)
    with authority_context(tmp_path, state):
        monkeypatch.setattr(os, 'fsync', fail_selected)
        with pytest.raises(OSError, match='uncertain'):
            authority.append_transcript(tmp_path, state, transcript(), actor='operator')
        assert failed
        visible = state.read_bytes()
        # Readback is deliberately not an acknowledgement or a repair.
        receipt = authority.transcript_receipt(tmp_path, state, 'synthetic',
            identity=SimpleNamespace(binds_actor=True, agent_id='operator'))
        assert receipt['recorded'] is True
        monkeypatch.setattr(os, 'fsync', real_fsync)
        result = authority.append_transcript(tmp_path, state, transcript(), actor='operator', replay_only=True)
        assert result == receipt
        assert state.read_bytes() == visible


def archive_request(state, task):
    events = [e for e in control.read_events(state) if e.task_id == task.id]
    quote = 'Synthetic exact cancellation, not success.'
    return dict(schema='operator-archive/v1', operation='archive', record_type='task', record_id=task.id,
                expected_event_id=events[-1].id, source_event_id=events[0].id, target='operator',
                history_sha256=operator_archive.history_digest(state, task.id), related_revisions={},
                category='operator_cancelled_no_longer_needed', reason='Synthetic abandonment.',
                approval_reference='synthetic:approval', approval_quote=quote,
                approval_sha256=hashlib.sha256(quote.encode()).hexdigest(),
                evidence_references=['synthetic:evidence'], terminal_event_id='')


def test_task_archive_preserves_original_metadata_and_retry_barrier(tmp_path, monkeypatch):
    monkeypatch.setenv('ARVYX_ENABLE_OPERATOR_ARCHIVE', '1')
    state = tmp_path / 'events.jsonl'
    with authority_context(tmp_path, state):
        task = control.create_task(state, 'Synthetic task', owner='operator',
                                   idempotency_key='synthetic-task-key', created_by='operator').task
        original = dict(control.read_events(state)[-1].payload)
        request = archive_request(state, task)
        first = operator_archive.archive_record(state, record_id=task.id, request=request, identity=OPERATOR_IDENTITY, dry_run=False)
        for key, value in original.items():
            if key not in {'status', 'updated_at', 'retirement'}:
                assert first['record'][key] == value
        def fail(state, event):
            raise OSError('synthetic retry barrier failure')
        monkeypatch.setattr(operator_archive, '_acknowledge_replay_unlocked', fail)
        with pytest.raises(OSError, match='barrier'):
            operator_archive.archive_record(state, record_id=task.id, request=request, identity=OPERATOR_IDENTITY, dry_run=False)
        preview = operator_archive.archive_record(state, record_id=task.id, request=request, identity=OPERATOR_IDENTITY, dry_run=True)
        assert preview['changed'] is False
        assert preview['event_id'] == first['event_id']
