"""Offline capture -> authenticated API -> journal/barriers -> outbox recovery."""
import hashlib
import json
import os
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from arvyx_control import api, cockpit_archive as capture, control
from arvyx_control.cockpit_archive_authority import governed_sink
from arvyx_control.operation_journal import journal_path


def owner_at(tmp_path):
    vault = tmp_path / 'vault'
    agents = vault / 'registry/agents'
    agents.mkdir(parents=True, exist_ok=True)
    (agents / 'operator.json').write_text('{}')
    db = sqlite3.connect(tmp_path / 'capture.sqlite3')
    db.row_factory = sqlite3.Row
    db.execute('CREATE TABLE IF NOT EXISTS native_organizers(session TEXT PRIMARY KEY,agent TEXT)')
    db.execute("INSERT OR IGNORE INTO native_organizers VALUES('session','operator')")
    db.commit()
    owner = SimpleNamespace(db=db, lock=threading.RLock(), vault=vault, host='original-host',
        _get=lambda sid: dict(id=sid, kind='organizer', project='', task=''))
    calls = []
    state = tmp_path / 'state/events.jsonl'
    audit = tmp_path / 'audit/events.jsonl'

    def call(method, route, body=None):
        response = api.handle_api_request(method, route, body, vault, state,
            bearer_secret='synthetic-operator', authorization='Bearer synthetic-operator', audit_log=audit)
        calls.append((method, route, response))
        return response

    owner.team = SimpleNamespace(_call=call)
    owner.calls, owner.state, owner.audit = calls, state, audit
    return owner


def operations(owner):
    with sqlite3.connect(journal_path(owner.audit)) as db:
        return db.execute('SELECT operation_id,state FROM operations').fetchall()


def receipt_payload(row):
    return dict(event_id=row['event_id'], session=row['session'], run=row['run'],
        text=row['text'], host='original-host', project='', task='', kind='organizer', agent='operator')


@pytest.mark.parametrize('barrier', ['log', 'log_parent', 'blob', 'blob_parent'])
def test_api_replay_repairs_durable_producer_before_outbox_ack(tmp_path, monkeypatch, barrier):
    owner = owner_at(tmp_path)
    recorder = capture.WorkCapture(owner, 'session', 'run')
    recorder.feed(b'Synthetic durable work.\n')
    recorder.finish()
    row = capture.pending_capture(owner)[0]
    blob = owner.vault / 'conversations/cockpit-archive' / (row['event_id'] + '.json')
    target = {'log': owner.state, 'log_parent': owner.state.parent,
              'blob': blob, 'blob_parent': blob.parent}[barrier]
    real_sync = os.fsync
    failures, observed = [], []
    failing = True

    def sync(fd):
        path = os.readlink(f'/proc/self/fd/{fd}')
        observed.append(path)
        # The initial blob file is synced at its temporary path, before rename.
        matches = path == str(target) or (barrier == 'blob' and path.startswith(str(blob.parent / '.')))
        if failing and matches and (barrier.startswith('blob') or (owner.state.exists() and owner.state.stat().st_size)):
            failures.append(path)
            raise OSError('synthetic selected durability barrier')
        return real_sync(fd)

    monkeypatch.setattr(os, 'fsync', sync)
    try:
        assert capture.sync_capture(owner, governed_sink(owner)) == 0
        assert failures
        assert len(capture.pending_capture(owner)) == 1
        original_operation = operations(owner)[0][0]
        assert operations(owner)[0][1] == 'dispatching'
        if barrier.startswith('log'):
            original_event = owner.state.read_bytes()
            # GET sees the event but does not repair it or stop retransmission.
            response = owner.team._call('GET', '/control/transcripts/' + row['event_id'])
            assert response.status == 200
            assert capture.sync_capture(owner, governed_sink(owner)) == 0
            assert operations(owner) == [(original_operation, 'dispatching')]
            # Reopen the durable local outbox and retry after host metadata changes.
            owner.db.close()
            owner = owner_at(tmp_path)
            owner.host = 'changed-host'
            failing = False
            assert capture.sync_capture(owner, governed_sink(owner)) == 1
            assert not capture.pending_capture(owner)
            assert owner.state.read_bytes() == original_event
            assert operations(owner) == [(original_operation, 'completed')]
            assert str(blob) in observed and str(blob.parent) in observed
            assert str(owner.state) in observed and str(owner.state.parent) in observed
            outcomes = [json.loads(line) for line in owner.audit.read_text().splitlines()]
            assert len([r for r in outcomes if r.get('operation_id') == original_operation and r.get('phase') == 'outcome']) == 1
            payload = receipt_payload(row)
            payload['actor'] = 'operator'
            payload['idempotency_key'] = row['event_id']
            # Completed retries repeat producer barriers and preserve event identity.
            assert owner.team._call('POST', '/control/transcripts', payload).status == 200
            assert owner.state.read_bytes() == original_event
        else:
            # Journal input is exact and creation remains authorized; retry must
            # recover a failure before event publication instead of stranding it.
            failing = False
            assert capture.sync_capture(owner, governed_sink(owner)) == 1
            assert not capture.pending_capture(owner)
            assert operations(owner) == [(original_operation, 'completed')]
            assert len([e for e in control.read_events(owner.state) if e.type == 'work.transcript']) == 1
    finally:
        owner.db.close()


def test_lost_completed_response_replays_without_duplicate_effect_or_audit(tmp_path):
    owner = owner_at(tmp_path)
    try:
        recorder = capture.WorkCapture(owner, 'session', 'run')
        recorder.feed(b'Synthetic response loss.\n')
        recorder.finish()
        original_call = owner.team._call
        lost = []
        def call(method, route, body=None):
            response = original_call(method, route, body)
            if method == 'POST' and not lost:
                lost.append(True)
                assert response.status == 201
                raise OSError('synthetic response loss')
            return response
        owner.team._call = call
        assert capture.sync_capture(owner, governed_sink(owner)) == 0
        event_bytes, audit_bytes = owner.state.read_bytes(), owner.audit.read_bytes()
        assert operations(owner)[0][1] == 'completed'
        assert capture.sync_capture(owner, governed_sink(owner)) == 1
        assert owner.state.read_bytes() == event_bytes
        # GET requests add read audit entries, but the one mutation outcome remains.
        outcomes = [json.loads(line) for line in owner.audit.read_text().splitlines()]
        assert len([e for e in outcomes if e.get('phase') == 'outcome']) == 1
    finally:
        owner.db.close()


def test_conflicting_request_never_repairs_or_replaces_transcript(tmp_path, monkeypatch):
    owner = owner_at(tmp_path)
    try:
        recorder = capture.WorkCapture(owner, 'session', 'run')
        recorder.feed(b'Synthetic conflict.\n')
        recorder.finish()
        row = capture.pending_capture(owner)[0]
        payload = capture.capture_delivery_payload(owner, row)
        assert owner.team._call('POST', '/control/transcripts', payload).status == 201
        before = owner.state.read_bytes()
        monkeypatch.setattr('arvyx_control.cockpit_archive_authority.append_transcript',
            lambda *a, **kw: pytest.fail('conflict must precede producer or barriers'))
        response = owner.team._call('POST', '/control/transcripts', dict(payload, text='changed'))
        assert response.status == 409
        assert owner.state.read_bytes() == before
    finally:
        owner.db.close()


def test_completed_denial_cannot_become_a_new_publication(tmp_path):
    owner = owner_at(tmp_path)
    try:
        recorder = capture.WorkCapture(owner, 'session', 'run')
        recorder.feed(b'Synthetic denied publication.\n')
        recorder.finish()
        payload = capture.capture_delivery_payload(owner, capture.pending_capture(owner)[0])
        agent = owner.vault / 'registry/agents/operator.json'
        agent.unlink()
        response = owner.team._call('POST', '/control/transcripts', payload)
        assert response.status == 400
        assert operations(owner)[0][1] == 'completed'
        agent.write_text('{}')
        assert capture.sync_capture(owner, governed_sink(owner)) == 0
        assert not owner.state.exists()
        assert operations(owner)[0][1] == 'completed'
    finally:
        owner.db.close()


def test_unpublished_recovery_rechecks_authority_and_current_actor(tmp_path, monkeypatch):
    owner = owner_at(tmp_path)
    try:
        recorder = capture.WorkCapture(owner, 'session', 'run')
        recorder.feed(b'Synthetic current authorization.\n')
        recorder.finish()
        real_replace = os.replace
        def interrupt(source, target):
            if str(target).endswith('.json') and 'cockpit-archive' in str(target):
                raise OSError('synthetic unpublished blob')
            return real_replace(source, target)
        with monkeypatch.context() as m:
            m.setattr(os, 'replace', interrupt)
            assert capture.sync_capture(owner, governed_sink(owner)) == 0
        operation = operations(owner)
        assert operation[0][1] == 'dispatching'
        agent = owner.vault / 'registry/agents/operator.json'
        agent.unlink()
        assert capture.sync_capture(owner, governed_sink(owner)) == 0
        assert operations(owner) == operation
        agent.write_text('{}')
        marker = owner.vault / '.arvyx-replica'
        marker.write_text('synthetic replica')
        assert capture.sync_capture(owner, governed_sink(owner)) == 0
        assert not owner.state.exists()
        marker.unlink()
        assert capture.sync_capture(owner, governed_sink(owner)) == 1
        assert operations(owner) == [(operation[0][0], 'completed')]
    finally:
        owner.db.close()
