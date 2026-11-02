from arvyx_control.local_executor import ExecutionPolicy
from arvyx_control.replica_authority import authority_context
"""Synthetic archive entrypoint regressions; no provider or PTY is started."""
import json
import socket
import sqlite3
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from arvyx_control import cockpit_archive as archive
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_client import request


def owner_at(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    vault = path.parent / (path.stem + '-vault')
    vault.mkdir(exist_ok=True)
    return SimpleNamespace(db=db, lock=threading.RLock(), vault=vault,
                           state=path.parent / (path.stem + '-events.jsonl'), _get=lambda sid: {},
                           _human=lambda actor: None, live={}, archive_sync='not configured')


@pytest.mark.skipif(not hasattr(socket, 'AF_UNIX'), reason='Unix sockets required')
def test_serialized_pages_cross_real_client_cap_without_losing_history(tmp_path, monkeypatch):
    owner = owner_at(tmp_path / 'archive.db')
    for i in range(90):
        LocalCockpit.archive(owner, 'session', actor='operator', event_id=f'event-{i}',
                             source='operator-note', text=('\\\"\t界' * 3000))
    # Relative socket addresses stay short even when pytest roots are long.
    # cwd and every durable fixture path remain in pytest-owned storage.
    monkeypatch.chdir(tmp_path)
    root = Path('.')
    (root / 'runtime').mkdir()
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(root / 'runtime/cockpit.sock'))
    server.listen()
    errors = []
    response_sizes = []
    def respond():
        try:
            while True:
                conn, _ = server.accept()
                with conn, conn.makefile('rb') as stream:
                    payload = json.loads(stream.readline())
                    if payload.pop('operation') == 'stop':
                        return
                    # This minimal archive-only harness implements the same
                    # shrinking transport budget as the production dispatcher.
                    from arvyx_control.cockpit_client import validate_budget, exchange_deadline
                    budget = validate_budget(payload.pop('_budget_seconds'))
                    with exchange_deadline(budget):
                        result = LocalCockpit.archive(owner, **payload)
                    body = json.dumps(dict(ok=True, result=result)).encode() + b'\n'
                    assert len(body) < 1048576
                    response_sizes.append(len(body))
                    conn.sendall(body)
        except BaseException as exc:
            errors.append(exc)
    # SQLite must remain on its creating thread; handle requests on this thread.
    def client():
        try:
            seen = []
            cursor = 0
            while True:
                page = request(root, 'archive', sid='session', actor='operator', after=cursor)
                assert isinstance(page, dict), 'explicit continuation envelope required'
                seen.extend(row['event_id'] for row in page['records'])
                assert page['next_after'] > cursor
                cursor = page['next_after']
                if not page['has_more']:
                    break
            assert seen == [f'event-{i}' for i in range(90)]
        except BaseException as exc:
            errors.append(exc)
        finally:
            with socket.socket(socket.AF_UNIX) as conn:
                conn.connect(str(root / 'runtime/cockpit.sock'))
                conn.sendall(b'{"operation":"stop"}\n')
    worker = threading.Thread(target=client)
    worker.start()
    respond()
    worker.join(6)
    server.close()
    owner.db.close()

    assert not errors, repr(errors)
    print('90 escaped/unicode archive records; wire page bytes:', response_sizes)


def test_explicit_archive_charges_identifiers_incrementally_and_rolls_back(tmp_path):
    owner = owner_at(tmp_path / 'archive.db')
    for i in range(1000):
        LocalCockpit.archive(owner, 'session', actor='operator', event_id=str(i).zfill(128), source='operator-note', text='x')
    row = owner.db.execute("SELECT name FROM sqlite_master WHERE name='transcript_accounting'").fetchone()
    assert row, 'transactional incremental transcript accounting required'
    before = owner.db.execute('SELECT bytes FROM transcript_accounting').fetchone()[0]
    assert before >= 384000
    statements = []
    owner.db.set_trace_callback(statements.append)
    LocalCockpit.archive(owner, 'session', actor='operator', event_id='last', source='operator-note', text='x')
    assert not any('SUM(' in sql.upper() for sql in statements)
    owner.db.execute("CREATE TEMP TRIGGER fail_archive BEFORE INSERT ON transcript_records BEGIN SELECT RAISE(ABORT,'fixture'); END")
    owner.db.commit()
    before = owner.db.execute('SELECT bytes FROM transcript_accounting').fetchone()[0]
    with pytest.raises(sqlite3.IntegrityError):
        LocalCockpit.archive(owner, 'session', actor='operator', event_id='failed', source='operator-note', text='x')
    assert owner.db.execute('SELECT bytes FROM transcript_accounting').fetchone()[0] == before
    owner.db.close()


def test_empty_runs_are_quota_charged_without_erasing_failure_evidence(tmp_path):
    owner = owner_at(tmp_path / 'capture.db')
    capture = archive.WorkCapture(owner, 'session', 'failed-run')
    before = owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting').fetchone()[0]
    assert before >= 256, 'run metadata must consume retained capacity'
    with patch.object(archive, 'CAPTURE_CAPACITY', before):
        with pytest.raises(BufferError):
            archive.WorkCapture(owner, 'session', 'another-run')
    assert archive.capture_status(owner)['interrupted_runs'] == 1
    assert owner.db.execute('SELECT COUNT(*) FROM capture_runs').fetchone()[0] == 1
    plans = owner.db.execute("EXPLAIN QUERY PLAN SELECT run FROM capture_runs WHERE status='open'").fetchall()
    assert any('INDEX' in row[3] for row in plans)
    capture.finish()
    assert owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting').fetchone()[0] == before
    owner.db.close()


def test_legacy_oversized_row_fails_explicitly_instead_of_stalling_cursor(tmp_path):
    owner = owner_at(tmp_path / 'archive.db')
    archive._schema(owner)
    owner.db.execute("INSERT INTO transcript_records(event_id,session,source,text,sha256) VALUES('legacy','session','operator-note',?,'digest')", ('x' * 1048576,))
    owner.db.commit()
    with pytest.raises(ValueError, match='page budget'):
        LocalCockpit.archive(owner, 'session', actor='operator')
    assert owner.db.execute('SELECT COUNT(*) FROM transcript_records').fetchone()[0] == 1
    owner.db.close()


def test_legacy_backfills_are_once_only_and_trigger_mutations_rollback(tmp_path):
    owner = owner_at(tmp_path / 'legacy.db')
    owner.db.executescript('''
        CREATE TABLE transcript_records(sequence INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id TEXT UNIQUE NOT NULL, session TEXT NOT NULL, source TEXT NOT NULL,
          text TEXT NOT NULL, sha256 TEXT NOT NULL);
        INSERT INTO transcript_records(event_id,session,source,text,sha256)
          VALUES('old','session','operator-note','x','digest');
        CREATE TABLE capture_runs(run TEXT PRIMARY KEY, session TEXT NOT NULL, status TEXT NOT NULL);
        INSERT INTO capture_runs VALUES('failed-fork','session','open');
    ''')
    LocalCockpit.archive(owner, 'session', actor='operator')
    archive.capture_status(owner)
    owner.db.commit()
    transcript = owner.db.execute('SELECT bytes FROM transcript_accounting').fetchone()[0]
    capture = owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting').fetchone()[0]
    assert transcript > 512 and capture > 512
    statements = []
    owner.db.set_trace_callback(statements.append)
    LocalCockpit.archive(owner, 'session', actor='operator')
    archive.capture_status(owner)
    assert not any('SUM(' in sql.upper() for sql in statements)
    assert owner.db.execute('SELECT bytes FROM transcript_accounting').fetchone()[0] == transcript
    assert owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting').fetchone()[0] == capture
    owner.db.execute("UPDATE transcript_records SET event_id='longer-identifier',text='longer'")
    owner.db.execute("UPDATE capture_runs SET run='longer-failed-fork-identifier'")
    assert owner.db.execute('SELECT bytes FROM transcript_accounting').fetchone()[0] > transcript
    assert owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting').fetchone()[0] > capture
    owner.db.rollback()
    owner.db.execute('DELETE FROM transcript_records')
    owner.db.execute('DELETE FROM capture_runs')
    assert owner.db.execute('SELECT bytes FROM transcript_accounting').fetchone()[0] == 0
    assert owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting').fetchone()[0] == 0
    owner.db.rollback()
    assert owner.db.execute('SELECT bytes FROM transcript_accounting').fetchone()[0] == transcript
    assert owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting').fetchone()[0] == capture
    owner.db.close()


def test_quota_denial_preserves_idempotency_and_history(tmp_path):
    owner = owner_at(tmp_path / 'quota.db')
    payload = dict(actor='operator', event_id='same', source='operator-note', text='x')
    first = LocalCockpit.archive(owner, 'session', **payload)
    used = owner.db.execute('SELECT bytes FROM transcript_accounting').fetchone()[0]
    with patch.object(archive, 'TRANSCRIPT_CAPACITY', used):
        assert LocalCockpit.archive(owner, 'session', **payload) == first
        with pytest.raises(ValueError, match='capacity'):
            LocalCockpit.archive(owner, 'session', **dict(payload, event_id='next'))
    assert LocalCockpit.archive(owner, 'session', actor='operator')['records'] == [first]
    owner.db.close()


def test_failed_fork_keeps_charged_run_evidence_and_quota_prevents_fork(tmp_path):
    with authority_context(tmp_path / 'pilot' / 'vault', tmp_path / 'pilot' / 'events.jsonl'):
        from arvyx_control import cockpit_client, control
        root = tmp_path / 'pilot'
        cockpit_client.initialize(root)
        owner = LocalCockpit(root / 'runtime', root / 'vault', root / 'events.jsonl', 'synthetic-host', execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))
        try:
            task = control.create_task(root / 'events.jsonl', 'synthetic', owner='demobot').task
            sid = owner.open(project='demo-agent', task=task.id, name='synthetic', actor='operator')['id']
            with patch('pty.fork', side_effect=OSError('synthetic fork failure')) as fork:
                with pytest.raises(OSError, match='synthetic fork failure'):
                    owner.start(sid, actor='operator', environment='host')
                assert fork.call_count == 1
            status = archive.capture_status(owner)
            assert status['open_runs'] == status['interrupted_runs'] == 0
            assert owner.db.execute("SELECT status FROM capture_runs").fetchone()[0] == 'aborted-before-process'
            assert owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting').fetchone()[0] > 512
            with patch.object(archive, 'CAPTURE_CAPACITY', 1), patch('pty.fork') as fork:
                with pytest.raises(BufferError):
                    owner.start(sid, actor='operator', environment='host')
                fork.assert_not_called()
            assert owner.db.execute('SELECT COUNT(*) FROM capture_runs').fetchone()[0] == 1
        finally:
            owner.close()


def test_count_boundary_empty_page_and_session_sequence_gaps(tmp_path):
    owner = owner_at(tmp_path / 'pages.db')
    for i in range(105):
        for sid in ('one', 'two'):
            LocalCockpit.archive(owner, sid, actor='operator', event_id=f'{sid}-{i}', source='operator-note', text='x')
    first = LocalCockpit.archive(owner, 'one', actor='operator')
    assert len(first['records']) == 100 and first['has_more']
    second = LocalCockpit.archive(owner, 'one', actor='operator', after=first['next_after'])
    assert len(second['records']) == 5 and not second['has_more']
    assert [r['event_id'] for r in first['records'] + second['records']] == [f'one-{i}' for i in range(105)]
    assert LocalCockpit.archive(owner, 'one', actor='operator', after=second['next_after']) == dict(records=[], next_after=second['next_after'], has_more=False)
    for bad in (-1, True, '0'):
        with pytest.raises(ValueError, match='cursor'):
            LocalCockpit.archive(owner, 'one', actor='operator', after=bad)
    owner.db.close()


def test_incremental_append_vm_budget_does_not_scale_with_history(tmp_path):
    owner = owner_at(tmp_path / 'steps.db')
    costs = []
    for i in range(1001):
        steps = [0]
        def count():
            steps[0] += 1
            return 0
        if i in (10, 1000):
            owner.db.set_progress_handler(count, 1)
        LocalCockpit.archive(owner, 'session', actor='operator', event_id=f'event-{i}', source='operator-note', text='x')
        owner.db.set_progress_handler(None, 0)
        if i in (10, 1000):
            costs.append(steps[0])
    assert costs[1] < costs[0] * 2, costs
    print('incremental append VM steps at 10/1000 retained rows:', costs)
    owner.db.close()
