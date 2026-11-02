"""Sol22 archive persistent metadata quota regressions."""
import sqlite3
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from arvyx_control import cockpit_archive as archive


def owner_at(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    return SimpleNamespace(db=db, lock=threading.RLock(), _get=lambda sid: None)


def charged(owner):
    row = owner.db.execute('SELECT * FROM capture_accounting').fetchone()
    return row['bytes'] + (row['metadata_bytes'] if 'metadata_bytes' in row.keys() else 0)


def test_sol22_short_lines_retain_charge_after_delivery_restart_and_backpressure(tmp_path):
    path = tmp_path / 'capture.db'
    owner = owner_at(path)
    capture = archive.WorkCapture(owner, 'session', 'run')
    capture.feed(b'\n' * 100)
    assert charged(owner) >= 25600, 'sol22: persistent row/index metadata must remain charged'
    before = charged(owner)
    assert archive.sync_capture(owner, lambda row: row['event_id']) == 100
    assert charged(owner) == before
    owner.db.close()
    owner = owner_at(path)
    capture = archive.WorkCapture(owner, 'session', 'retry')
    assert charged(owner) > before  # The new retained run is charged too.
    before = charged(owner)
    with patch.object(archive, 'CAPTURE_CAPACITY', before + 5000):
        with pytest.raises(BufferError):
            capture.feed(b'\n' * 100)
    assert charged(owner) == before
    assert owner.db.execute('SELECT COUNT(*) FROM work_capture').fetchone()[0] == 100
    capture.feed(b'exact retry\n')
    assert owner.db.execute('SELECT COUNT(*) FROM work_capture').fetchone()[0] == 101
    owner.db.close()


def test_sol22_native_import_quota_keeps_source_cursor(tmp_path):
    owner = owner_at(tmp_path / 'capture.db')
    archive._capture_schema(owner)
    owner.db.commit()
    owner._human = lambda actor: None
    owner._get = lambda sid: {'workspace': str(tmp_path)}
    owner.native = lambda sid, actor: {'tool': 'fixture', 'conversation': 'conversation'}
    store = tmp_path/'synthetic-native.db'
    store.touch()
    owner.native_runtimes = {'fixture': SimpleNamespace(
        home=tmp_path, store=store,
        plan=lambda *args: None,
        transcript=lambda *args, **kwargs: [dict(id=i, role='user', content='') for i in range(1, 101)])}
    with patch.object(archive, 'CAPTURE_CAPACITY', 5000):
        with pytest.raises(BufferError):
            archive.import_native(owner, 'session', actor='operator')
    assert charged(owner) == 0
    assert owner.db.execute('SELECT COUNT(*) FROM native_archive_cursor').fetchone()[0] == 0
    assert archive.import_native(owner, 'session', actor='operator')['cursor'] == 100
    assert charged(owner) >= 25600
    owner.db.close()


def test_sol22_finish_rolls_back_metadata_and_tail(tmp_path):
    owner = owner_at(tmp_path / 'capture.db')
    capture = archive.WorkCapture(owner, 'session')
    capture.feed(b'tail')
    before = charged(owner)
    owner.db.execute("CREATE TEMP TRIGGER fail_finish BEFORE UPDATE ON capture_runs BEGIN SELECT RAISE(ABORT, 'fixture'); END")
    owner.db.commit()
    with pytest.raises(sqlite3.IntegrityError):
        capture.finish()
    assert charged(owner) == before
    assert bytes(capture.buffer) == b'tail'
    owner.db.execute('DROP TRIGGER fail_finish')
    owner.db.commit()
    capture.finish()
    assert charged(owner) >= 260, 'sol22: finish must charge metadata too'
    owner.db.close()


def test_sol22_legacy_accounting_backfilled_once_and_mutations_transactional(tmp_path):
    owner = owner_at(tmp_path / 'capture.db')
    archive._capture_schema(owner)
    # Simulate the old text-only accounting schema, including already retained rows.
    for name in ('capture_insert', 'capture_delete', 'capture_update'):
        owner.db.execute('DROP TRIGGER IF EXISTS ' + name)
    owner.db.execute('DROP TABLE capture_accounting')
    owner.db.execute('CREATE TABLE capture_accounting(id INTEGER PRIMARY KEY, bytes INTEGER NOT NULL)')
    owner.db.execute("INSERT INTO work_capture(event_id,session,run,text) VALUES('event','session','run','x')")
    owner.db.execute('INSERT INTO capture_accounting VALUES(1,1)')
    owner.db.commit()
    archive._capture_schema(owner)
    owner.db.commit()
    before = charged(owner)
    assert before >= 257, 'sol22: legacy rows must not escape quota'
    archive._capture_schema(owner)
    assert charged(owner) == before
    owner.db.execute("UPDATE work_capture SET session='longer-session',text='longer' WHERE event_id='event'")
    assert charged(owner) > before
    owner.db.rollback()
    assert charged(owner) == before
    owner.db.execute("DELETE FROM work_capture WHERE event_id='event'")
    assert charged(owner) == 0
    owner.db.rollback()
    assert charged(owner) == before
    owner.db.close()
