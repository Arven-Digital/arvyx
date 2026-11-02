"""Synthetic stores only; no runtime plans, launch, or provider access."""
import sqlite3
import tempfile
from pathlib import Path
import pytest
from arvyx_control.agent_sessions import RoutingError
from arvyx_control.hermes_profile import HermesProfile
from arvyx_control.cockpit_native_runtime import NativeRuntime


@pytest.fixture
def native():
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        store = home / 'state.db'
        with sqlite3.connect(store) as db:
            db.execute('CREATE TABLE sessions(id, cwd, end_reason)')
            db.execute('INSERT INTO sessions VALUES(?,?,?)', ('selected', str(home), None))
            db.execute('CREATE TABLE messages(id INTEGER,session_id,role,content)')
        profile = HermesProfile(home)
        runtime = object.__new__(NativeRuntime)
        runtime.tool, runtime.store, runtime.profile = 'hermes', store, profile
        yield home, profile, runtime


@pytest.mark.parametrize('value', ['x' * (2 * 1024 * 1024), b'blob', 12, 'x' * 12000], ids=['2MiB', 'blob', 'integer', 'aggregate'])
def test_metadata_rejected_before_materialization(native, value):
    home, profile, _ = native
    with sqlite3.connect(profile.store) as db:
        db.execute('UPDATE sessions SET end_reason=?', (value,))
    from contextlib import contextmanager
    original = profile.connection
    decoded = []
    @contextmanager
    def guarded_connection():
        with original() as db:
            def decode(raw):
                decoded.append(len(raw))
                assert len(raw) <= 10000, 'oversized metadata crossed SQL boundary'
                return raw.decode()
            db.text_factory = decode
            yield db
    profile.connection = guarded_connection
    with pytest.raises(RoutingError, match='budget'):
        profile.resolve('selected', home)
    assert max(decoded, default=0) <= 10000


def test_duplicate_rows_are_ambiguous(native):
    home, profile, _ = native
    with sqlite3.connect(profile.store) as db:
        db.executemany('INSERT INTO sessions VALUES(?,?,?)', [('selected', str(home), None)] * 1000)
    with pytest.raises(RoutingError, match='ambiguous'):
        profile.resolve('selected', home)


def test_nearby_valid_reads(native):
    home, profile, runtime = native
    assert profile.resolve('selected', home)['end_reason'] is None
    with sqlite3.connect(profile.store) as db:
        db.execute('INSERT INTO messages VALUES(1,?,?,?)', ('selected', 'assistant', 'nearby'))
    assert runtime.transcript('selected') == [{'id': 1, 'role': 'assistant', 'content': 'nearby'}]


@pytest.mark.parametrize('kind', ['metadata', 'transcript'])
def test_unrelated_rows_obey_work_budget(native, kind):
    home, profile, runtime = native
    with sqlite3.connect(profile.store) as db:
        if kind == 'metadata':
            db.execute('DELETE FROM sessions')
            db.executemany('INSERT INTO sessions VALUES(?,?,?)', [('unrelated', str(home), None)] * 200000)
        else:
            db.executemany('INSERT INTO messages VALUES(1,?,?,?)', [('unrelated', 'user', 'text')] * 200000)
    profile.query_budget_steps = 10000
    with pytest.raises((RoutingError, ValueError), match='work/time budget'):
        if kind == 'metadata':
            profile.resolve('selected', home)
        else:
            runtime.transcript('selected')
    assert 10000 < profile.last_query_steps <= 11000


@pytest.mark.parametrize('kind', ['metadata', 'transcript'])
def test_deadline_even_for_short_queries(native, monkeypatch, kind):
    import arvyx_control.hermes_profile as module
    home, profile, runtime = native
    ticks = iter([0, 3])
    monkeypatch.setattr(module.time, 'monotonic', lambda: next(ticks, 3))
    with pytest.raises(RoutingError, match='work/time budget'):
        if kind == 'metadata':
            profile.resolve('selected', home)
        else:
            runtime.transcript('selected')
