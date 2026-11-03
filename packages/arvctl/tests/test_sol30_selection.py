"""Offline exact-selection regressions using only synthetic SQLite profiles."""
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
import sqlite3
from contextlib import closing
from types import SimpleNamespace

import pytest

from arvyx_control.agent_sessions import AgentSessions, SessionRoute, RoutingError
from arvyx_control.hermes_history import HermesHistory
from arvyx_control.public_onboarding_api import PublicOnboardingAPI, PREFIX


@pytest.fixture
def selection(tmp_path):
    home = tmp_path / 'synthetic'; home.mkdir(mode=0o700)
    with closing(sqlite3.connect(home / 'state.db')) as db, db:
        db.execute('CREATE TABLE sessions(id TEXT PRIMARY KEY,title TEXT,started_at REAL,cwd,end_reason,prompt)')
        db.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?)', ('exact', 'title', 1, '/safe', None, 'NOT RETURNED'))
    history = HermesHistory(home)
    owner = SimpleNamespace(sessions=AgentSessions({history.target: history}),
                            targets=frozenset({history.target}), extension=None,
                            vault=tmp_path/'vault', state=tmp_path/'events.jsonl')
    api = PublicOnboardingAPI(credentials={hashlib.sha256(b'synthetic').hexdigest(): 'owner'}, owners={'owner': owner})
    def update(cwd='/safe', end_reason=None, session_id='exact'):
        with closing(sqlite3.connect(home / 'state.db')) as db, db:
            db.execute('UPDATE sessions SET cwd=?,end_reason=?,id=?', (cwd, end_reason, session_id))
    def dispatch(session_id='exact', confirmed=True, auth_value='synthetic'):
        return api.dispatch('POST', PREFIX+'sessions/select', 'Bearer '+auth_value,
                            {'route': asdict(SessionRoute(history.target, session_id)), 'confirmed': confirmed})
    return history, update, dispatch


@pytest.mark.parametrize('field', ['cwd', 'end_reason'])
@pytest.mark.parametrize('value', ['x' * (2*1024*1024), '😀' * 1025], ids=['two-MiB', 'unicode-over-byte-cap'])
def test_authorized_dispatch_rejects_oversized_selection(selection, field, value):
    history, update, dispatch = selection
    update(**{field: value})
    status, response = dispatch()
    assert status == 409
    assert response == {'error': 'exact_route_unavailable', 'queued': False}


def test_aggregate_response_rejected(selection):
    _, update, dispatch = selection
    identifier = '\x01' * 4096
    update(cwd='\x01' * 4096, end_reason='\x01' * 4096, session_id=identifier)
    assert dispatch(identifier)[0] == 409


@pytest.mark.parametrize('value', [42, 1.25, b'bytes'])
@pytest.mark.parametrize('field', ['cwd', 'end_reason'])
def test_invalid_sqlite_metadata_types_fail_closed(selection, value, field):
    _, update, dispatch = selection
    update(**{field: value})
    assert dispatch()[0] == 409


@pytest.mark.parametrize('cwd,end_reason', [(None, None), ('😀'*1024, 'compression'), ('/exact\x00path', '')])
def test_valid_values_preserved_exactly(selection, cwd, end_reason):
    _, update, dispatch = selection
    update(cwd=cwd, end_reason=end_reason)
    status, response = dispatch()
    assert status == 200
    assert response['result'] == {'id': 'exact', 'cwd': cwd, 'end_reason': end_reason}
    assert len(json.dumps(response).encode()) <= 65536
    assert dispatch('missing')[0] == 409
    assert dispatch(confirmed=False)[0] == 400
    assert dispatch(auth_value='wrong')[0] == 401


@pytest.mark.parametrize('aggregate', [False, True], ids=['field', 'aggregate'])
def test_rejected_strings_never_reach_python(selection, monkeypatch, aggregate):
    history, update, _ = selection
    identifier = '\x01' * 4096 if aggregate else 'exact'
    if aggregate:
        update(cwd='\x01'*4096, end_reason='\x01'*4096, session_id=identifier)
    else:
        update(cwd='X'*100000)
    original = history.connection
    materialized = []
    @contextmanager
    def connection():
        with original() as db:
            def decode(raw):
                materialized.append(len(raw))
                return raw.decode()
            db.text_factory = decode
            yield db
    monkeypatch.setattr(history, 'connection', connection)
    with pytest.raises(RoutingError):
        history.exact(identifier)
    # Schema names may be decoded; no rejected row string may be decoded.
    assert max(materialized, default=0) < 4096


def test_selection_query_budget_and_cleanup(selection):
    history, _, _ = selection
    with closing(sqlite3.connect(history.home/'state.db')) as db, db:
        db.execute('ALTER TABLE sessions RENAME TO original')
        db.execute('CREATE TABLE sessions AS SELECT * FROM original')
        db.executemany('INSERT INTO sessions(id,title,started_at) VALUES(?,?,?)',
                       [(f'other-{i}', 'title', 1) for i in range(2000)])
    history.query_budget_steps = 0
    with pytest.raises(RoutingError, match='work/time'):
        history.exact('exact')
    history.query_budget_steps = 10_000_000
    assert history.exact('exact')['cwd'] == '/safe'


def test_optional_columns_remain_optional(tmp_path):
    home = tmp_path/'minimal'; home.mkdir(mode=0o700)
    with closing(sqlite3.connect(home/'state.db')) as db, db:
        db.execute('CREATE TABLE sessions(id TEXT PRIMARY KEY,title TEXT,started_at REAL)')
        db.execute("INSERT INTO sessions VALUES('exact','title',1)")
    history = HermesHistory(home)
    assert history.exact('exact') == {'id': 'exact'}
