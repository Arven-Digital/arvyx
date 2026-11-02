"""Isolated session routing contract and metadata-only scale receipt."""
import sqlite3
import time
from dataclasses import replace

import pytest

from arvyx_control.agent_sessions import (
    AgentSessions, SessionMetadata, SessionRoute, SessionTarget,
    DisconnectedError, RoutingError, StaleRouteError,
)


class Adapter:
    def __init__(self, path, target):
        self.target = target
        self.connected = True
        self.calls = []
        self.db = sqlite3.connect(path)
        self.db.execute('CREATE TABLE sessions(id TEXT PRIMARY KEY, title TEXT, updated REAL)')

    def metadata(self, target):
        assert target == self.target
        return [SessionMetadata(SessionRoute(target, row[0]), row[1], row[2])
                for row in self.db.execute('SELECT id,title,updated FROM sessions')]

    def perform(self, target, action, session_id=None):
        # Adapter must atomically validate the incarnation and connection with dispatch.
        if target != self.target:
            raise StaleRouteError('stale adapter incarnation')
        if not self.connected:
            raise DisconnectedError('disconnected')
        self.calls.append((target, action, session_id))
        if action == 'new':
            self.db.execute('INSERT INTO sessions VALUES(?,?,?)', ('new-id', 'New', 2000))
            return SessionMetadata(SessionRoute(target, 'new-id'), 'New', 2000)
        return {'session_id': session_id, 'messages': ['loaded only on select']}


@pytest.fixture
def setup(tmp_path):
    target = SessionTarget('machine-A', 'agent-A', '/exact/workspace', 'connection-1')
    adapter = Adapter(tmp_path / 'sessions.db', target)
    adapter.db.executemany('INSERT INTO sessions VALUES(?,?,?)',
                           [(f's{i:04}', f'Title {i}', i) for i in range(1205)])
    service = AgentSessions({target: adapter})
    yield target, adapter, service
    adapter.db.close()


def test_metadata_scale_recent_search_and_full_pagination(setup):
    target, adapter, service = setup
    start = time.perf_counter()
    recent = service.recent(target)
    assert len(recent) == 5
    assert recent[0].route.session_id == 's1204'
    ids = []
    cursor = None
    while True:
        page = service.all(target, cursor=cursor, limit=97)
        assert page.total == 1205
        ids.extend(item.route.session_id for item in page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
    assert len(ids) == len(set(ids)) == 1205
    assert service.all(target, query='TITLE 1204').items[0].route.session_id == 's1204'
    assert not adapter.calls
    elapsed = time.perf_counter() - start
    print(f'1205 temporary SQLite sessions: recent/search/full pagination {elapsed:.6f}s')
    assert elapsed < 5


def test_select_and_explicit_new_only(setup):
    target, adapter, service = setup
    route = service.recent(target)[0].route
    assert service.select(route)['session_id'] == route.session_id
    created = service.new(target)
    assert created.route.session_id == 'new-id'
    assert [call[1] for call in adapter.calls] == ['select', 'new']


@pytest.mark.parametrize('field,value', [('machine_id', 'machine-B'), ('agent_id', 'agent-B'),
                                         ('workspace_id', '/other'), ('connection_id', 'old')])
def test_exact_routing_rejects_cross_machine_and_stale(setup, field, value):
    target, adapter, service = setup
    bad = replace(target, **{field: value})
    with pytest.raises(RoutingError):
        service.select(SessionRoute(bad, 's0001'))
    assert not adapter.calls


def test_disconnected_never_queues_retries_or_creates(setup):
    target, adapter, service = setup
    adapter.connected = False
    for action in [lambda: service.recent(target), lambda: service.new(target),
                   lambda: service.select(SessionRoute(target, 's0001'))]:
        with pytest.raises(DisconnectedError):
            action()
    assert not adapter.calls


def test_stale_incarnation_and_unknown_session_no_fallback(setup):
    target, adapter, service = setup
    with pytest.raises(RoutingError):
        service.select(SessionRoute(target, 'missing'))
    adapter.target = replace(target, connection_id='connection-2')
    with pytest.raises(StaleRouteError):
        service.select(SessionRoute(target, 's0001'))
    assert not adapter.calls


def test_cursor_binding_and_collection_change(setup):
    target, adapter, service = setup
    cursor = service.all(target, limit=2).next_cursor
    with pytest.raises(StaleRouteError):
        service.all(target, query='other', cursor=cursor)
    adapter.db.execute("DELETE FROM sessions WHERE id='s0001'")
    assert service.all(target, cursor=cursor).total == 1205
    with pytest.raises(RoutingError):
        service.select(SessionRoute(target, 's0001'))


def test_transport_metadata_and_adapter_cross_machine_rejected(setup):
    target, adapter, service = setup
    page = service.all(target, limit=1)
    transport = page.to_dict()
    assert transport['total'] == 1205
    assert transport['items'][0]['route']['target']['machine_id'] == 'machine-A'
    assert 'messages' not in str(transport)
    other = replace(target, machine_id='machine-B')
    adapter.metadata = lambda _: [SessionMetadata(SessionRoute(other, 's0001'), 'foreign', 1)]
    with pytest.raises(RoutingError):
        service.recent(target)
    assert not adapter.calls


def test_disconnect_at_dispatch_is_not_retried(setup):
    target, adapter, service = setup
    calls = []
    def disconnect(target, action, session_id=None):
        calls.append(action)
        raise DisconnectedError('connection dropped at dispatch')
    adapter.perform = disconnect
    with pytest.raises(DisconnectedError):
        service.select(SessionRoute(target, 's0001'))
    assert calls == ['select']


def test_invalid_boundaries(setup):
    target, adapter, service = setup
    with pytest.raises(ValueError):
        SessionTarget('', 'a', 'w', 'c')
    for limit in [0, -1, True, 1001]:
        with pytest.raises(ValueError):
            service.all(target, limit=limit)
    with pytest.raises(StaleRouteError):
        service.all(target, cursor='not-a-cursor')


def test_active_metadata_changes_do_not_reorder_snapshot_offsets(setup):
    target, adapter, service = setup
    first = service.all(target, limit=97)
    expected = [f's{i:04}' for i in range(1204, -1, -1)]
    ids = [x.route.session_id for x in first.items]
    cursor = first.next_cursor
    while cursor:
        adapter.db.execute("UPDATE sessions SET updated=updated+100000,title=title||' active' WHERE id IN ('s0001','s0400','s1204')")
        page = service.all(target, limit=97, cursor=cursor)
        ids.extend(x.route.session_id for x in page.items)
        cursor = page.next_cursor
    assert ids == expected
    assert service.all(target, limit=1).items[0].title.endswith(' active')


def test_snapshot_expiry_and_reconnection(setup):
    target, adapter, _ = setup
    now = [100.]
    service = AgentSessions({target: adapter}, snapshot_ttl=5, clock=lambda: now[0])
    cursor = service.all(target, limit=3).next_cursor
    now[0] += 6
    with pytest.raises(StaleRouteError):
        service.all(target, cursor=cursor)
    cursor = service.all(target, limit=3).next_cursor
    adapter.target = replace(target, connection_id='reconnected')
    with pytest.raises(StaleRouteError):
        service.all(target, cursor=cursor)
    with pytest.raises(StaleRouteError):
        service.select(SessionRoute(target, 's0001'))
    assert not adapter.calls


def test_oversized_new_snapshot_does_not_evict_existing_cursor(setup, monkeypatch):
    from arvyx_control import agent_sessions
    target, adapter, _ = setup
    service = AgentSessions({target: adapter}, max_snapshots=1)
    page = service.all(target, query='Title 12', limit=1)
    assert page.next_cursor is not None
    retained = dict(service._snapshots)
    monkeypatch.setattr(agent_sessions, 'MAX_SNAPSHOT_BYTES',
                        next(iter(retained.values()))[4] + 1)
    with pytest.raises(RoutingError, match='snapshot byte budget'):
        service.all(target, limit=1)
    assert service._snapshots == retained
    assert service.all(target, query='Title 12', cursor=page.next_cursor, limit=1).total == page.total
