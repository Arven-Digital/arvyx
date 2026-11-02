"""Claude Code metadata adapter over a synthetic state root; nothing is launched.

Fixtures are synthetic: the "transcripts" contain a sentinel that must never
appear in any listing, search hit or exact inspection result.
"""
import json
import os
import uuid

import pytest

from arvyx_control.agent_sessions import AgentSessions, RoutingError
from arvyx_control.claude_code_history import ClaudeCodeHistory
from arvyx_control import session_file_store

SENTINEL = 'SYNTHETIC-TRANSCRIPT-SENTINEL-MUST-NEVER-SURFACE'
BASE = 1_700_000_000


def session_uuid(i):
    return str(uuid.UUID(int=i + 1))


def write_claude_session(project_dir, i, *, cwd='/synthetic/work', summary_first=True, mismatch=False):
    sid = session_uuid(i)
    path = project_dir / (sid + '.jsonl')
    rows = []
    if summary_first:
        rows.append(dict(type='summary', summary=SENTINEL + ' summary', leafUuid=sid))
    rows.append(dict(type='user', sessionId='ffffffff-ffff-4fff-8fff-ffffffffffff' if mismatch else sid, cwd=cwd,
                     version='0.0.0-synthetic', timestamp='2026-01-01T00:00:00.000Z',
                     message=dict(role='user', content=SENTINEL)))
    rows += [dict(type='assistant', sessionId=sid, message=dict(role='assistant', content=SENTINEL)) for _ in range(3)]
    path.write_text('\n'.join(json.dumps(r) for r in rows) + '\n', encoding='utf-8')
    os.utime(path, (BASE + i, BASE + i))
    return sid, path


def build_claude_home(root, *, projects=(('C--Users-synthetic-work', 3), ('-home-synthetic-lab', 5))):
    home = root / 'claude-home'
    home.mkdir(mode=0o700)
    (home / 'settings.json').write_text('{}', encoding='utf-8')
    container = home / 'projects'
    container.mkdir(mode=0o700)
    written = {}
    for index, (name, count) in enumerate(projects):
        directory = container / name
        directory.mkdir()
        for i in range(count):
            sid, _ = write_claude_session(directory, index * 1000 + i)
            written[name + '/' + sid] = index * 1000 + i
    return home, written


@pytest.fixture
def store(tmp_path):
    home, written = build_claude_home(tmp_path)
    noise = home / 'projects' / 'C--Users-synthetic-work'
    (noise / 'memory').mkdir()
    (noise / 'memory' / 'MEMORY.md').write_text(SENTINEL, encoding='utf-8')
    (noise / 'agent-0abc123.jsonl').write_text(SENTINEL, encoding='utf-8')
    (noise / 'notes.txt').write_text(SENTINEL, encoding='utf-8')
    (home / 'projects' / 'not a project!').mkdir()
    adapter = ClaudeCodeHistory(home)
    adapter.written = written
    return adapter


def _flat(value):
    return json.dumps(value, default=str)


def test_listing_uses_names_and_stat_only_and_hides_noise(store, monkeypatch):
    def never(*args, **kwargs):
        raise AssertionError('listing must not open any session file')
    monkeypatch.setattr(session_file_store._Walker, 'open_file', never)
    items = store.metadata(store.target)
    assert {x.route.session_id for x in items} == set(store.written)
    assert all(x.title in ('C--Users-synthetic-work', '-home-synthetic-lab') for x in items)
    assert store.last_scan['sessions'] == 8 and store.last_scan['skipped'] >= 4
    assert SENTINEL not in _flat([x.__dict__ for x in items])


def test_recent_all_search_and_pagination_scale_past_a_thousand_sessions(tmp_path):
    home, written = build_claude_home(tmp_path, projects=(('-home-synthetic-big', 1205),))
    adapter = ClaudeCodeHistory(home)
    service = AgentSessions({adapter.target: adapter})
    recent = service.recent(adapter.target)
    assert [x.route.session_id for x in recent] == sorted(written, key=lambda k: -written[k])[:5]
    page = service.all(adapter.target, limit=97)
    ids = [x.route.session_id for x in page.items]
    assert page.total == 1205
    while page.next_cursor:
        page = service.all(adapter.target, limit=97, cursor=page.next_cursor)
        ids.extend(x.route.session_id for x in page.items)
    assert len(ids) == len(set(ids)) == 1205
    assert service.all(adapter.target, query='SYNTHETIC-BIG').total == 1205
    assert service.all(adapter.target, query=session_uuid(7)).total == 1
    assert service.all(adapter.target, query=SENTINEL).total == 0


def test_exact_returns_routing_fields_only(store):
    session_id = next(iter(store.written))
    result = store.exact(session_id)
    assert result['id'] == session_id and result['cwd'] == '/synthetic/work'
    assert result['version'] == '0.0.0-synthetic' and result['encoding'] == 'jsonl'
    assert result['started_at'] == '2026-01-01T00:00:00.000Z'
    assert set(result) == {'id', 'path', 'size_bytes', 'modified_at', 'encoding', 'cwd', 'version', 'started_at'}
    assert SENTINEL not in _flat(result)
    service = AgentSessions({store.target: store})
    route = service.recent(store.target)[0].route
    selected = service.select(route)
    assert selected['id'] == route.session_id and SENTINEL not in _flat(selected)


@pytest.mark.parametrize('bad', ['', 'missing', '../x', 'C--Users-synthetic-work/../settings.json',
                                 'C--Users-synthetic-work/not-a-uuid', 'C--Users-synthetic-work/' + session_uuid(999_999)])
def test_exact_refuses_unknown_and_non_literal_identifiers(store, bad):
    with pytest.raises(RoutingError):
        store.exact(bad)


def test_exact_refuses_identity_mismatch_and_prefix_without_routing_fields(store):
    directory = store.home / 'projects' / 'C--Users-synthetic-work'
    sid, _ = write_claude_session(directory, 500, mismatch=True)
    with pytest.raises(RoutingError, match='does not match'):
        store.exact('C--Users-synthetic-work/' + sid)
    sid2 = session_uuid(501)
    only_summaries = directory / (sid2 + '.jsonl')
    only_summaries.write_text('\n'.join(json.dumps(dict(type='summary', summary=SENTINEL)) for _ in range(3)) + '\n')
    with pytest.raises(RoutingError, match='bounded prefix'):
        store.exact('C--Users-synthetic-work/' + sid2)
    big = directory / (session_uuid(502) + '.jsonl')
    big.write_bytes(b'{"type":"summary","summary":"' + b'x' * (session_file_store.PREFIX_BYTES + 10) + b'"}\n'
                    + json.dumps(dict(sessionId=session_uuid(502), cwd='/late')).encode() + b'\n')
    with pytest.raises(RoutingError, match='bounded prefix'):
        store.exact('C--Users-synthetic-work/' + session_uuid(502))


def test_budgets_refuse_incomplete_enumeration(store):
    store.max_sessions = 3
    with pytest.raises(RoutingError, match='session budget'):
        store.metadata(store.target)
    store.max_sessions = 20_000
    store.max_entries = 4
    with pytest.raises(RoutingError, match='work/time budget'):
        store.metadata(store.target)


def test_replaced_store_and_changed_review_snapshot_fail_closed(tmp_path, store):
    snapshot = dict(profile=str(store.home), identity=list(store.identity),
                    home_identity=list(store.profile.home_identity), harness='claude')
    assert ClaudeCodeHistory(store.home, review_snapshot=snapshot).identity == store.identity
    with pytest.raises(RoutingError, match='identity changed'):
        ClaudeCodeHistory(store.home, review_snapshot=dict(snapshot, harness='codex'))
    with pytest.raises(RoutingError, match='identity changed'):
        ClaudeCodeHistory(store.home, review_snapshot=dict(snapshot, identity=[0, 0]))
    replaced = tmp_path / 'replacement'
    (store.home / 'projects').rename(replaced)
    (store.home / 'projects').mkdir()
    with pytest.raises(RoutingError, match='replaced'):
        store.metadata(store.target)


def test_missing_store_is_empty_not_connectable_and_launch_is_refused(tmp_path):
    home = tmp_path / 'fresh'
    home.mkdir()
    adapter = ClaudeCodeHistory(home)
    assert adapter.identity is None and adapter.metadata(adapter.target) == ()
    with pytest.raises(RoutingError):
        adapter.exact('p/' + session_uuid(1))
    with pytest.raises(RoutingError, match='no verified native launch adapter'):
        adapter.launch_plan(tmp_path, authorized=True)


@pytest.mark.skipif(not hasattr(os, 'symlink') or os.name != 'posix', reason='POSIX symlink semantics')
def test_symlinked_root_and_session_links_are_refused_or_skipped(tmp_path, store):
    link_home = tmp_path / 'link-home'
    os.symlink(store.home, link_home)
    with pytest.raises(RoutingError, match='symlink'):
        ClaudeCodeHistory(link_home)
    directory = store.home / 'projects' / 'C--Users-synthetic-work'
    real = next(directory.glob('*.jsonl'))
    os.symlink(real, directory / (session_uuid(777) + '.jsonl'))
    ids = {x.route.session_id for x in store.metadata(store.target)}
    assert 'C--Users-synthetic-work/' + session_uuid(777) not in ids
    with pytest.raises(RoutingError):
        store.exact('C--Users-synthetic-work/' + session_uuid(777))
