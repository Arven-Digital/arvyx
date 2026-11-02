"""Codex metadata adapter over a synthetic state root; nothing is launched."""
import json
import os
import uuid

import pytest

from arvyx_control.agent_sessions import AgentSessions, RoutingError
from arvyx_control.codex_history import CodexHistory

SENTINEL = 'SYNTHETIC-ROLLOUT-SENTINEL-MUST-NEVER-SURFACE'
BASE = 1_700_000_000


def rollout_uuid(i):
    return str(uuid.UUID(int=0xC0DE_0000 + i))


def write_codex_rollout(day_dir, i, *, compressed=False, legacy=False, mismatch=False, cwd='/synthetic/repo'):
    rid = rollout_uuid(i)
    stamp = f'2026-11-01T{i // 3600 % 24:02d}-{i // 60 % 60:02d}-{i % 60:02d}'
    name = f'rollout-{stamp}-{rid}.jsonl' + ('.zst' if compressed else '')
    path = day_dir / name
    if compressed:
        path.write_bytes(b'\x28\xb5\x2f\xfd' + os.urandom(64))  # zstd magic plus opaque bytes; never decoded
    else:
        meta = dict(id='ffffffff-ffff-4fff-8fff-ffffffffffff' if mismatch else rid, timestamp='2026-11-01T00:00:00.000Z',
                    cwd=cwd, originator='synthetic', cli_version='0.0.0-synthetic', instructions=SENTINEL)
        first = meta if legacy else dict(timestamp=meta['timestamp'], type='session_meta', payload=meta)
        rows = [first] + [dict(timestamp=meta['timestamp'], type='response_item',
                               payload=dict(type='message', role='user', content=[dict(type='input_text', text=SENTINEL)]))
                          for _ in range(3)]
        path.write_text('\n'.join(json.dumps(r) for r in rows) + '\n', encoding='utf-8')
    os.utime(path, (BASE + i, BASE + i))
    return f'{day_dir.parent.parent.name}/{day_dir.parent.name}/{day_dir.name}/{name}', stamp


def build_codex_home(root, *, count=6):
    home = root / 'codex-home'
    home.mkdir(mode=0o700)
    (home / 'config.toml').write_text('# synthetic\n', encoding='utf-8')
    (home / 'history.jsonl').write_text(SENTINEL + '\n', encoding='utf-8')
    day = home / 'sessions' / '2026' / '11' / '01'
    day.mkdir(parents=True)
    written = {}
    for i in range(count):
        sid, stamp = write_codex_rollout(day, i, compressed=(i % 3 == 2), legacy=(i % 3 == 1))
        written[sid] = (i, stamp)
    return home, written


@pytest.fixture
def store(tmp_path):
    home, written = build_codex_home(tmp_path)
    sessions = home / 'sessions'
    (sessions / 'notes.txt').write_text(SENTINEL, encoding='utf-8')
    (sessions / '2026' / '13x').mkdir()
    (sessions / '2026' / '11' / '01' / 'other.jsonl').write_text(SENTINEL, encoding='utf-8')
    (sessions / '2026' / '11' / '01' / 'rollout-bad-name.jsonl').write_text(SENTINEL, encoding='utf-8')
    adapter = CodexHistory(home)
    adapter.written = written
    return adapter


def test_listing_is_name_and_stat_only_with_timestamp_titles(store):
    items = store.metadata(store.target)
    assert {x.route.session_id for x in items} == set(store.written)
    for item in items:
        assert item.title == store.written[item.route.session_id][1]
        assert item.updated_at == BASE + store.written[item.route.session_id][0]
    assert store.last_scan == dict(sessions=6, skipped=4, probes=store.last_scan['probes'])
    assert SENTINEL not in json.dumps([x.__dict__ for x in items], default=str)
    service = AgentSessions({store.target: store})
    assert [x.route.session_id for x in service.recent(store.target)] == sorted(store.written, key=lambda k: -store.written[k][0])[:5]
    assert service.all(store.target, query='.zst').total == 2
    assert service.all(store.target, query=SENTINEL).total == 0


def test_exact_plain_legacy_and_compressed_rollouts(store):
    by_index = {v[0]: k for k, v in store.written.items()}
    plain = store.exact(by_index[0])
    assert plain['encoding'] == 'jsonl' and plain['cwd'] == '/synthetic/repo' and plain['cli_version'] == '0.0.0-synthetic'
    assert plain['started_at'] == '2026-11-01T00:00:00.000Z'
    legacy = store.exact(by_index[1])
    assert legacy['encoding'] == 'jsonl' and legacy['cwd'] == '/synthetic/repo'
    compressed = store.exact(by_index[2])
    assert compressed['encoding'] == 'zstd' and compressed['cwd'] is None and compressed['started_at'] == store.written[by_index[2]][1]
    assert 'zstd decoder' in compressed['note']
    for result in (plain, legacy, compressed):
        assert SENTINEL not in json.dumps(result) and 'instructions' not in result


@pytest.mark.parametrize('bad', ['', '2026/11/01/other.jsonl', '2026/11/01/../01/rollout-x.jsonl', '2026/11/rollout-x.jsonl',
                                 'abcd/11/01/rollout-2026-11-01T00-00-00-' + str(uuid.UUID(int=5)) + '.jsonl',
                                 '2026/11/01/rollout-2026-11-01T00-00-00-' + str(uuid.UUID(int=5)) + '.jsonl'])
def test_exact_refuses_unknown_and_non_literal_identifiers(store, bad):
    with pytest.raises(RoutingError):
        store.exact(bad)


def test_exact_refuses_identity_mismatch_and_empty_rollout(store):
    day = store.home / 'sessions' / '2026' / '11' / '01'
    sid, _ = write_codex_rollout(day, 50, mismatch=True)
    with pytest.raises(RoutingError, match='does not match'):
        store.exact(sid)
    empty_id, _ = write_codex_rollout(day, 51)
    (store.home / 'sessions' / empty_id).write_bytes(b'')
    with pytest.raises(RoutingError, match='bounded prefix'):
        store.exact(empty_id)


def test_budget_and_replacement_fail_closed(tmp_path, store):
    store.max_entries = 3
    with pytest.raises(RoutingError, match='work/time budget'):
        store.metadata(store.target)
    store.max_entries = 200_000
    snapshot = dict(profile=str(store.home), identity=list(store.identity), home_identity=list(store.profile.home_identity), harness='codex')
    assert CodexHistory(store.home, review_snapshot=snapshot).metadata(CodexHistory(store.home).target)
    (store.home / 'sessions').rename(tmp_path / 'moved')
    (store.home / 'sessions').mkdir()
    with pytest.raises(RoutingError, match='replaced'):
        store.metadata(store.target)
    with pytest.raises(RoutingError, match='no verified native launch adapter'):
        store.launch(tmp_path)
