"""Claude Code and Codex metadata connections through the production onboarding chain.

Synthetic state roots and a disposable vault only. Discovery, registration,
reviewed connection, Last 5 / All / search / exact inspection and restore after
reopen all run through the real API; no harness is started and no transcript
content crosses the service boundary.
"""
import json

import pytest

from test_claude_code_history import SENTINEL as CLAUDE_SENTINEL, build_claude_home
from test_codex_history import SENTINEL as CODEX_SENTINEL, build_codex_home
from reviewed_action_helpers import reviewed_call
from arvyx_control import harness_discovery, metadata_adapters


@pytest.fixture
def services(tmp_path):
    from arvyx_control.local_onboarding import local_composition
    root = tmp_path / 'onboarding'
    root.mkdir(mode=0o700)
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    claude_home, claude_sessions = build_claude_home(tmp_path, projects=(('-home-synthetic-lab', 7),))
    claude_home.rename(home / '.claude')
    codex_home, codex_sessions = build_codex_home(tmp_path, count=6)
    codex_home.rename(home / '.codex')
    (home / '.gemini').mkdir()
    (home / '.gemini' / 'settings.json').write_text('{}')
    vault = tmp_path / 'vault'
    records = [('agents', dict(id='agent-codex', machine_id='machine-a', runtime_id='runtime-codex')),
               ('machines', dict(id='machine-a')),
               ('runtimes', dict(id='runtime-codex', harness='codex'))]
    for kind, record in records:
        directory = vault / 'registry' / kind
        directory.mkdir(parents=True, exist_ok=True)
        (directory / (record['id'] + '.json')).write_text(json.dumps(record))
    api = local_composition(root, vault=vault, machine_id='machine-a', capability='browser-test', discovery_home=home)

    def raw(path, body=None, token=None):
        return api.dispatch('GET' if body is None else 'POST', '/api/public-onboarding/' + path,
                            'Bearer ' + (token or 'browser-test'), {} if body is None else body)

    def call(path, body=None, **kwargs):
        return reviewed_call(raw, path, body, **kwargs)
    yield api, call, home, root, vault, claude_sessions, codex_sessions
    api.close()


def _candidates(call):
    status, result = call('discover', {})
    assert status == 200, result
    return {c['family']: c for c in result['candidates']}


def _clean(value):
    text = json.dumps(value)
    assert CLAUDE_SENTINEL not in text and CODEX_SENTINEL not in text
    return value


def test_registry_and_public_catalog_agree():
    assert harness_discovery.MANUAL_METADATA_FAMILIES == metadata_adapters.METADATA_HARNESSES == {'hermes', 'claude', 'codex'}
    rows = {row['family']: row for row in harness_discovery.discovery_catalog('linux')}
    for family in metadata_adapters.METADATA_HARNESSES:
        assert rows[family]['manual_metadata_connection_supported'] and rows[family]['runtime_adapter_verified'] is False
    assert not rows['gemini']['manual_metadata_connection_supported']
    for entry in metadata_adapters.catalog():
        assert entry['metadata_only'] is True and entry['runtime_adapter_verified'] is False
    with pytest.raises(ValueError):
        metadata_adapters.adapter('gemini')


def test_discovery_offers_metadata_connection_for_claude_and_codex_only(services):
    api, call, *_ = services
    by_family = _clean(_candidates(call))
    for family, label in (('claude', 'Claude Code'), ('codex', 'Codex')):
        assert by_family[family]['available'] is True and by_family[family]['requires_agent_id'] is True
        assert by_family[family]['reason'].startswith(f'Read-only {label} metadata adapter')
    assert by_family['gemini']['available'] is False and by_family['gemini'].get('requires_agent_id') is False
    assert by_family['gemini']['reason'] == 'No compatible local connection adapter is configured.'
    capabilities = call('capabilities')[1]
    assert [a['id'] for a in capabilities['metadata_adapters']] == ['hermes', 'claude', 'codex']
    assert all(a['runtime_adapter_verified'] is False for a in capabilities['metadata_adapters'])


def test_register_connect_list_search_and_inspect_claude_code(services):
    api, call, home, root, vault, claude_sessions, _ = services
    candidate = _candidates(call)['claude']
    status, registered = call('profiles/register', dict(candidate_id=candidate['id'], display_name='Claude Researcher', confirmed=True))
    assert status == 201, registered
    agent_id = registered['agent_id']
    runtime = json.loads((vault / 'registry' / 'agents' / (agent_id + '.json')).read_text())['runtime_id']
    assert json.loads((vault / 'registry' / 'runtimes' / (runtime + '.json')).read_text())['harness'] == 'claude'
    status, connected = call('profiles/connect', dict(candidate_id=candidate['id'], agent_id=agent_id, confirmed=True))
    assert status == 200, connected
    _clean(connected)
    assert connected['harness'] == 'claude' and connected['metadata_only'] is True and connected['live_runtime'] is False
    assert connected['instruction_source_id'] is None
    target = connected['target']
    assert target['agent_id'] == agent_id and target['workspace_id'] == str(home / '.claude')
    assert call('capabilities')[1]['instruction_sources'] == []
    recent = _clean(call('sessions/recent', dict(target=target))[1])['items']
    assert len(recent) == 5 and all(x['title'] == '-home-synthetic-lab' for x in recent)
    page = _clean(call('sessions/all', dict(target=target, limit=3))[1])
    ids = [x['route']['session_id'] for x in page['items']]
    while page['next_cursor']:
        page = _clean(call('sessions/all', dict(target=target, limit=3, cursor=page['next_cursor']))[1])
        ids.extend(x['route']['session_id'] for x in page['items'])
    assert sorted(ids) == sorted(claude_sessions)
    assert call('sessions/all', dict(target=target, query=CLAUDE_SENTINEL))[1]['total'] == 0
    status, selected = call('sessions/select', dict(route=recent[0]['route'], confirmed=True))
    assert status == 200, selected
    _clean(selected)
    assert selected['result']['cwd'] == '/synthetic/work' and selected['result']['encoding'] == 'jsonl'
    assert 'message' not in selected['result'] and 'summary' not in selected['result']
    # A second identity cannot take the same state root (review-time refusal, not an ambiguous attempt).
    second = call('profiles/register', dict(candidate_id=candidate['id'], display_name='Second', confirmed=True))[1]['agent_id']
    assert call('actions/prepare', dict(action='profiles/connect',
                request=dict(candidate_id=candidate['id'], agent_id=second, confirmed=True)))[0] == 400


def test_manual_codex_connection_restores_after_reopen(services):
    api, call, home, root, vault, _, codex_sessions = services
    body = dict(family='codex', path=str(home / '.codex'), agent_id='agent-codex', confirmed=True)
    assert call('manual/connect', dict(body, family='claude'))[0] == 403  # runtime record is a Codex identity
    status, connected = call('manual/connect', body)
    assert status == 200, connected
    assert connected['harness'] == 'codex' and connected['instruction_source_id'] is None
    target = connected['target']
    listed = _clean(call('sessions/all', dict(target=target, limit=100))[1])
    assert sorted(x['route']['session_id'] for x in listed['items']) == sorted(codex_sessions)
    compressed = next(x for x in listed['items'] if x['route']['session_id'].endswith('.zst'))
    status, selected = call('sessions/select', dict(route=compressed['route'], confirmed=True))
    assert status == 200 and selected['result']['encoding'] == 'zstd' and selected['result']['cwd'] is None
    from arvyx_control.local_onboarding import local_composition
    api.close()
    reopened = local_composition(root, vault=vault, machine_id='machine-a', capability='browser-test', discovery_home=home)
    try:
        def again(path, body=None):
            return reopened.dispatch('GET' if body is None else 'POST', '/api/public-onboarding/' + path, 'Bearer browser-test', body or {})
        assert again('targets')[1]['items'] == [target]
        restored = again('sessions/recent', dict(target=target))[1]['items']
        assert len(restored) == 5 and CODEX_SENTINEL not in json.dumps(restored)
        pin = json.loads(reopened.owners['local-owner'].creation.db.execute(
            'SELECT snapshot FROM onboarding_connection_pins').fetchone()[0])
        assert pin['harness'] == 'codex' and pin['profile'] == str(home / '.codex')
    finally:
        reopened.close()


def test_unsupported_family_and_foreign_marker_are_refused_at_review(services):
    api, call, home, *_ = services
    candidates = _candidates(call)
    gemini = candidates['gemini']
    assert call('actions/prepare', dict(action='profiles/register',
                request=dict(candidate_id=gemini['id'], display_name='Nope', confirmed=True)))[0] == 400
    assert call('actions/prepare', dict(action='manual/connect',
                request=dict(family='gemini', path=str(home / '.gemini'), agent_id='agent-codex', confirmed=True)))[0] == 400
    # A Codex candidate whose discovered marker is not config.toml cannot be connected as Codex.
    owner = api.owners['local-owner']
    forged = dict(candidates['codex'], id='codex:agent:forged', path=str(home / '.codex' / 'history.jsonl'))
    owner.discovery = lambda: dict(candidates=[forged], truncated=False)
    call('discover', {})
    assert call('actions/prepare', dict(action='profiles/connect',
                request=dict(candidate_id='codex:agent:forged', agent_id='agent-codex', confirmed=True)))[0] == 400
    # Registration for a family without an adapter is refused before any registry write.
    from arvyx_control.registry_enrollment import preflight
    with pytest.raises(ValueError):
        preflight(owner.extension.vault, 'machine-a', 'Nope', 'gemini')
