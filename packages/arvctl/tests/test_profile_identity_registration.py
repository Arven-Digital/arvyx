"""Fresh-install journey: a discovered Hermes profile can get an explicit identity.

Before this, the only registry writer required a running native session, so a
fresh owner could discover profiles but never connect one (403 at review).
"""
import json
import os
import sqlite3

import pytest

from test_pass2_reviewed_actions import services, original_services, prepare  # noqa: F401
from arvyx_control.cockpit_primary import compatible_native_identity
from arvyx_control.registry_enrollment import preflight, register_profile_identity


def _candidate(owner, profile, local_id='one'):
    candidate = dict(id='hermes:profile:' + local_id, family='hermes', label='Hermes', kind='profile',
                     local_id=local_id, path=str(profile / 'config.yaml'),
                     location='~/.hermes/profiles/' + local_id + '/config.yaml')
    owner.discovery = lambda: dict(candidates=[candidate], truncated=False)
    return candidate


def _registry(owner):
    return owner.extension.vault / 'registry'


def test_registration_requires_review_and_creates_permissionless_compatible_identity(services):
    api, call, profile, _ = services
    owner = api.owners['local-owner']
    candidate = _candidate(owner, profile)
    call('discover', {})
    body = dict(candidate_id=candidate['id'], display_name='Fresh Researcher', confirmed=True)
    before = sorted(p.name for p in (_registry(owner) / 'agents').glob('*.json'))
    # A direct POST without durable review is refused and writes nothing.
    assert call('profiles/register', body)[0] == 409
    assert sorted(p.name for p in (_registry(owner) / 'agents').glob('*.json')) == before
    status, result = call('actions/commit', prepare(call, 'profiles/register', body))
    assert status == 201, result
    assert result['registered'] is True and result['scopes'] == [] and result['execution'] is False
    agent_id = result['agent_id']
    record = json.loads((_registry(owner) / 'agents' / (agent_id + '.json')).read_text())
    assert record['scopes'] == [] and record['registration'] == 'explicit-local-human-profile'
    assert record['machine_id'] == owner.extension.machine
    runtime = json.loads((_registry(owner) / 'runtimes' / (record['runtime_id'] + '.json')).read_text())
    assert runtime['harness'] == 'hermes'
    assert oct(os.stat(_registry(owner) / 'agents' / (agent_id + '.json')).st_mode & 0o777) == '0o600'
    assert compatible_native_identity(owner.extension.vault, agent_id, owner.extension.machine, 'hermes')
    # Registration is not connection: no target exists until the separate review.
    assert call('targets')[1]['items'] == []
    connect = dict(candidate_id=candidate['id'], agent_id=agent_id, confirmed=True)
    status, connected = call('actions/commit', prepare(call, 'profiles/connect', connect))
    assert status == 200 and connected['target']['agent_id'] == agent_id
    # Display names are unique; a second registration with the same name is refused at review.
    assert call('actions/prepare', dict(action='profiles/register', request=dict(body, display_name='fresh researcher')))[0] == 400


def test_profile_cannot_be_rebound_to_another_identity_and_refusal_is_not_ambiguous(services):
    api, call, profile, _ = services
    owner = api.owners['local-owner']
    candidate = _candidate(owner, profile)
    call('discover', {})
    first = call('actions/commit', prepare(call, 'profiles/register',
                 dict(candidate_id=candidate['id'], display_name='First', confirmed=True)))[1]['agent_id']
    second = call('actions/commit', prepare(call, 'profiles/register',
                  dict(candidate_id=candidate['id'], display_name='Second', confirmed=True)))[1]['agent_id']
    assert call('actions/commit', prepare(call, 'profiles/connect',
                dict(candidate_id=candidate['id'], agent_id=first, confirmed=True)))[0] == 200
    status, result = call('actions/prepare', dict(action='profiles/connect',
                          request=dict(candidate_id=candidate['id'], agent_id=second, confirmed=True)))
    # Deterministic refusal at review, never a 503 ambiguous attempt after commit.
    assert status == 400, result
    with owner.creation.db as db:
        assert db.execute("SELECT count(*) FROM reviewed_actions WHERE status='ambiguous'").fetchone()[0] == 0


def test_registration_refuses_unknown_candidate_family_and_unsupported_harness(services):
    api, call, profile, _ = services
    owner = api.owners['local-owner']
    # Gemini is discovered but has no local metadata adapter (Claude Code and Codex now do).
    other = dict(id='gemini:agent:default', family='gemini', label='Gemini', kind='agent', local_id='default',
                 path=str(profile / 'settings.json'), location='~/.gemini/settings.json')
    owner.discovery = lambda: dict(candidates=[other], truncated=False)
    call('discover', {})
    body = dict(candidate_id='gemini:agent:default', display_name='Nope', confirmed=True)
    assert call('actions/prepare', dict(action='profiles/register', request=body))[0] == 400
    assert call('actions/prepare', dict(action='profiles/register', request=dict(body, candidate_id='missing')))[0] == 400
    with pytest.raises(ValueError):
        preflight(owner.extension.vault, owner.extension.machine, 'Nope', 'gemini')


@pytest.mark.parametrize('name', ['', ' padded', 'tab\tname', 'x' * 129])
def test_noncanonical_display_names_are_refused(services, name):
    api, _, _, _ = services
    owner = api.owners['local-owner']
    with pytest.raises(ValueError):
        register_profile_identity(owner.extension.vault, owner.extension.machine, name, 'hermes')


def test_unenrolled_machine_is_refused_and_agent_is_never_published_without_runtime(services, monkeypatch):
    api, _, _, _ = services
    owner = api.owners['local-owner']
    vault = owner.extension.vault
    with pytest.raises(ValueError):
        register_profile_identity(vault, 'unknown-machine', 'Orphan', 'hermes')
    before_agents = set((vault / 'registry' / 'agents').glob('*.json'))
    before_runtimes = set((vault / 'registry' / 'runtimes').glob('*.json')) if (vault / 'registry' / 'runtimes').exists() else set()
    import arvyx_control.registry_enrollment as module
    real_dump = module.json.dump
    calls = []

    def fail_on_agent(record, stream, **kwargs):
        calls.append(record['id'])
        if 'machine_id' in record:
            raise OSError('synthetic disk failure on agent publication')
        return real_dump(record, stream, **kwargs)

    monkeypatch.setattr(module.json, 'dump', fail_on_agent)
    with pytest.raises(OSError):
        register_profile_identity(vault, owner.extension.machine, 'Interrupted', 'hermes')
    # Both partial files are rolled back; nothing references a half-written identity.
    assert set((vault / 'registry' / 'agents').glob('*.json')) == before_agents
    assert set((vault / 'registry' / 'runtimes').glob('*.json')) == before_runtimes
    assert len(calls) == 2


def test_uncertain_registration_attempt_names_the_published_identity(services, monkeypatch):
    """REV-0568: a lost completion still leaves a reconcilable attempt naming the new agent."""
    api, call, profile, _ = services
    owner = api.owners['local-owner']
    candidate = _candidate(owner, profile)
    call('discover', {})
    body = dict(candidate_id=candidate['id'], display_name='Interrupted Identity', confirmed=True)
    import arvyx_control.reviewed_actions as reviewed
    real_encoded = reviewed.encoded

    def lose_completion(value):
        if isinstance(value, dict) and value.get('registered') is True:
            raise OSError('synthetic loss after publication, before the attempt is marked complete')
        return real_encoded(value)
    commit = prepare(call, 'profiles/register', body)
    monkeypatch.setattr(reviewed, 'encoded', lose_completion)
    status, result = call('actions/commit', commit)
    assert status == 503 and result['reconcile_required'] is True and result['consent_id'] == commit['consent_id']
    monkeypatch.undo()
    status, attempt = call('actions/attempts/' + commit['consent_id'])
    assert status == 200 and attempt['status'] == 'ambiguous' and attempt['reconcile_required'] is True
    planned = attempt['result']['planned']
    assert planned['display_name'] == 'Interrupted Identity' and planned['harness'] == 'hermes'
    assert planned['machine_id'] == owner.extension.machine
    assert attempt['registry_present'] == {'agent': True, 'runtime': True}
    assert compatible_native_identity(owner.extension.vault, planned['agent_id'], owner.extension.machine, 'hermes')
    # The name is taken by the identity that was published; the attempt now says which one.
    assert call('actions/prepare', dict(action='profiles/register', request=body))[0] == 400
    connect = dict(candidate_id=candidate['id'], agent_id=planned['agent_id'], confirmed=True)
    assert call('actions/commit', prepare(call, 'profiles/connect', connect))[0] == 200
    # A completed attempt carries the result, never a stale plan.
    done = prepare(call, 'profiles/register', dict(body, display_name='Completed Identity'))
    assert call('actions/commit', done)[0] == 201
    assert call('actions/attempts/' + done['consent_id'])[1]['result']['registered'] is True


def test_rolled_back_registration_attempt_reports_absent_identity(services, monkeypatch):
    api, call, profile, _ = services
    owner = api.owners['local-owner']
    candidate = _candidate(owner, profile)
    call('discover', {})
    body = dict(candidate_id=candidate['id'], display_name='Rolled Back', confirmed=True)
    import arvyx_control.registry_enrollment as module
    real_dump = module.json.dump

    def fail_on_agent(record, stream, **kwargs):
        if 'machine_id' in record:
            raise OSError('synthetic disk failure on agent publication')
        return real_dump(record, stream, **kwargs)
    commit = prepare(call, 'profiles/register', body)
    monkeypatch.setattr(module.json, 'dump', fail_on_agent)
    assert call('actions/commit', commit)[0] == 503
    monkeypatch.undo()
    attempt = call('actions/attempts/' + commit['consent_id'])[1]
    planned = attempt['result']['planned']
    assert attempt['status'] == 'ambiguous' and attempt['registry_present'] == {'agent': False, 'runtime': False}
    assert not (owner.extension.vault / 'registry' / 'agents' / (planned['agent_id'] + '.json')).exists()
    # Nothing was published, so the same display name registers cleanly afterwards.
    assert call('actions/commit', prepare(call, 'profiles/register', body))[0] == 201


def test_plan_recording_is_a_no_op_outside_a_reviewed_commit(services):
    from arvyx_control.reviewed_actions import record_attempt_plan
    assert record_attempt_plan(dict(agent_id='local-x')) is False


def test_existing_records_are_never_rewritten(services):
    api, _, _, _ = services
    owner = api.owners['local-owner']
    vault = owner.extension.vault
    snapshot = {p: p.read_bytes() for p in (vault / 'registry').rglob('*.json')}
    register_profile_identity(vault, owner.extension.machine, 'Additive', 'hermes')
    for path, data in snapshot.items():
        assert path.read_bytes() == data
