"""Durable consent is checked at the production API boundary, no native effects."""
import sqlite3
import pytest
from test_local_onboarding_services import services as original_services
from unittest.mock import patch
from test_local_onboarding_services import services


@pytest.fixture
def services(original_services):
    api,_,profile,root=original_services
    def raw(path,body=None):return api.dispatch('GET' if body is None else 'POST','/api/public-onboarding/'+path,'Bearer browser-test',{} if body is None else body)
    return api,raw,profile,root


def prepare(call,path,body):
    status,review=call('actions/prepare',dict(action=path,request=body))
    assert status==200,review
    return dict(consent_id=review['consent_id'],consent_sha256=review['sha256'],confirmed=True)


def test_legacy_boolean_is_not_a_reviewed_manual_connection(services):
    api,call,profile,_=services
    status,result=call('manual/connect',dict(family='hermes',path=str(profile),agent_id='agent-a',confirmed=True))
    assert status==409 and result['error']=='reviewed_action_consent_required'
    assert call('targets')[1]['items']==[]


def test_reviewed_connection_survives_reopen_readback_and_cannot_replay(services):
    api,call,profile,root=services
    body=dict(family='hermes',path=str(profile),agent_id='agent-a',confirmed=True)
    commit=prepare(call,'manual/connect',body)
    assert call('targets')[1]['items']==[]
    assert call('actions/commit',dict(commit,consent_sha256='wrong'))[0]==400
    status,result=call('actions/commit',commit)
    assert status==200 and result['target']['agent_id']=='agent-a'
    assert call('actions/commit',commit)[0]==400
    with sqlite3.connect(root/'agents.sqlite') as db:
        row=db.execute('SELECT actor,action,status,result FROM reviewed_actions').fetchone()
        assert row[:3]==('local-owner','manual/connect','completed')
        assert 'agent-a' in row[3]
    assert call('actions/attempts/'+commit['consent_id'])[1]['status']=='completed'
    from arvyx_control.local_onboarding import local_composition
    api.close()
    reopened=local_composition(root,vault=api.owners['local-owner'].extension.vault,machine_id='machine-a',capability='browser-test')
    try:
        def again(path,body=None):return reopened.dispatch('GET' if body is None else 'POST','/api/public-onboarding/'+path,'Bearer browser-test',body or {})
        assert again('actions/attempts/'+commit['consent_id'])[1]['status']=='completed'
        assert again('actions/commit',commit)[0]==400
        assert again('targets')[1]['items']==[result['target']]  # Durable reviewed metadata identity; no runtime lease is restored.
    finally:reopened.close()


def test_replaced_profile_expiry_and_ambiguous_effect_fail_closed(services):
    api,call,profile,_=services
    body=dict(family='hermes',path=str(profile),agent_id='agent-a',confirmed=True)
    commit=prepare(call,'manual/connect',body)
    (profile/'state.db').rename(profile/'old.db')
    with sqlite3.connect(profile/'state.db') as db:db.executescript('CREATE TABLE sessions(id TEXT,title TEXT,started_at REAL);')
    assert call('actions/commit',commit)[0]==400
    commit=prepare(call,'manual/connect',body)
    with api.owners['local-owner'].creation.db as db:db.execute('UPDATE reviewed_actions SET expires=0')
    assert call('actions/commit',commit)[0]==400
    commit=prepare(call,'manual/connect',body)
    extension=api.owners['local-owner'].extension
    original=extension.route
    def lose(path,method,body,**kwargs):
        result=original(path,method,body,**kwargs)
        if path=='manual/connect':raise OSError('lost acknowledgement after publication')
        return result
    with patch.object(extension,'route',side_effect=lose):
        assert call('actions/commit',commit)[0]==503
    assert call('targets')[1]['items']
    assert call('actions/attempts/'+commit['consent_id'])[1]['status']=='ambiguous'
    assert call('actions/commit',commit)[0]==400


def test_discovered_hermes_profile_connects_only_after_exact_identity_review(services):
    api,call,profile,root=services
    owner=api.owners['local-owner']
    candidate=dict(id='hermes:profile:one',family='hermes',label='Hermes',kind='profile',local_id='one',path=str(profile/'config.yaml'),location='~/.hermes/profiles/one/config.yaml')
    owner.discovery=lambda:dict(candidates=[candidate],truncated=False)
    scan=call('discover',{})[1]
    assert scan['candidates'][0]['available'] is True
    assert scan['candidates'][0]['requires_agent_id'] is True
    body=dict(candidate_id=candidate['id'],agent_id='agent-a',confirmed=True)
    assert call('profiles/connect',body)[0]==409
    commit=prepare(call,'profiles/connect',body)
    assert call('targets')[1]['items']==[]
    status,result=call('actions/commit',commit)
    assert status==200 and result['metadata_only'] is True and result['live_runtime'] is False
    assert result['target']['agent_id']=='agent-a'
    assert call('actions/prepare',dict(action='profiles/connect',request=dict(body,agent_id='unregistered')))[0]==403


def test_consent_is_bound_to_authenticated_owner_not_a_submitted_name(services):
    import hashlib
    api,call,profile,_=services
    commit=prepare(call,'manual/connect',dict(family='hermes',path=str(profile),agent_id='agent-a',confirmed=True))
    api.owners['different-owner']=api.owners['local-owner']
    api.credentials[hashlib.sha256(b'other-capability').hexdigest()]='different-owner'
    assert api.dispatch('POST','/api/public-onboarding/actions/commit','Bearer other-capability',commit)[0]==400
    assert api.dispatch('GET','/api/public-onboarding/actions/attempts/'+commit['consent_id'],'Bearer other-capability',{})[0]==404
    assert call('actions/commit',commit)[0]==200
    api.owners.pop('different-owner')
