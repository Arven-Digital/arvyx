"""Authenticated production HTTP handler, real consent/creation SQLite state."""
import hashlib,json
from types import SimpleNamespace
import pytest
from arvyx_control.local_onboarding import local_composition
from arvyx_control.public_onboarding_api import handler_for,fixture_composition
from test_local_handler_wire import request

@pytest.fixture
def http(tmp_path):
    directory=tmp_path/'onboarding';directory.mkdir(mode=0o700)
    api=local_composition(directory,vault=tmp_path/'vault',machine_id='local-machine',capability='browser-test')
    server=SimpleNamespace(server_address=('127.0.0.1',12345),server_port=12345,origin='http://127.0.0.1:12345')
    handler=handler_for(api)
    def call(path,body=None,**kwargs):return request(handler,server,'/api/public-onboarding/'+path,body,**kwargs)
    yield api,call
    api.close()


def test_real_local_legacy_creation_cannot_bypass_reviewed_consent(http):
    api,call=http
    body=dict(name='Fresh',harness='hermes',confirmed=True)
    assert call('agents/create',body,auth=False)[0]==401
    assert call('agents/create',body,origin=False)[0]==403
    assert call('agents/create',body)[0]==409
    assert call('agents')[1]['items']==[]
    assert api.owners['local-owner'].creation.db.execute('SELECT COUNT(*) FROM onboarding_consents').fetchone()[0]==0


def test_http_creation_rejects_missing_expired_changed_and_reused_consent(http):
    api,call=http
    assert call('agents/commit',dict(confirmed=True))[0]==400
    body=dict(name='Reviewed',harness='hermes',environment='metadata',identity_mode='clean')
    status,prepared=call('agents/prepare',body);assert status==200
    commit=dict(consent_id=prepared['consent_id'],consent_sha256=prepared['sha256'],confirmed=True)
    assert call('agents/commit',dict(commit,consent_sha256='changed'))[0]==400
    assert call('agents/commit',dict(commit,name='Changed after review'))[0]==400
    db=api.owners['local-owner'].creation.db
    with db:db.execute('UPDATE onboarding_consents SET expires=0')
    assert call('agents/commit',commit)[0]==400
    prepared=call('agents/prepare',body)[1]
    commit.update(consent_id=prepared['consent_id'],consent_sha256=prepared['sha256'])
    assert call('agents/commit',commit)[0]==201
    assert call('agents/commit',commit)[0]==400
    assert len(call('agents')[1]['items'])==1


def test_fixture_clean_creation_contract_remains_explicit(http,tmp_path):
    api,key,adapter=fixture_composition(tmp_path/'fixture')
    api.credentials={hashlib.sha256(b'browser-test').hexdigest():'fixture-owner'}
    server=SimpleNamespace(server_address=('127.0.0.1',12345),server_port=12345,origin='http://127.0.0.1:12345')
    try:
        handler=handler_for(api);path='/api/public-onboarding/agents/create'
        assert request(handler,server,path,dict(name='Fixture',harness='fixture',confirmed=False))[0]==400
        assert request(handler,server,path,dict(name='Fixture',harness='fixture',confirmed=True))[0]==201
    finally:api.close()
