"""Durable existing policy + consented endpoint dispatch; fixture effect only."""
import inspect,json
from types import SimpleNamespace
from dataclasses import replace
import pytest
from arvyx_control.organizer_authority import OrganizerAuthority
from arvyx_control.executor_endpoint import ExecutorEndpoint
from test_local_onboarding_services import services
from delegation_fixture_helpers import capabilities,admitted
from test_local_handler_wire import request
from arvyx_control.public_onboarding_api import handler_for

@pytest.fixture(autouse=True)
def disposable_authority(tmp_path):
    from arvyx_control.replica_authority import authority_context
    with authority_context(tmp_path / "vault"):
        yield

def policy(path):
    # Baseline remains executable: demonstrate its volatile state losing audit.
    return OrganizerAuthority(database=path) if 'database' in inspect.signature(OrganizerAuthority).parameters else OrganizerAuthority()

def seed(p):
    actor=p.provision_identity('organizer',kind='internal',organizer=True)
    worker=p.provision_identity('worker',kind='internal');p.enroll_machine('machine-a');p.bind_agent(worker,machine='machine-a',root=True)
    return actor,worker

def test_policy_and_attributable_audit_survive_reopen_without_granting_claims(tmp_path):
    path=tmp_path/'policy.sqlite';p=policy(path);actor,worker=seed(p)
    assert p.authorize(actor,operation='invoke_root',machine='machine-a',executing_agent=worker).allowed
    reopened=policy(path)
    assert len(reopened.audit())==1,'existing in-memory policy loses audit and all provisioning on reopen'
    actor2=reopened.identity_handle('organizer');worker2=reopened.identity_handle('worker')
    assert reopened.authorize(actor2,operation='invoke_root',machine='machine-a',executing_agent=worker2).allowed
    assert not reopened.authorize(replace(actor2),operation='invoke_root',machine='machine-a',executing_agent=worker2).allowed
    reopened.set_organizer(actor2,False)
    assert not p.authorize(actor,operation='invoke_root',machine='machine-a',executing_agent=worker).allowed
    assert p.audit()[-1].initiating_principal=='organizer'
    p.close();reopened.close()

@pytest.fixture
def delegation(services,tmp_path):
    api,_,profile,root=services;p=policy(tmp_path/'policy.sqlite');actor,worker=seed(p);calls=[]
    endpoint=ExecutorEndpoint('http://127.0.0.1:12345','fixture',machine='machine-a',agent='worker',session='session-exact',environments=('root',))
    def effect(path,data=None,*,deadline=None):
        if path=='capabilities':return capabilities(p,machine='machine-a',agent='worker',session='session-exact',environments=['root'])
        with admitted(p,data):
            calls.append(data);(tmp_path/'effect.json').write_text(json.dumps(data))
        return dict(request_id=data['request_id'],status='completed',reference='disposable-effect')
    endpoint._call=effect
    from arvyx_control.organizer_delegation import DelegationService
    service=DelegationService(tmp_path/'delegation.sqlite',p,actor,{('machine-a','worker','session-exact'):endpoint})
    api.owners['local-owner'].extension.delegations=service
    server=SimpleNamespace(server_address=('127.0.0.1',12345),server_port=12345,origin='http://127.0.0.1:12345')
    handler=handler_for(api)
    def call(path,body=None,**kw):return request(handler,server,'/api/public-onboarding/'+path,body,**kw)
    yield p,actor,worker,calls,call,service
    if service:service.close()
    if hasattr(p,'close'):p.close()

def body():return dict(machine='machine-a',executing_agent='worker',session='session-exact',operation='invoke_root',environment='root',goal='Record an explicit disposable fixture effect.')
def consent(p,ack=True):return dict(consent_id=p['consent_id'],consent_sha256=p['sha256'],confirmed=True,root_acknowledged=ack)

def test_http_review_effect_and_audit_exact_destination_single_use(delegation):
    p,actor,worker,calls,call,service=delegation
    assert call('delegations/prepare',body(),auth=False)[0]==401
    assert call('delegations/prepare',body(),origin=False)[0]==403
    status,review=call('delegations/prepare',body());assert status==200,review
    assert not calls
    assert call('delegations/commit',consent(review,False))[0]==400
    assert call('delegations/commit',dict(consent(review),consent_sha256='changed'))[0]==400
    status,result=call('delegations/commit',consent(review));assert status==200,result
    assert len(calls)==1 and calls[0]['session']=='session-exact'
    assert calls[0]['decision']['authority_chain']==['organizer','worker','machine-a','root']
    assert call('delegations/commit',consent(review))[0]==400
    assert call('delegations')[1]['items'][0]['status']=='completed'
    assert p.audit()[-1].initiating_organizer=='organizer'

def test_fresh_revocation_missing_endpoint_and_ambiguous_result_never_retry(delegation):
    p,actor,worker,calls,call,service=delegation
    status,review=call('delegations/prepare',body());assert status==200,review
    p.set_machine_state('machine-a','disconnected')
    assert call('delegations/commit',consent(review))[0]==403 and not calls
    p.enroll_machine('machine-a')
    assert call('delegations/prepare',dict(body(),session='other-session'))[0] in (403,501)
    endpoint=service.endpoints[('machine-a','worker','session-exact')]
    old=endpoint._call
    def lost(path,data=None,*,deadline=None):
        result=old(path,data,deadline=deadline)
        if path=='executor/execute':raise OSError('fixture lost reply after effect')
        return result
    endpoint._call=lost
    status,review=call('delegations/prepare',body());assert status==200
    assert call('delegations/commit',consent(review))[0]==503
    assert call('delegations/commit',consent(review))[0]==400 and len(calls)==1
    assert call('delegations')[1]['items'][0]['status']=='ambiguous'


def replace_endpoint(service):
    """A new executor connection object at the same exact address/binding.

    It keeps the disposable in-memory transport (no socket is opened), so its
    read-only binding discovery succeeds and only the incarnation differs.
    """
    key=('machine-a','worker','session-exact');old=service.endpoints[key]
    replacement=ExecutorEndpoint('http://127.0.0.1:12345','fixture',machine='machine-a',agent='worker',session='session-exact',environments=('root',))
    replacement._call=old._call
    service.endpoints[key]=replacement
    return replacement


def test_changed_executor_incarnation_requires_a_new_review(delegation):
    _,_,_,calls,call,service=delegation
    status,review=call('delegations/prepare',body());assert status==200
    class Replacement:
        def execute(self,plan):calls.append(plan);return dict(status='replacement')
    replace_endpoint(service)
    status,refused=call('delegations/commit',consent(review))
    assert status==400,refused
    assert not calls
    # Refused before any attempt is recorded; a fresh review of the new
    # connection is the only path to an effect (positive control).
    assert service.db.execute('SELECT status FROM organizer_requests WHERE id=?',(review['consent_id'],)).fetchone()[0]=='prepared'
    status,fresh=call('delegations/prepare',body());assert status==200,fresh
    status,result=call('delegations/commit',consent(fresh));assert status==200,result
    assert len(calls)==1 and calls[0]['request_id']==fresh['consent_id']


def test_executor_object_id_reuse_cannot_reuse_review(delegation):
    from unittest.mock import patch
    _,_,_,calls,call,service=delegation
    class Replacement:
        def execute(self,plan):calls.append(plan);return dict(status='replacement')
    with patch('arvyx_control.organizer_delegation.id',return_value=7,create=True):
        _,review=call('delegations/prepare',body())
        replace_endpoint(service)
        assert call('delegations/commit',consent(review))[0]==400
    assert not calls


def test_commit_denial_is_a_durable_policy_audit_even_when_request_rolls_back(delegation):
    p,actor,worker,calls,call,service=delegation
    _,review=call('delegations/prepare',body())
    before=len(p.audit());p.set_organizer(actor,False)
    assert call('delegations/commit',consent(review))[0]==403
    assert len(p.audit())==before+1
    assert p.audit()[-1].allowed is False and not calls


def test_separate_process_revocation_is_loaded_before_dispatch(tmp_path):
    import subprocess,sys
    path=tmp_path/'policy.sqlite';p=OrganizerAuthority(database=path);actor,worker=seed(p)
    code = ('from arvyx_control.organizer_authority import OrganizerAuthority; '
            'from arvyx_control.replica_authority import authority_context; '
            'from pathlib import Path; import sys; '
            'binding=authority_context(Path(sys.argv[2])); binding.__enter__(); '
            'p=OrganizerAuthority(database=sys.argv[1]); '
            'p.set_organizer(p.identity_handle("organizer"),False); '
            'p.close(); binding.__exit__(None,None,None)')
    result=subprocess.run([sys.executable,'-c',code,str(path),str(tmp_path/'vault')],check=True)
    assert not p.dispatch(actor,operation='invoke_root',machine='machine-a',executing_agent=worker).allowed
    assert p.audit()[-1].allowed is False
    p.close()
