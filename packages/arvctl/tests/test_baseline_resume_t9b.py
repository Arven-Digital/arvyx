"""Baseline boundary regressions, authored but NOT_EXECUTED in t_9ca72893."""
from contextlib import contextmanager
from unittest.mock import patch
import time

import pytest
from arvyx_control.remote_delegation import RemoteDelegationEndpoint
from arvyx_control.organizer_authority import OrganizerAuthority
from arvyx_control.organizer_delegation import DelegationService
from arvyx_control.replica_authority import authority_context
from arvyx_control.shared_onboarding_cli import client


def wire(environment='host'):
    return dict(machine='machine-a',executing_agent='worker',session='session-exact',
                operation='invoke_'+environment,environment=environment,goal='new-local-shell',
                request_id='a'*32,decision=dict(initiating_organizer='organizer'),
                root_acknowledged=environment=='root',consent_expires_at=time.time()+60,receiving_leaf='d'*64,
                delegation_fence=dict(authority_id='b'*64,token='c'*64))


@pytest.mark.parametrize('environment,operation',[('root','invoke_root'),('host','invoke_root')])
def test_remote_root_refused_before_transport_or_attempt(tmp_path,environment,operation):
    with authority_context(tmp_path/'vault'),patch('arvyx_control.shared_onboarding_cli.client') as factory:
        endpoint=RemoteDelegationEndpoint(tmp_path/'links.sqlite','http://127.0.0.1:12345','fixture',machine='machine-a')
        try:
            # A root operation without the original human root acknowledgement is
            # refused first, on the plan itself, before any protocol consideration.
            with pytest.raises(PermissionError,match='explicit original root risk acknowledgement required'):
                endpoint.execute(dict(wire(environment),operation=operation,root_acknowledged=False))
            # Even with the original acknowledgement, remote root stays unavailable
            # until authenticated approval transfer/final admission exists.
            with pytest.raises(PermissionError,match='authenticated local approval transfer'):
                endpoint.execute(dict(wire(environment),operation=operation,root_acknowledged=True))
            factory.return_value.assert_not_called()
            assert endpoint.links('a'*32) is None
        finally:endpoint.close()


def test_remote_root_not_advertised_or_prepared_and_receiver_cannot_bypass(tmp_path):
    with authority_context(tmp_path/'vault'),patch('arvyx_control.shared_onboarding_cli.client'):
        policy=OrganizerAuthority(database=tmp_path/'policy.sqlite')
        actor=policy.provision_identity('organizer',kind='internal',organizer=True)
        worker=policy.provision_identity('worker',kind='internal')
        policy.enroll_machine('machine-a');policy.bind_agent(worker,machine='machine-a',root=True)
        endpoint=RemoteDelegationEndpoint(tmp_path/'links.sqlite','http://127.0.0.1:12345','fixture',machine='machine-a')
        service=DelegationService(tmp_path/'requests.sqlite',policy,actor,{('machine-a','worker','session-exact'):endpoint})
        try:
            assert service.catalog()[0]['environments']==['host','sandbox']
            request={key:wire('root')[key] for key in ('machine','executing_agent','session','operation','environment','goal')}
            with pytest.raises(PermissionError,match='authenticated local approval transfer'):
                service.route('delegations/prepare','POST',request)
            assert service.db.execute('SELECT count(*) FROM organizer_requests').fetchone()[0]==0
            # Deny at the receiving authority too, even if a caller bypasses the
            # sender and presents a locally acknowledged or synthetically sealed plan.
            with patch('arvyx_control.organizer_durable.validate_delegated_effect') as validate:
                with pytest.raises(PermissionError,match='authenticated local approval transfer'):
                    service.route('delegations/fenced-execute','POST',wire('root'))
                validate.assert_not_called()
            assert service.db.execute('SELECT count(*) FROM organizer_requests').fetchone()[0]==0
        finally:service.close();endpoint.close();policy.close()


def test_nonroot_forwarding_keeps_attempt_expiry_and_one_deadline(tmp_path):
    calls=[]
    plan=wire()
    def transport(path,data=None,*,deadline=None):
        calls.append((path,data,deadline))
        if path=='capabilities':return dict(owner_host='machine-a')
        if path=='delegations/fence':return dict(organizer_effect_fence='b'*64)
        assert path=='delegations/fenced-execute'
        assert data==plan
        return dict(id=plan['request_id'],status='completed')
    with authority_context(tmp_path/'vault'),patch('arvyx_control.shared_onboarding_cli.client',return_value=transport):
        endpoint=RemoteDelegationEndpoint(tmp_path/'links.sqlite','http://127.0.0.1:12345','fixture',machine='machine-a')
        try:
            assert endpoint.execute(plan)==dict(status='remote_completed',reference=plan['request_id'])
            assert [call[0] for call in calls]==['capabilities','delegations/fence','capabilities','delegations/fenced-execute']
            assert len({call[2] for call in calls})==1
            assert endpoint.links(plan['request_id'])==dict(remote_id=plan['request_id'],status='completed')
            with pytest.raises(ValueError,match='reconcile'):
                endpoint.execute(plan)
            assert len(calls)==4
        finally:endpoint.close()


@pytest.mark.parametrize('path,body',[('delegations/fence',None),('delegations/fenced-execute',{'fixture':True})])
def test_real_client_allowlist_reaches_fenced_routes_without_network(path,body):
    calls=[]
    class Response:
        def read(self,size):return b'{}'
    class Recorder:
        @contextmanager
        def open(self,request,timeout):
            calls.append((request.full_url,request.get_method(),timeout))
            yield Response()
    with patch('arvyx_control.http_bounds.BoundedOpener',return_value=Recorder()):
        call=client('http://127.0.0.1:12345','synthetic-fixture',timeout=2)
        assert call(path,body,deadline=time.monotonic()+1)=={}
    assert len(calls)==1
    assert calls[0][0]=='http://127.0.0.1:12345/api/public-onboarding/'+path
    assert calls[0][1]==('GET' if body is None else 'POST')
    assert 0<calls[0][2]<=1
