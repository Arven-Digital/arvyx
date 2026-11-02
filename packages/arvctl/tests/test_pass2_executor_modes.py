"""Explicit executor modes compose policy, durable consent and exact transport."""
from unittest.mock import patch
import pytest
from arvyx_control.organizer_authority import OrganizerAuthority
from arvyx_control.organizer_delegation import DelegationService
from arvyx_control.executor_endpoint import ExecutorEndpoint
from arvyx_control.replica_authority import authority_context
from test_durable_organizer_journey import seed,body,consent
from delegation_fixture_helpers import capabilities,admitted


@pytest.mark.parametrize('mode',['sandbox','host'])
def test_mode_needs_its_own_persisted_attestation_and_exact_endpoint(tmp_path,mode):
    with authority_context(tmp_path/'vault'):
        p=OrganizerAuthority(database=tmp_path/'policy.sqlite');actor,worker=seed(p)
        operation='invoke_'+mode
        assert not p.authorize(actor,operation=operation,machine='machine-a',executing_agent=worker).allowed
        p.bind_executor(worker,machine='machine-a',environments=(mode,))
        reopened=OrganizerAuthority(database=tmp_path/'policy.sqlite')
        assert reopened.authorize(reopened.identity_handle('organizer'),operation=operation,machine='machine-a',executing_agent=reopened.identity_handle('worker')).allowed
        effects=[]
        def call(path,data=None,*,deadline=None):
            if path=='capabilities':return capabilities(p,machine='machine-a',agent='worker',session='session-exact',environments=[mode])
            with admitted(p,data):effects.append(data)
            return dict(request_id=data['request_id'],status='completed',reference='fixture-effect')
        with patch('arvyx_control.shared_onboarding_cli.client',return_value=call):endpoint=ExecutorEndpoint('http://127.0.0.1:12345','fixture',machine='machine-a',agent='worker',session='session-exact',environments=(mode,))
        service=DelegationService(tmp_path/'requests.sqlite',p,actor,{('machine-a','worker','session-exact'):endpoint})
        request=dict(body(),operation=operation,environment=mode)
        try:
            _,review=service.route('delegations/prepare','POST',request)
            assert effects==[]
            assert service.route('delegations/commit','POST',consent(review,False))[0]==200
            assert len(effects)==1 and effects[0]['environment']==mode
            assert effects[0]['decision']['authority_chain']==['organizer','worker','machine-a',mode]
            p.bind_executor(worker,machine='machine-a',environments=())
            with pytest.raises(PermissionError):service.route('delegations/prepare','POST',request)
        finally:service.close();reopened.close();p.close()
