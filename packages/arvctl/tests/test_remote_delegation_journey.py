"""Independent source/receiver policies, production handlers, harmless owner recorder."""
from types import SimpleNamespace
import pytest
from arvyx_control.local_onboarding import local_composition
from arvyx_control.public_onboarding_api import handler_for
from test_local_handler_wire import request as wire_request
from test_completion_fix5_F import lane,journey,services
from test_completion_fix5_remote_fence import remote,fence_authority,prepare,commit


@pytest.mark.parametrize('lane',['root'],indirect=True)
def test_remote_handler_to_durable_executor_chain_and_lost_reply(remote):
    lane=remote['lane'];service=remote['receiver'];endpoint=remote['endpoint']
    assert remote['source']._backend.path!=lane['policy']._backend.path
    directory=lane['tmp']/'remote-http';directory.mkdir(mode=0o700)
    api=local_composition(directory,vault=lane['owner'].vault,machine_id='machine-a',capability='browser-test')
    api.owners['local-owner'].extension.delegations=service
    handler=handler_for(api);server=SimpleNamespace(server_address=('127.0.0.1',12345),server_port=12345,origin='http://127.0.0.1:12345');calls=[]
    def call(path,data=None,**kw):
        calls.append(path);status,result=wire_request(handler,server,'/api/public-onboarding/'+path,data)
        if status>=300:raise PermissionError(result)
        return result
    endpoint.call=call
    try:
        consent=prepare(remote);assert not lane['effects']
        status,result=commit(remote,consent);assert status==200,result
        assert result['status']=='completed' and len(lane['effects'])==1
        link=endpoint.links(consent['consent_id']);assert link==dict(remote_id=consent['consent_id'],status='completed')
        assert service.route('delegations','GET',{})[1]['items'][0]['id']==consent['consent_id']
        with pytest.raises(ValueError):commit(remote,consent)
        def lost_reply(path,data=None,**kw):
            result=call(path,data,**kw)
            if path=='delegations/fenced-execute':raise OSError('synthetic reply lost after remote durable effect')
            return result
        endpoint.call=lost_reply;second=prepare(remote)
        status,uncertain=commit(remote,second)
        assert status==503 and uncertain['status']=='ambiguous' and uncertain['reconcile_required'] is True
        assert len(lane['effects'])==2
        lost_link=endpoint.links(second['consent_id']);assert lost_link==dict(remote_id=second['consent_id'],status='ambiguous')
        recorded=remote['sender'].route('delegations','GET',{})[1]['items'][0]
        assert recorded['remote']['remote_id']==second['consent_id']
        assert service.route('delegations','GET',{})[1]['items'][0]['status']=='completed'
        with pytest.raises(ValueError):commit(remote,second)
        assert len(lane['effects'])==2
        assert 'delegations/prepare' not in calls and 'delegations/commit' not in calls
        endpoint.call=call
        # A machine mismatch arising after review is refused by commit's read-only
        # binding preflight: before any attempt, remote link or transport effect,
        # so no ambiguous attempt needs reconciliation.
        third=prepare(remote);endpoint.expected_machine='other-machine';before=list(calls)
        with pytest.raises(PermissionError,match='remote exact machine mismatch'):commit(remote,third)
        assert len(lane['effects'])==2 and calls==before and endpoint.links(third['consent_id']) is None
        assert remote['sender'].db.execute('SELECT status FROM organizer_requests WHERE id=?',(third['consent_id'],)).fetchone()[0]=='prepared'
        # A mismatch known at review time is refused before any consent is issued.
        with pytest.raises(PermissionError,match='remote exact machine mismatch'):prepare(remote)
        assert len(lane['effects'])==2 and calls==before
    finally:api.close()
