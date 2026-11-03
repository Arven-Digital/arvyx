"""Leaf leases and exact organizer fences; disposable state, process/transport recorders."""
from contextlib import ExitStack
import inspect
import json
import os
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from test_local_onboarding_services import services
from test_session_workspace_journey import journey
from arvyx_control.replica_authority import authority_context

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='host-shell execution policy (host_uid) and the PTY owner are POSIX-only')


@pytest.fixture
def lane(journey, tmp_path, request, monkeypatch):
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control.native_lifecycle import OwnerProducer
    from arvyx_control.local_executor import ExecutionPolicy
    from arvyx_control.local_executor_service import LocalExecutorService
    from arvyx_control.organizer_authority import OrganizerAuthority
    mode=getattr(request,'param','host')
    monkeypatch.setattr(os,'geteuid',lambda:0 if mode=='root' else 1000)
    api, _, target, root, _ = journey
    ext = api.owners['local-owner'].extension
    database = tmp_path/'policy.sqlite'
    with authority_context(ext.vault):
        policy = OrganizerAuthority(database=database)
        actor = policy.provision_identity('organizer', kind='internal', organizer=True)
        worker = policy.provision_identity('agent-a', kind='internal')
        policy.enroll_machine('machine-a')
        policy.bind_agent(worker, machine='machine-a', root=True)
        policy.bind_executor(worker, machine='machine-a', environments=['host'])
    owner = LocalCockpit(tmp_path/'owner', ext.vault, tmp_path/'events.jsonl', 'machine-a')
    owner.delegation_authority_database = database
    producer = OwnerProducer(owner, policy=ExecutionPolicy(host_uid=os.geteuid(), allow_host=True, allow_root=True))
    args = dict(credential='x'*48, producer=producer, target=target, session='leaf', workspace=root/'existing',
                environments=[mode], identity_store=Path(ext.owner.creation.db.execute('PRAGMA database_list').fetchone()[2]))
    if 'authority_database' in inspect.signature(LocalExecutorService).parameters:
        args['authority_database'] = database
    leaf = LocalExecutorService(tmp_path/'leaf.sqlite', **args)
    effects = []
    def process(sid, **kwargs):
        # The production owner admission closure still runs with a harmless recorder.
        with ExitStack() as stack:
            check=stack.enter_context(kwargs['effect_guard']()) if kwargs.get('effect_guard') else None
            if kwargs.get('admission'): kwargs['admission']()
            if check: check()
            effects.append(sid)
            owner.db.execute("UPDATE sessions SET status='running',pid=12345 WHERE id=?", (sid,))
            owner.db.commit()
            owner.live[sid] = dict(process_generation='synthetic-'+sid,fd=1,attached=False)
    with patch.object(owner, '_start', side_effect=process):
        yield dict(leaf=leaf, args=args, producer=producer, owner=owner, policy=policy, actor=actor,
                   worker=worker, database=database, target=target, root=root, effects=effects, tmp=tmp_path, mode=mode)
    owner.live.clear()  # No process was created by this recorder.
    leaf.close(); owner.close(); policy.close()


def leaf_call(leaf, body=None):
    return leaf.dispatch('GET' if body is None else 'POST', '/api/public-onboarding/'+
        ('capabilities' if body is None else 'executor/execute'), 'Bearer '+'x'*48, body or {})


def request(mode='host'):
    return dict(machine='machine-a', executing_agent='agent-a', session='leaf', operation='invoke_'+mode,
                environment=mode, goal='new-local-shell')


def chain(lane, transport):
    from arvyx_control.executor_endpoint import ExecutorEndpoint
    from arvyx_control.organizer_delegation import DelegationService
    endpoint = ExecutorEndpoint('http://127.0.0.1:12345', 'x'*48, machine='machine-a', agent='agent-a',
                                session='leaf', environments=[lane['mode']], timeout=.10)
    endpoint._call = transport
    service = DelegationService(lane['tmp']/'requests.sqlite', lane['policy'], lane['actor'],
                                {('machine-a','agent-a','leaf'):endpoint})
    return service


def prepare(lane, service):
    with authority_context(lane['owner'].vault, lane['owner'].state):
        status, review = service.route('delegations/prepare', 'POST', request(lane['mode']))
    assert status == 200, review
    return dict(consent_id=review['consent_id'], consent_sha256=review['sha256'], confirmed=True,
                root_acknowledged=lane['mode']=='root')


def commit(lane, service, consent):
    with authority_context(lane['owner'].vault, lane['owner'].state):
        return service.route('delegations/commit', 'POST', consent)


@pytest.mark.parametrize('boundary', ['request', 'reopen'])
def test_workspace_directory_incarnation_is_a_provisioned_lease(lane, boundary):
    from arvyx_control.local_executor_service import LocalExecutorService
    workspace = lane['root']/'existing'
    workspace.rename(lane['root']/'original'); workspace.mkdir()
    if boundary == 'reopen':
        with pytest.raises(PermissionError):
            reopened = LocalExecutorService(lane['tmp']/'leaf.sqlite', **lane['args'])
            reopened.close()
    else:
        assert leaf_call(lane['leaf'])[0] == 403
    assert not lane['effects']


@pytest.mark.parametrize('lane',['host','root'],indirect=True)
@pytest.mark.parametrize('revocation', ['organizer', 'machine'])
def test_timeout_does_not_authorize_a_late_first_effect(lane, revocation):
    entered = threading.Event(); release = threading.Event(); finished = threading.Event()
    result = []; threads = []
    original = lane['producer'].plan
    def delayed(*args, **kwargs):
        value = original(*args, **kwargs)
        entered.set(); assert release.wait(3)
        return value
    def transport(path, data=None, *, deadline=None):
        if path == 'capabilities':
            status, value = leaf_call(lane['leaf']); assert status == 200
            return value
        def receive():
            try: result.append(leaf_call(lane['leaf'], data))
            finally: finished.set()
        worker = threading.Thread(target=receive); threads.append(worker); worker.start()
        assert entered.wait(2)
        raise TimeoutError('harmless transport recorder: sender timed out; receiver continues')
    service = chain(lane, transport)
    try:
        consent = prepare(lane, service)
        with patch.object(lane['producer'], 'plan', side_effect=delayed):
            try:
                assert commit(lane, service, consent)[0] == 503
                with authority_context(lane['owner'].vault, lane['owner'].state):
                    if revocation == 'organizer': lane['policy'].set_organizer(lane['actor'], False)
                    else: lane['policy'].set_machine_state('machine-a', 'disconnected')
            finally: release.set()
            assert finished.wait(3)
        for worker in threads: worker.join(2)
        assert not lane['effects'], result
        assert result[0][0] in (403,503), result
        assert service.db.execute('SELECT status FROM organizer_requests').fetchone()[0] == 'ambiguous'
        assert lane['leaf'].db.execute('SELECT status FROM executor_attempts').fetchone()[0] == 'ambiguous'
        with pytest.raises(ValueError): commit(lane, service, consent)
    finally:
        release.set()
        for worker in threads: worker.join(3)
        service.close()


@pytest.mark.parametrize('lane',['host','root'],indirect=True)
def test_unchanged_workspace_and_live_authority_still_create_once(lane):
    def transport(path, data=None, *, deadline=None):
        status, value = leaf_call(lane['leaf'], data)
        assert status == 200, value
        return value
    service = chain(lane, transport)
    try:
        consent = prepare(lane, service)
        assert commit(lane, service, consent)[0] == 200
        assert len(lane['effects']) == 1
        with pytest.raises(ValueError): commit(lane, service, consent)
    finally: service.close()


def issued(lane, *, expires=None):
    with authority_context(lane['owner'].vault, lane['owner'].state), lane['policy']._lock:
        decision=lane['policy'].authorize(lane['actor'], operation='invoke_host', machine='machine-a', executing_agent=lane['worker'])
        from dataclasses import asdict
        effect=dict(request(), request_id='a'*32, decision=asdict(decision), root_acknowledged=False)
        ticket=lane['policy']._backend.issue_effect_ticket(effect, time.time()+60 if expires is None else expires)
    return ticket,effect


def guard(lane, ticket, **changes):
    from arvyx_control.organizer_durable import delegated_effect_guard
    fields=dict(attempt='a'*32, machine='machine-a', agent='agent-a', environment='host', root_acknowledged=False)
    fields.update(changes)
    return delegated_effect_guard(lane['database'],ticket,**fields)


@pytest.mark.parametrize('mutation', ['attempt','machine','agent','environment','root_acknowledged','token','authority_id'])
def test_effect_ticket_cannot_be_rebound(lane, mutation):
    ticket,_=issued(lane)
    changes={}
    if mutation in ticket: ticket=dict(ticket,**{mutation:'b'*64})
    else: changes[mutation]=True if mutation=='root_acknowledged' else 'foreign'
    with authority_context(lane['owner'].vault, lane['owner'].state), pytest.raises(PermissionError):
        with guard(lane,ticket,**changes): pytest.fail('misbound effect admitted')


def test_effect_ticket_is_single_use_and_keeps_original_expiry(lane):
    ticket,effect=issued(lane)
    from arvyx_control.organizer_durable import validate_delegated_effect
    with authority_context(lane['owner'].vault, lane['owner'].state):
        expiry=validate_delegated_effect(lane['database'],ticket,effect)
        assert time.time()<expiry<time.time()+61
        with guard(lane,ticket) as check:
            check()
        with pytest.raises(PermissionError):
            with guard(lane,ticket): pytest.fail('replayed effect admitted')


def test_revocation_then_reenable_never_revives_unsettled_ticket(lane):
    ticket,_=issued(lane)
    with authority_context(lane['owner'].vault,lane['owner'].state):
        lane['policy'].set_organizer(lane['actor'],False)
        lane['policy'].set_organizer(lane['actor'],True)
        with pytest.raises(PermissionError):
            with guard(lane,ticket): pytest.fail('revoked ticket revived')


def test_expiry_is_checked_after_policy_lock_wait(lane):
    ticket,_=issued(lane,expires=time.time()+.15)
    entered=threading.Event(); outcome=[]
    def receive():
        with authority_context(lane['owner'].vault,lane['owner'].state):
            entered.set()
            try:
                with guard(lane,ticket): outcome.append('admitted')
            except PermissionError: outcome.append('refused')
    with authority_context(lane['owner'].vault,lane['owner'].state), lane['policy']._lock:
        worker=threading.Thread(target=receive);worker.start();assert entered.wait(1)
        time.sleep(.20)
    worker.join(2)
    assert outcome==['refused']


def test_admitted_effect_excludes_successful_revocation_until_exit(lane):
    ticket,_=issued(lane)
    started=threading.Event(); revoked=threading.Event()
    def revoke():
        with authority_context(lane['owner'].vault,lane['owner'].state):
            started.set();lane['policy'].set_machine_state('machine-a','disconnected');revoked.set()
    with authority_context(lane['owner'].vault,lane['owner'].state):
        with guard(lane,ticket) as check:
            worker=threading.Thread(target=revoke);worker.start();assert started.wait(1)
            assert not revoked.wait(.05)
            check()
        worker.join(2)
        assert revoked.is_set()


def test_remote_forwarding_cannot_replace_original_fence_or_renew_consent(lane):
    from arvyx_control.remote_delegation import RemoteDelegationEndpoint
    from arvyx_control.organizer_delegation import DelegationService
    ticket,effect=issued(lane);effect=dict(effect,delegation_fence=ticket)
    # The shared authority is explicit; there is no implied remote callback trust.
    effect['consent_expires_at']=time.time()+60
    # Issue the complete exact wire document, including original expiry.
    with authority_context(lane['owner'].vault,lane['owner'].state),lane['policy']._lock:
        effect.pop('delegation_fence')
        effect['delegation_fence']=lane['policy']._backend.issue_effect_ticket(effect,effect['consent_expires_at'])
    calls=[]
    def remote(path,data=None,*,deadline=None):
        calls.append((path,data))
        if path=='capabilities':return dict(owner_host='machine-a')
        if path=='delegations/fence':return dict(organizer_effect_fence=None)
        # This simulates the old independently reviewed remote request succeeding.
        if path=='delegations/prepare':return dict(request=data,decision=effect['decision'],consent_id='b'*32,sha256='d'*64)
        if path=='delegations/commit':return dict(id='b'*32,status='completed')
        raise AssertionError(path)
    with patch('arvyx_control.shared_onboarding_cli.client',return_value=remote):
        endpoint=RemoteDelegationEndpoint(lane['tmp']/'remote.sqlite','http://127.0.0.1:12345','fixture',machine='machine-a')
    try:
        with pytest.raises(PermissionError):endpoint.execute(effect)
        assert not [p for p,_ in calls if p in ('delegations/prepare','delegations/commit')]
    finally:endpoint.close()


def test_remote_shared_fence_forwards_exact_attempt_without_second_review(lane):
    from arvyx_control.remote_delegation import RemoteDelegationEndpoint
    leaf_service=chain(lane,lambda path,data=None,**kw:leaf_call(lane['leaf'],data)[1])
    calls=[]
    def remote(path,data=None,*,deadline=None):
        calls.append((path,data))
        if path=='capabilities':return dict(owner_host='machine-a')
        status,value=leaf_service.route(path,'GET' if data is None else 'POST',data or {})
        assert status==200,value
        return value
    with patch('arvyx_control.shared_onboarding_cli.client',return_value=remote):
        endpoint=RemoteDelegationEndpoint(lane['tmp']/'remote.sqlite','http://127.0.0.1:12345','fixture',machine='machine-a')
    from arvyx_control.organizer_delegation import DelegationService
    sender=DelegationService(lane['tmp']/'sender.sqlite',lane['policy'],lane['actor'],{('machine-a','agent-a','leaf'):endpoint})
    try:
        consent=prepare(lane,sender)
        assert commit(lane,sender,consent)[0]==200
        wire=[data for path,data in calls if path=='delegations/fenced-execute']
        assert len(wire)==1 and wire[0]['request_id']==consent['consent_id']
        assert len(lane['effects'])==1
        assert endpoint.links(consent['consent_id'])==dict(remote_id=consent['consent_id'],status='completed')
        assert not [path for path,_ in calls if path in ('delegations/prepare','delegations/commit')]
    finally:sender.close();endpoint.close();leaf_service.close()


@pytest.mark.skipif(os.environ.get('AMC_FIX5_F_HOST_TRANSPORT')!='1',reason='select parent-host loopback transport explicitly')
@pytest.mark.parametrize('revocation',['organizer','machine'])
def test_real_http_sender_timeout_keeps_late_leaf_fenced(lane,revocation):
    from arvyx_control.public_onboarding_api import make_server
    from arvyx_control.executor_endpoint import ExecutorEndpoint
    from arvyx_control.organizer_delegation import DelegationService
    entered=threading.Event();release=threading.Event();finished=threading.Event()
    original_plan=lane['producer'].plan;original_dispatch=lane['leaf'].dispatch
    def delayed(*args,**kwargs):
        value=original_plan(*args,**kwargs);entered.set();assert release.wait(2)
        return value
    def dispatch(*args,**kwargs):
        try:return original_dispatch(*args,**kwargs)
        finally:
            if args[1].endswith('/executor/execute'):finished.set()
    # Binding a socket can be denied by the sandbox. Keep that failure visible;
    # the evidence bundle supplies the exact parent-host command.
    server=make_server(lane['leaf'],port=0)
    listener=threading.Thread(target=server.serve_forever,daemon=True);listener.start()
    endpoint=ExecutorEndpoint('http://127.0.0.1:'+str(server.server_port),'x'*48,
        machine='machine-a',agent='agent-a',session='leaf',environments=['host'],timeout=.15)
    service=DelegationService(lane['tmp']/'http-requests.sqlite',lane['policy'],lane['actor'],
        {('machine-a','agent-a','leaf'):endpoint})
    try:
        consent=prepare(lane,service)
        with patch.object(lane['producer'],'plan',side_effect=delayed),patch.object(lane['leaf'],'dispatch',side_effect=dispatch):
            try:
                assert commit(lane,service,consent)[0]==503
                assert entered.is_set(),'receiver did not reach pre-admission barrier'
                with authority_context(lane['owner'].vault,lane['owner'].state):
                    if revocation=='organizer':lane['policy'].set_organizer(lane['actor'],False)
                    else:lane['policy'].set_machine_state('machine-a','disconnected')
            finally:release.set()
            assert finished.wait(2)
        assert not lane['effects']
        assert service.db.execute('SELECT status FROM organizer_requests').fetchone()[0]=='ambiguous'
        assert lane['leaf'].db.execute('SELECT status FROM executor_attempts').fetchone()[0]=='ambiguous'
        with pytest.raises(ValueError):commit(lane,service,consent)
    finally:
        release.set();server.shutdown();server.server_close();listener.join(2);service.close()


def test_batched_revoke_and_reenable_still_invalidates_old_ticket(lane):
    ticket,_=issued(lane)
    with authority_context(lane['owner'].vault,lane['owner'].state):
        with lane['policy']._lock:
            lane['policy'].set_organizer(lane['actor'],False)
            lane['policy'].set_organizer(lane['actor'],True)
        with pytest.raises(PermissionError):
            with guard(lane,ticket):pytest.fail('net unchanged policy revived revoked ticket')


def test_legacy_unpinned_leaf_cannot_silently_adopt_current_workspace(lane):
    from arvyx_control.local_executor_service import LocalExecutorService
    identity=json.loads(lane['leaf'].db.execute('SELECT document FROM executor_identity').fetchone()[0])
    identity.pop('workspace_identity')
    with lane['leaf'].db:
        lane['leaf'].db.execute('UPDATE executor_identity SET document=?',(json.dumps(identity),))
    with pytest.raises(PermissionError):
        LocalExecutorService(lane['tmp']/'leaf.sqlite',**lane['args'])


def test_workspace_replaced_after_plan_is_refused_before_create(lane):
    original=lane['producer'].plan
    def changed(*args,**kwargs):
        plan=original(*args,**kwargs)
        workspace=lane['root']/'existing';workspace.rename(lane['root']/'original');workspace.mkdir()
        return plan
    service=chain(lane,lambda path,data=None,**kw:leaf_call(lane['leaf'],data)[1])
    try:
        consent=prepare(lane,service)
        with patch.object(lane['producer'],'plan',side_effect=changed),patch.object(lane['producer'],'create') as effect:
            assert commit(lane,service,consent)[0]==503
            effect.assert_not_called()
        assert not lane['effects']
        assert lane['leaf'].db.execute('SELECT status FROM executor_attempts').fetchone()[0]=='ambiguous'
    finally:service.close()


def test_missing_or_forged_fence_cannot_use_independent_owner_lease(lane):
    raw:dict=dict(request(),request_id='f'*32,decision={},root_acknowledged=False)
    assert leaf_call(lane['leaf'],raw)[0]==400
    raw.update(delegation_fence=dict(authority_id='a'*64,token='b'*64),consent_expires_at=time.time()+60,receiving_leaf=lane['leaf'].receiving_leaf)
    assert leaf_call(lane['leaf'],raw)[0] in (403,503)
    assert not lane['effects']


def test_leaf_attempt_evidence_does_not_persist_ticket_bearer(lane):
    wire=[]
    def transport(path,data=None,**kwargs):
        if data is not None:wire.append(data)
        return leaf_call(lane['leaf'],data)[1]
    service=chain(lane,transport)
    try:
        consent=prepare(lane,service);assert commit(lane,service,consent)[0]==200
        token=wire[0]['delegation_fence']['token']
        saved=lane['leaf'].db.execute('SELECT payload FROM executor_attempts').fetchone()[0]
        assert token not in saved
        assert json.loads(saved)['delegation_fence']['token_sha256']==__import__('hashlib').sha256(token.encode()).hexdigest()
    finally:service.close()


def test_copying_policy_database_does_not_create_a_shared_revocation_fence(lane):
    import shutil
    from arvyx_control.organizer_durable import validate_delegated_effect
    ticket,effect=issued(lane)
    copied=lane['tmp']/'copied-policy.sqlite';shutil.copy2(lane['database'],copied)
    with authority_context(lane['owner'].vault,lane['owner'].state),pytest.raises(PermissionError):
        validate_delegated_effect(copied,ticket,effect)


def test_absent_capability_cannot_match_a_null_fence(lane):
    from arvyx_control.executor_endpoint import ExecutorEndpoint
    calls=[]
    def transport(path,data=None,**kwargs):
        calls.append(path)
        if path=='capabilities':return dict(machine='machine-a',agent='agent-a',session='leaf',environments=['host'],receiving_leaf='a'*64)
        return dict(request_id='a'*32,status='completed',reference='harmless-recorder')
    endpoint=ExecutorEndpoint('http://127.0.0.1:12345','fixture',machine='machine-a',agent='agent-a',session='leaf',environments=['host'])
    endpoint._call=transport
    plan=dict(request(),request_id='a'*32,root_acknowledged=False,decision={},delegation_fence=dict(authority_id=None,token=None),consent_expires_at=time.time()+60,receiving_leaf='a'*64)
    with pytest.raises(PermissionError):endpoint.execute(plan)
    assert calls==['capabilities']


def test_remote_absent_capability_cannot_match_a_null_fence(lane):
    from arvyx_control.remote_delegation import RemoteDelegationEndpoint
    calls=[]
    def transport(path,data=None,**kwargs):
        calls.append(path)
        if path=='capabilities':return dict(owner_host='machine-a')
        if path=='delegations/fence':return {}
        return dict(id='a'*32,status='completed')
    with patch('arvyx_control.shared_onboarding_cli.client',return_value=transport):
        endpoint=RemoteDelegationEndpoint(lane['tmp']/'null-remote.sqlite','http://127.0.0.1:12345','fixture',machine='machine-a')
    plan=dict(request(),request_id='a'*32,root_acknowledged=False,decision={},delegation_fence=dict(authority_id=None,token=None),consent_expires_at=time.time()+60)
    try:
        with pytest.raises(PermissionError):endpoint.execute(plan)
        assert 'delegations/fenced-execute' not in calls
    finally:endpoint.close()
