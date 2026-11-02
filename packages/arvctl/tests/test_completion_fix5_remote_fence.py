"""Distinct durable authorities and real owner admission; synthetic process recorders."""
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path
import importlib.util
import json
import os
import secrets
import threading
import time
from unittest.mock import patch
import pytest
from test_completion_fix5_F import lane, journey, services, request, leaf_call
from arvyx_control.organizer_authority import OrganizerAuthority
from arvyx_control.organizer_delegation import DelegationService
from arvyx_control.executor_endpoint import ExecutorEndpoint
from arvyx_control.remote_delegation import RemoteDelegationEndpoint
from arvyx_control.replica_authority import authority_context


def test_verified_transport_uses_the_same_pinned_ca_bytes(remote):
    """TLS factory/connection recorder; no socket or certificate acceptance."""
    from arvyx_control.remote_effect_fence import RemoteFenceClient
    from contextlib import contextmanager
    from types import SimpleNamespace
    f=remote['fence'];lane=remote['lane'];ca=lane['tmp']/'synthetic-ca.der';ca.write_bytes(b'SYNTHETIC-CA-BYTES')
    import http.client, io
    class SocketRecorder:
        def makefile(self, *args):return io.BytesIO(b'HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}')
    response=http.client.HTTPResponse(SocketRecorder(),method='POST');response.begin()
    context=object();connection=SimpleNamespace(request=lambda *a,**k:None,getresponse=lambda:response)
    @contextmanager
    def bounded(*args):yield
    with patch('ssl.create_default_context',return_value=context) as create,patch('http.client.HTTPSConnection',return_value=connection) as connect,patch('arvyx_control.http_bounds.bounded_connection',bounded):
        client=RemoteFenceClient(lane['tmp']/'tls-recorder.sqlite',origin='https://synthetic-coordinator.invalid',authority_id=f.authority_id,
            receiver_id=f.receiver_id,key=f.key,binding=f.binding,authority_database=f.authority_database,
            organizer=f.organizer,local_organizer=f.local_organizer,ca_file=ca)
        try:
            create.assert_called_once_with(cadata=b'SYNTHETIC-CA-BYTES')
            ca.write_bytes(b'REPLACEMENT-SYNTHETIC-CA')
            assert client._exchange({})==(401,{})
            assert create.call_count==1 and connect.call_args.kwargs['context'] is context
        finally:client.close()


@pytest.fixture(autouse=True)
def fence_authority(lane):
    with authority_context(lane['owner'].vault,lane['owner'].state):
        yield


@pytest.fixture
def remote(lane):
    """Receiver policy is lane.policy; sender/coordinator has a separate DB."""
    from arvyx_control.organizer_durable import authority_fence_identity
    with authority_context(lane['owner'].vault,lane['owner'].state):
        source=OrganizerAuthority(database=lane['tmp']/'source-policy.sqlite')
        actor=source.provision_identity('organizer',kind='internal',organizer=True)
        worker=source.provision_identity('agent-a',kind='internal')
        source.enroll_machine('machine-a');source.bind_agent(worker,machine='machine-a',root=True)
        source.bind_executor(worker,machine='machine-a',environments=['host'])
        authority=authority_fence_identity(source._backend.path)
    assert source._backend.path!=lane['policy']._backend.path
    assert source._backend.path.stat().st_ino!=lane['policy']._backend.path.stat().st_ino
    receiver=None;coordinator=None;fence=None
    receiver_binding=None
    if importlib.util.find_spec('arvyx_control.remote_effect_fence') is not None:
        from arvyx_control.remote_effect_fence import RemoteFenceClient,RemoteFenceService
        binding=dict(receiver_id='receiver-a',incarnation=lane['owner'].incarnation,epoch=1,
            target=lane['target'],session='leaf',workspace_identity=lane['leaf'].workspace_identity,
            environments=[lane['mode']],policy_id=lane['leaf'].authority_id)
        binding['epoch']=lane['owner'].native_lifecycle(action='inspect',actor='operator')['epoch']
        receiver_binding=binding
        key=secrets.token_hex(32)
        coordinator=RemoteFenceService(source,{'receiver-a':dict(key=key,binding=binding,organizer='organizer')})
        fence=RemoteFenceClient(lane['tmp']/'remote-owner.sqlite',origin='http://127.0.0.1:12347',authority_id=authority,
            receiver_id='receiver-a',key=key,binding=binding,authority_database=lane['database'],organizer='organizer',local_organizer='organizer',fixture_http=True)
        fence._exchange=lambda envelope:coordinator.handle(envelope)
        lane['owner'].delegation_remote_fence=fence
        # Explicitly provision a fresh leaf lease for this exact remote trust configuration.
        lane['leaf'].close()
        from arvyx_control.local_executor_service import LocalExecutorService
        args=dict(lane['args'],remote_fence=fence)
        lane['leaf']=LocalExecutorService(lane['tmp']/'remote-leaf.sqlite',**args)
        original_close=lane['leaf'].close
        # lane teardown closes its originally constructed instance; close is idempotent in SQLite.
    leaf=ExecutorEndpoint('http://127.0.0.1:12346','x'*48,machine='machine-a',agent='agent-a',session='leaf',environments=[lane['mode']])
    leaf._call=lambda path,data=None,**kw:_value(leaf_call(lane['leaf'],data))
    options={} if fence is None else dict(remote_fence=fence)
    receiver=DelegationService(lane['tmp']/'receiver-attempts.sqlite',lane['policy'],lane['actor'],{('machine-a','agent-a','leaf'):leaf},**options)
    def forward(path,data=None,**kw):
        if path=='capabilities':return dict(owner_host='machine-a')
        with authority_context(lane['owner'].vault,lane['owner'].state):return _value(receiver.route(path,'GET' if data is None else 'POST',data or {}))
    with patch('arvyx_control.shared_onboarding_cli.client',return_value=forward):
        options={} if fence is None else dict(receiver_binding=receiver_binding,coordinator_id=authority,environments=[lane['mode']])
        endpoint=RemoteDelegationEndpoint(lane['tmp']/'forward.sqlite','http://127.0.0.1:12345','fixture',machine='machine-a',**options)
    sender=DelegationService(lane['tmp']/'sender-attempts.sqlite',source,actor,{('machine-a','agent-a','leaf'):endpoint})
    value=dict(lane=lane,source=source,actor=actor,sender=sender,receiver=receiver,endpoint=endpoint,fence=fence,coordinator=coordinator,binding=receiver_binding)
    http_servers=[];http_threads=[];http_api=None
    if os.environ.get('AMC_FIX5_REMOTE_HOST_HTTP')=='1':
        from arvyx_control.remote_effect_fence import make_server as fence_server
        from arvyx_control.local_onboarding import local_composition
        from arvyx_control.public_onboarding_api import make_server as onboarding_server
        from arvyx_control.shared_onboarding_cli import client
        original=coordinator.handle
        def authenticated(envelope):
            with authority_context(lane['owner'].vault,lane['owner'].state):return original(envelope)
        coordinator.handle=authenticated
        server=fence_server(coordinator,origin='http://127.0.0.1:0',fixture_http=True)
        # The original fixture client store was provisioned for the recorder
        # origin. A fresh, explicitly provisioned HTTP client store pins this
        # actual disposable origin; it never rebinds the recorder database.
        http_options=dict(origin='http://127.0.0.1:'+str(server.server_port),authority_id=fence.authority_id,
            receiver_id=fence.receiver_id,key=fence.key,binding=fence.binding,authority_database=fence.authority_database,
            organizer=fence.organizer,local_organizer=fence.local_organizer,fixture_http=True)
        http_fence=RemoteFenceClient(lane['tmp']/'http-remote-owner.sqlite',**http_options)
        lane['owner'].delegation_remote_fence=http_fence;receiver.remote_fence=http_fence
        lane['leaf'].close();lane['leaf']=LocalExecutorService(lane['tmp']/'http-leaf.sqlite',**dict(lane['args'],remote_fence=http_fence))
        value['fence']=http_fence
        directory=lane['tmp']/'matrix-http';directory.mkdir(mode=0o700)
        http_api=local_composition(directory,vault=lane['owner'].vault,machine_id='machine-a',capability='synthetic-http-matrix')
        http_api.owners['local-owner'].extension.state=lane['owner'].state
        http_api.owners['local-owner'].extension.delegations=receiver
        receiving=onboarding_server(http_api)
        endpoint.call=client('http://127.0.0.1:'+str(receiving.server_port),'synthetic-http-matrix',timeout=2)
        http_servers=[server,receiving]
        http_threads=[threading.Thread(target=server.serve_forever,daemon=True) for server in http_servers]
        for thread in http_threads:thread.start()
    try:yield value
    finally:
        for server in http_servers:server.shutdown();server.server_close()
        for thread in http_threads:thread.join(3)
        if http_api is not None:http_api.close();value['fence'].close()

        sender.close();receiver.close();endpoint.close();source.close()
        if fence is not None:fence.close();lane['leaf'].close()


def _value(result):
    status,value=result
    if status>=300:raise PermissionError(value)
    return value


def prepare(remote):
    lane=remote['lane']
    with authority_context(lane['owner'].vault,lane['owner'].state):
        review=remote['sender'].route('delegations/prepare','POST',request(lane['mode']))[1]
    return dict(consent_id=review['consent_id'],consent_sha256=review['sha256'],confirmed=True,root_acknowledged=lane['mode']=='root')


def commit(remote,consent):
    lane=remote['lane']
    with authority_context(lane['owner'].vault,lane['owner'].state):return remote['sender'].route('delegations/commit','POST',consent)


def test_independent_host_original_review_reaches_exact_owner(remote):
    consent=prepare(remote);status,result=commit(remote,consent)
    assert status==200,result
    assert len(remote['lane']['effects'])==1
    assert remote['sender'].db.execute('SELECT id,expires FROM organizer_requests').fetchone()==remote['receiver'].db.execute('SELECT id,expires FROM organizer_requests').fetchone()
    with pytest.raises(ValueError):commit(remote,consent)


@pytest.mark.parametrize('lane',['host','root'],indirect=True)
def test_independent_host_preserves_original_mode_root_ack_and_actor(remote):
    consent=prepare(remote);assert commit(remote,consent)[0]==200
    source=remote['source']._backend.db
    record=json.loads(source.execute('SELECT record FROM organizer_effect_tickets').fetchone()[0])
    assert record['request_id']==consent['consent_id']
    assert record['environment']==remote['lane']['mode']
    assert record['root_acknowledged'] is (remote['lane']['mode']=='root')
    assert record['decision']['initiating_organizer']=='organizer'


@pytest.mark.parametrize('revocation',['organizer','machine'])
def test_sender_timeout_then_revocation_excludes_late_first_effect(remote,revocation):
    lane=remote['lane'];entered=threading.Event();release=threading.Event();done=threading.Event();results=[];threads=[]
    original_plan=lane['producer'].plan;forward=remote['endpoint'].call
    def delayed(*args,**kw):
        result=original_plan(*args,**kw);entered.set();assert release.wait(5);return result
    def timeout(path,data=None,**kw):
        if path!='delegations/fenced-execute':return forward(path,data,**kw)
        def receive():
            try:results.append(forward(path,data,**kw))
            except Exception as exc:results.append(type(exc).__name__)
            finally:done.set()
        thread=threading.Thread(target=receive);threads.append(thread);thread.start();assert entered.wait(3)
        raise TimeoutError('synthetic sender deadline; receiver continues')
    remote['endpoint'].call=timeout;consent=prepare(remote)
    try:
        with patch.object(lane['producer'],'plan',side_effect=delayed):
            assert commit(remote,consent)[0]==503
            if revocation=='organizer':remote['source'].set_organizer(remote['actor'],False)
            else:remote['source'].set_machine_state('machine-a','disconnected')
            release.set();assert done.wait(5)
        assert lane['effects']==[],results
        assert remote['sender'].db.execute('SELECT status FROM organizer_requests').fetchone()[0]=='ambiguous'
        with pytest.raises(ValueError):commit(remote,consent)
    finally:
        release.set()
        for thread in threads:thread.join(5)


@pytest.mark.parametrize('revocation',['organizer','machine'])
def test_admitted_effect_requires_authenticated_settlement_before_revocation(remote,revocation):
    from arvyx_control.remote_effect_fence import RemoteEffectUnsettled
    lane=remote['lane'];entered=threading.Event();release=threading.Event();result=[]
    def process(sid,**kw):
        with kw['effect_guard']() as check:
            kw['admission']();check();lane['effects'].append(sid);entered.set();assert release.wait(5)
            lane['owner'].db.execute("UPDATE sessions SET status='running',pid=12345 WHERE id=?",(sid,));lane['owner'].db.commit()
            lane['owner'].live[sid]=dict(fd=1,attached=False,process_generation='synthetic-'+sid)
    consent=prepare(remote)
    def send():result.append(commit(remote,consent))
    with patch.object(lane['owner'],'_start',side_effect=process):
        thread=threading.Thread(target=send);thread.start()
        try:
            assert entered.wait(4)
            # A new source handle sees the same durable unsettled permit.
            reopened=OrganizerAuthority(database=remote['source']._backend.path)
            try:
                with pytest.raises(RemoteEffectUnsettled):
                    if revocation=='organizer':reopened.set_organizer(reopened.identity_handle('organizer'),False)
                    else:reopened.set_machine_state('machine-a','disconnected')
                # Even a deadline/lease far past the original expiry cannot release it.
                with patch('time.time',return_value=time.time()+100000),pytest.raises(RemoteEffectUnsettled):
                    reopened.set_machine_state('machine-a','disconnected')
            finally:reopened.close()
        finally:release.set();thread.join(6)
    assert result[0][0]==200,result
    if revocation=='organizer':remote['source'].set_organizer(remote['actor'],False)
    else:remote['source'].set_machine_state('machine-a','disconnected')
    assert len(lane['effects'])==1


@pytest.mark.parametrize('lost',['acquire','settle'])
def test_lost_permit_or_ack_remains_durable_and_cannot_replay(remote,lost):
    from arvyx_control.remote_effect_fence import RemoteEffectUnsettled,RemoteFenceClient
    lane=remote['lane'];fence=remote['fence'];exchange=fence._exchange
    def lose(envelope):
        value=exchange(envelope)
        if envelope['message']['operation']==lost:raise TimeoutError('synthetic authenticated response lost')
        return value
    fence._exchange=lose;consent=prepare(remote);assert commit(remote,consent)[0]==503
    assert len(lane['effects'])==(1 if lost=='settle' else 0)
    row=fence.db.execute('SELECT permit_id,record,status FROM remote_owner_permits').fetchone();assert row[2]=='uncertain'
    path=Path(fence.db.execute('PRAGMA database_list').fetchone()[2])
    reopened=RemoteFenceClient(path,origin=fence.origin,authority_id=fence.authority_id,receiver_id=fence.receiver_id,
        key=fence.key,binding=fence.binding,authority_database=fence.authority_database,organizer=fence.organizer,local_organizer=fence.local_organizer,fixture_http=True)
    try:
        assert reopened.db.execute('SELECT status FROM remote_owner_permits').fetchone()[0]=='uncertain'
        if lost=='acquire':
            with pytest.raises(RemoteEffectUnsettled):remote['source'].set_organizer(remote['actor'],False)
        else:remote['source'].set_organizer(remote['actor'],False)
        with pytest.raises(ValueError):commit(remote,consent)
    finally:reopened.close();fence._exchange=exchange


@pytest.mark.parametrize('fault',['wrong-request-auth','wrong-response-auth','receiver-incarnation'])
def test_independent_transport_and_owner_identity_fail_closed(remote,fault):
    fence=remote['fence'];original=fence._exchange
    def altered(envelope):
        if fault=='wrong-request-auth':envelope=dict(envelope,mac='0'*64)
        status,value=original(envelope)
        if fault=='wrong-response-auth':value=dict(value,mac='0'*64)
        return status,value
    consent=prepare(remote)
    if fault=='receiver-incarnation':remote['lane']['owner'].incarnation='b'*32
    else:fence._exchange=altered
    if fault=='receiver-incarnation':
        # Capability preflight now detects stale receiver identity before admission.
        # Over the opt-in real HTTP hop the receiver's refusal arrives as its
        # exact 403 status rather than the in-process recorder's PermissionError.
        if os.environ.get('AMC_FIX5_REMOTE_HOST_HTTP')=='1':
            from urllib.error import HTTPError
            with pytest.raises(HTTPError) as refused:commit(remote,consent)
            assert refused.value.code==403
        else:
            with pytest.raises(PermissionError):commit(remote,consent)
    else:assert commit(remote,consent)[0]==503
    assert not remote['lane']['effects']


def test_authenticated_request_replay_is_refused(remote):
    from arvyx_control.remote_effect_fence import _mac,PROTOCOL
    message=dict(protocol=PROTOCOL,authority_id=remote['fence'].authority_id,receiver_id='receiver-a',nonce='a'*32,operation='status',payload=dict(permit_id='b'*32,sha256='c'*64))
    envelope=dict(message=message,mac=_mac(remote['fence'].key,message))
    assert remote['fence']._exchange(envelope)[0]==200
    assert remote['fence']._exchange(envelope)[0]==403
    assert remote['source']._backend.db.execute('SELECT COUNT(*) FROM organizer_remote_nonces WHERE nonce=?',('a'*32,)).fetchone()[0]==1


def test_wait_beyond_original_expiry_does_not_renew_approval(remote):
    lane=remote['lane'];clock=[time.time()];original=lane['producer'].plan
    def delayed(*args,**kw):
        result=original(*args,**kw);clock[0]+=1000;return result
    consent=prepare(remote)
    with patch('time.time',side_effect=lambda:clock[0]),patch.object(lane['producer'],'plan',side_effect=delayed):
        assert commit(remote,consent)[0]==503
    assert not lane['effects']


@pytest.mark.parametrize('lane',['host','root'],indirect=True)
def test_independent_receiver_policy_still_controls_execution(remote):
    lane=remote['lane'];consent=prepare(remote)
    if lane['mode']=='root':lane['policy'].bind_agent(lane['worker'],machine='machine-a',root=False)
    else:lane['policy'].bind_executor(lane['worker'],machine='machine-a',environments=[])
    assert commit(remote,consent)[0]==503
    assert not lane['effects']


def test_production_transport_requires_verified_tls_and_explicit_trust(remote):
    from arvyx_control.remote_effect_fence import RemoteFenceClient
    f=remote['fence']
    options=dict(origin=f.origin,authority_id=f.authority_id,receiver_id=f.receiver_id,key=f.key,binding=f.binding,
        authority_database=f.authority_database,organizer=f.organizer,local_organizer=f.local_organizer)
    with pytest.raises(ValueError,match='HTTPS'):RemoteFenceClient(remote['lane']['tmp']/'invalid.sqlite',**options)
    with pytest.raises(ValueError,match='loopback'):RemoteFenceClient(remote['lane']['tmp']/'invalid.sqlite',**dict(options,origin='http://example.com:1234'),fixture_http=True)


@pytest.mark.parametrize('revocation',['organizer','machine'])
@pytest.mark.skipif(os.environ.get('AMC_FIX5_REMOTE_HOST_HTTP')!='1',reason='parent-host disposable sockets only')
def test_real_http_independent_sender_timeout_and_revocation(remote,revocation):
    """Real coordinator + receiving API sockets, no fork/provider or native input."""
    from arvyx_control.remote_effect_fence import make_server
    from arvyx_control.public_onboarding_api import make_server as api_server
    from arvyx_control.local_onboarding import local_composition
    from arvyx_control.shared_onboarding_cli import client
    lane=remote['lane'];context=(lane['owner'].vault,lane['owner'].state);handler=remote['coordinator'].handle
    def authenticated(envelope):
        with authority_context(*context):return handler(envelope)
    remote['coordinator'].handle=authenticated
    coordinator=make_server(remote['coordinator'],origin='http://127.0.0.1:0',fixture_http=True)
    remote['fence'].origin='http://127.0.0.1:'+str(coordinator.server_port)
    # Use the actual transport method rather than the pure-handler recorder.
    remote['fence']._exchange=type(remote['fence'])._exchange.__get__(remote['fence'])
    directory=lane['tmp']/'http-receiver';directory.mkdir(mode=0o700)
    api=local_composition(directory,vault=lane['owner'].vault,machine_id='machine-a',capability='synthetic-receiver')
    api.owners['local-owner'].extension.state=lane['owner'].state
    api.owners['local-owner'].extension.delegations=remote['receiver']
    server=api_server(api)
    threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (coordinator,server)]
    for t in threads:t.start()
    original_dispatch=api.dispatch;finished=threading.Event()
    def dispatch(method,path,authorization,body):
        try:return original_dispatch(method,path,authorization,body)
        finally:
            if path.endswith('delegations/fenced-execute'):finished.set()
    api.dispatch=dispatch
    remote['endpoint'].call=client('http://127.0.0.1:'+str(server.server_port),'synthetic-receiver',timeout=.15)
    entered=threading.Event();release=threading.Event();done=threading.Event();original=lane['producer'].plan
    def delayed(*args,**kw):
        value=original(*args,**kw);entered.set();assert release.wait(6);done.set();return value
    try:
        consent=prepare(remote)
        with patch.object(lane['producer'],'plan',side_effect=delayed):
            assert commit(remote,consent)[0]==503
            assert entered.is_set()
            if revocation=='organizer':remote['source'].set_organizer(remote['actor'],False)
            else:remote['source'].set_machine_state('machine-a','disconnected')
            release.set();assert done.wait(5);assert finished.wait(5)
        # Join all bounded in-flight handlers before reading recorded effects.
        server.shutdown();server.server_close()
        assert not lane['effects']
    finally:
        release.set()
        for s in (coordinator,server):s.shutdown();s.server_close()
        for t in threads:t.join(3)
        api.close()


@pytest.mark.skipif(os.environ.get('AMC_FIX5_REMOTE_HOST_HTTP')!='1',reason='parent-host disposable sockets only')
def test_real_http_admitted_permit_refuses_revocation_until_ack(remote):
    from arvyx_control.remote_effect_fence import make_server,RemoteEffectUnsettled
    lane=remote['lane'];original=remote['coordinator'].handle
    def authenticated(envelope):
        with authority_context(lane['owner'].vault,lane['owner'].state):return original(envelope)
    remote['coordinator'].handle=authenticated
    server=make_server(remote['coordinator'],origin='http://127.0.0.1:0',fixture_http=True)
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    remote['fence'].origin='http://127.0.0.1:'+str(server.server_port)
    remote['fence']._exchange=type(remote['fence'])._exchange.__get__(remote['fence'])
    entered=threading.Event();release=threading.Event();results=[]
    def process(sid,**kw):
        with kw['effect_guard']() as check:
            kw['admission']();check();lane['effects'].append(sid);entered.set();assert release.wait(5)
            lane['owner'].db.execute("UPDATE sessions SET status='running',pid=12345 WHERE id=?",(sid,));lane['owner'].db.commit()
            lane['owner'].live[sid]=dict(fd=1,attached=False,process_generation='synthetic-'+sid)
    consent=prepare(remote)
    with patch.object(lane['owner'],'_start',side_effect=process):
        sender=threading.Thread(target=lambda:results.append(commit(remote,consent)));sender.start()
        try:
            assert entered.wait(4)
            with pytest.raises(RemoteEffectUnsettled):remote['source'].set_organizer(remote['actor'],False)
        finally:release.set();sender.join(6);server.shutdown();server.server_close();worker.join(3)
    assert results[0][0]==200 and len(lane['effects'])==1
    remote['source'].set_organizer(remote['actor'],False)


@pytest.mark.parametrize('delivered',[False,True])
def test_authenticated_reconciliation_cancels_lost_acquire_without_replay(remote,delivered):
    from arvyx_control.remote_effect_fence import digest,RemoteEffectUnsettled
    fence=remote['fence'];original=fence._exchange;captured=[]
    def lost(envelope):
        if envelope['message']['operation']=='acquire':
            captured.append(envelope)
            if delivered:original(envelope)
            raise TimeoutError('synthetic lost acquire')
        return original(envelope)
    fence._exchange=lost;consent=prepare(remote);assert commit(remote,consent)[0]==503
    assert not remote['lane']['effects']
    row=fence.db.execute('SELECT record FROM remote_owner_permits').fetchone();record=json.loads(row[0]);sha=digest(record)
    fence._exchange=original
    assert fence.call('status',dict(permit_id=captured[0]['message']['payload']['permit_id'],sha256=sha))['status'] in ('unsettled','not-observed-uncertain')
    fence.reconcile(consent['consent_id'],expected_sha256=sha,outcome='no-effect-proven',evidence_sha256=digest(dict(synthetic_no_process=True,attempt=consent['consent_id'])),confirmed=True)
    remote['source'].set_organizer(remote['actor'],False)
    # Even a previously undelivered authenticated acquire can no longer arrive.
    assert remote['fence']._exchange(captured[0])[0]==403
    with pytest.raises(ValueError):commit(remote,consent)
    assert not remote['lane']['effects']


def test_private_owner_and_onboarding_factories_route_real_trust(remote):
    from arvyx_control.remote_effect_fence import private_config
    from arvyx_control.local_onboarding import local_composition
    lane=remote['lane'];f=remote['fence'];owner=lane['owner']
    fields=dict(database=Path(f.db.execute('PRAGMA database_list').fetchone()[2]),origin=f.origin,authority_id=f.authority_id,receiver_id=f.receiver_id,key=f.key,binding=f.binding,
        authority_database=f.authority_database,organizer=f.organizer,local_organizer=f.local_organizer,fixture_http=True,ca_file=None)
    path=lane['tmp']/'owner-trust.json';path.write_text(json.dumps(fields,default=str));path.chmod(0o600)
    previous=owner.delegation_remote_fence;owner.delegation_remote_fence=None
    try:
        expected=owner.native_lifecycle(action='inspect',actor='operator')
        assert owner.configure_remote_delegation(path,actor='operator',expected=expected,confirmed=True)['configured'] is True
        assert owner.delegation_remote_fence.configuration_sha256==f.configuration_sha256
        with pytest.raises(PermissionError):owner.configure_remote_delegation(path,actor='operator',expected=expected,confirmed=True)
    finally:
        if owner.delegation_remote_fence is not None:owner.delegation_remote_fence.close()
        owner.delegation_remote_fence=previous
    runtime=lane['tmp']/'runtime-config.json'
    runtime.write_text(json.dumps(dict(database=str(lane['tmp']/'configured-requests.sqlite'),authority_database=str(remote['source']._backend.path),organizer='organizer',remote_fence_config=None,
        endpoints=[dict(kind='remote',machine='machine-a',agent='agent-a',session='leaf',configuration=dict(database=str(lane['tmp']/'configured-links.sqlite'),origin='http://127.0.0.1:12345',credential='synthetic-only',receiver_binding=f.binding,coordinator_id=f.authority_id,environments=[lane['mode']]))])))
    runtime.chmod(0o600);directory=lane['tmp']/'configured-onboarding';directory.mkdir(mode=0o700)
    api=local_composition(directory,vault=owner.vault,machine_id='source-host',capability='synthetic-configured',delegation_config=runtime)
    try:
        status,value=api.dispatch('GET','/api/public-onboarding/capabilities','Bearer synthetic-configured',{})
        assert status==200 and value['delegation_targets'][0]['machine']=='machine-a'
        assert api.dispatch('POST','/api/public-onboarding/configure_remote_delegation','Bearer synthetic-configured',{'config':str(path)})[0]==404
    finally:api.close()


def test_original_review_pins_remote_workspace_and_owner_incarnation(remote):
    consent=prepare(remote)
    remote['endpoint'].receiver_binding=dict(remote['endpoint'].receiver_binding,epoch=remote['binding']['epoch']+1)
    with pytest.raises(ValueError,match='connection changed'):commit(remote,consent)
    assert not remote['lane']['effects']
