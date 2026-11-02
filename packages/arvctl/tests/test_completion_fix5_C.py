"""Lane C bounded regressions; disposable metadata and process recorders only."""
import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from arvyx_control import cockpit_archive as archive
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_native_runtime import NativeRuntime
from arvyx_control.replica_authority import authority_context
from test_sol24_archive import owner_at
from test_sol27_archive_pem import native_owner
from test_local_onboarding_services import services


BAD_ENDINGS = ['ENéD RSA PRIVATE KEY', 'END RéSA PRIVATE KEY',
               'END RSA PRIV界ATE KEY', 'END RSA PRIVATE KE🙂Y']


def delivery_bytes(owner):
    owner.host = 'fixture-host'
    owner._get = lambda sid: dict(id=sid, project='fixture', task='task', kind='work')
    registry = owner.vault / 'registry/projects'
    registry.mkdir(parents=True, exist_ok=True)
    (registry / 'fixture.json').write_text(json.dumps(dict(owner_agent_id='fixture-agent')))
    received = []
    def sink(row):
        received.append(json.dumps(archive.capture_delivery_payload(owner, row)).encode())
        return row['event_id']
    archive.sync_capture(owner, sink)
    return b''.join(received)


@pytest.mark.parametrize('ending', BAD_ENDINGS)
@pytest.mark.parametrize('fragmented', [False, True])
def test_unicode_workcapture_split_and_reopen_never_delivers_body(tmp_path, ending, fragmented):
    db = tmp_path / 'capture.db'
    owner = owner_at(db)
    recorder = archive.WorkCapture(owner, 's')
    raw = ('BEGIN RSA PRIVATE KEY\n' + ending + '\n').encode()
    for part in ([bytes([b]) for b in raw] if fragmented else [raw]):
        recorder.feed(part)
    recorder.finish()
    owner.db.close()
    owner = owner_at(db)
    try:
        recorder = archive.WorkCapture(owner, 's')
        recorder.feed(b'LATER_PRIVATE_BODY\n');recorder.finish()
        stored=str(archive.pending_capture(owner));delivered=delivery_bytes(owner)
        assert 'LATER_PRIVATE_BODY' not in stored
        assert b'LATER_PRIVATE_BODY' not in delivered
    finally:owner.db.close()


@pytest.mark.parametrize('ending', BAD_ENDINGS)
def test_unicode_native_import_actual_sql_page_reopen_delivery(tmp_path, ending):
    store = tmp_path / 'state.db'
    with sqlite3.connect(store) as db:
        db.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY,session_id TEXT,role TEXT,content TEXT)')
        db.executemany('INSERT INTO messages VALUES(?,?,?,?)',
            [(i,'conversation','assistant','safe') for i in range(1,99)] +
            [(99,'conversation','assistant','BEGIN RSA PRIVATE KEY'),
             (100,'conversation','assistant',ending),
             (101,'conversation','assistant','LATER_PRIVATE_BODY')])
    path = tmp_path / 'archive.db';owner = native_owner(path, store)
    assert LocalCockpit.native_archive(owner, 's', actor='operator')['cursor'] == 100
    owner.db.close();owner = native_owner(path, store)
    try:
        result = LocalCockpit.native_archive(owner, 's', actor='operator')
        assert result['cursor'] == 101 and not result['has_more']
        stored=str(archive.pending_capture(owner));delivered=delivery_bytes(owner)
        assert 'LATER_PRIVATE_BODY' not in stored
        assert b'LATER_PRIVATE_BODY' not in delivered
    finally:owner.db.close()


@pytest.fixture
def launch_owner(tmp_path):
    from arvyx_control import cockpit_client, control
    from arvyx_control.local_executor import ExecutionPolicy
    root = tmp_path / 'pilot';cockpit_client.initialize(root)
    owner = LocalCockpit(root/'runtime',root/'vault',root/'events.jsonl','fixture-host',
        execution_policy=ExecutionPolicy(host_uid=os.geteuid(),allow_host=True))
    with authority_context(owner.vault,owner.state):
        task=control.create_task(owner.state,'synthetic',owner='demobot').task
    sid=owner.open(project='demo-agent',task=task.id,name='synthetic',actor='operator')['id']
    yield owner,sid
    owner.close()


@pytest.mark.parametrize('cwd_mode', ['mismatch', 'missing'])
def test_gemini_requires_recorded_exact_workspace_before_start(launch_owner, tmp_path, cwd_mode):
    owner,sid=launch_owner
    home=tmp_path/'native';home.mkdir()
    workspace=Path(owner._get(sid)['workspace']);other=tmp_path/'other';other.mkdir()
    store=home/'metadata.json';store.write_text(json.dumps(dict(sessionId='exact',cwd=str(workspace))))
    runtime=NativeRuntime(tool='gemini',executable='/usr/bin/python3',home=home,store=store)
    assert runtime.plan('exact',workspace)[0][-1]=='exact'
    store.write_text(json.dumps(dict(sessionId='exact',**({} if cwd_mode=='missing' else dict(cwd=str(other))))))
    owner.native_runtimes['gemini']=runtime
    # Seed an already-bound legacy owner row, then exercise real start admission.
    with owner.db:owner.db.execute('INSERT INTO native_bindings VALUES(?,?,?)',(sid,'gemini','exact'))
    with patch.object(owner,'_start') as boundary:
        with pytest.raises(ValueError,match='workspace'):
            owner.start_native(sid,actor='operator',allow_provider=True,environment='host')
        boundary.assert_not_called()


def test_reservation_rejection_creates_no_phantom_capture(launch_owner):
    owner,sid=launch_owner
    runtime=SimpleNamespace(reserve=lambda conversation: (_ for _ in ()).throw(ValueError('already reserved')))
    owner.native_runtimes['gemini']=runtime
    with owner.db:owner.db.execute('INSERT INTO native_bindings VALUES(?,?,?)',(sid,'gemini','exact'))
    before=archive.capture_status(owner)
    with patch('pty.fork') as fork:
        for _ in range(3):
            with pytest.raises(ValueError,match='reserved'):
                owner._start(sid,actor='operator',argv=['/never-executed'],expected_native=owner.native(sid,actor='operator'))
        fork.assert_not_called()
    after=archive.capture_status(owner)
    assert after['open_runs']==before['open_runs']==0
    assert after['used_bytes']==before['used_bytes']
    assert owner.db.execute('SELECT count(*) FROM capture_runs').fetchone()[0]==0
    owner.close()
    reopened=LocalCockpit(owner.root,owner.vault,owner.state,owner.host,native_runtimes=owner.native_runtimes)
    try:
        assert archive.capture_status(reopened)['interrupted_runs']==0
        assert archive.capture_status(reopened)['used_bytes']==before['used_bytes']
    finally:reopened.close()


def test_known_no_child_pipe_and_fork_failures_are_aborted_and_charged(launch_owner):
    owner,sid=launch_owner
    with patch('os.pipe2',side_effect=OSError('synthetic pipe failure')),patch('pty.fork') as fork:
        with pytest.raises(OSError,match='pipe failure'):owner.start(sid,actor='operator',environment='host')
        fork.assert_not_called()
    assert archive.capture_status(owner)['interrupted_runs']==0
    assert owner.db.execute('SELECT status FROM capture_runs').fetchone()[0]=='aborted-before-process'
    charged=archive.capture_status(owner)['used_bytes'];assert charged>512
    with patch('pty.fork',side_effect=OSError('synthetic fork failure')) as fork:
        with pytest.raises(OSError,match='fork failure'):owner.start(sid,actor='operator',environment='host')
        assert fork.call_count==1
    assert archive.capture_status(owner)['interrupted_runs']==0
    assert [r[0] for r in owner.db.execute('SELECT status FROM capture_runs')]==['aborted-before-process','aborted-before-process']
    assert archive.capture_status(owner)['used_bytes']>charged


def test_rev0534_no_child_fork_oserror_is_aborted_released_and_reopens_consistently(launch_owner):
    """REV-0534: pty.fork OSError (no child) leaves aborted, not interrupted."""
    from unittest.mock import Mock
    owner,sid=launch_owner
    reservation=Mock()
    owner.native_runtimes['gemini']=SimpleNamespace(reserve=lambda conversation:reservation)
    with owner.db:owner.db.execute('INSERT INTO native_bindings VALUES(?,?,?)',(sid,'gemini','exact'))
    before=archive.capture_status(owner)
    with patch('pty.fork',side_effect=OSError(11,'synthetic EAGAIN: no child created')) as fork:
        with pytest.raises(OSError,match='no child'):
            owner._start(sid,actor='operator',argv=['/never-executed'],expected_native=owner.native(sid,actor='operator'))
        assert fork.call_count==1
    reservation.release.assert_called_once()
    assert sid not in owner.live
    status=archive.capture_status(owner)
    assert (status['open_runs'],status['interrupted_runs'],status['aborted_runs'])==(0,0,1)
    assert [tuple(r) for r in owner.db.execute('SELECT session,status FROM capture_runs')]==[(sid,'aborted-before-process')]
    assert status['used_bytes']>before['used_bytes']  # failure evidence stays charged
    assert owner.db.execute('SELECT count(*) FROM cleanup_ownership WHERE session=?',(sid,)).fetchone()[0]==0
    assert owner._get(sid)['status']!='running'
    owner.close()
    reopened=LocalCockpit(owner.root,owner.vault,owner.state,owner.host,native_runtimes=owner.native_runtimes)
    try:
        again=archive.capture_status(reopened)
        assert (again['open_runs'],again['interrupted_runs'],again['aborted_runs'])==(0,0,1)
        assert again['used_bytes']==status['used_bytes']
        assert [tuple(r) for r in reopened.db.execute('SELECT session,status FROM capture_runs')]==[(sid,'aborted-before-process')]
    finally:reopened.close()


def test_rev0534_post_fork_uncertainty_is_not_classified_aborted(launch_owner):
    """Control: a non-OSError from the fork boundary is not known no-child."""
    from unittest.mock import Mock
    owner,sid=launch_owner
    reservation=Mock()
    owner.native_runtimes['gemini']=SimpleNamespace(reserve=lambda conversation:reservation)
    with owner.db:owner.db.execute('INSERT INTO native_bindings VALUES(?,?,?)',(sid,'gemini','exact'))
    with patch('pty.fork',side_effect=RuntimeError('synthetic uncertain fork boundary')):
        with pytest.raises(RuntimeError):
            owner._start(sid,actor='operator',argv=['/never-executed'],expected_native=owner.native(sid,actor='operator'))
    status=archive.capture_status(owner)
    assert status['aborted_runs']==0 and status['open_runs']==status['interrupted_runs']==1
    owner.close()
    reopened=LocalCockpit(owner.root,owner.vault,owner.state,owner.host,native_runtimes=owner.native_runtimes)
    try:
        again=archive.capture_status(reopened)
        assert (again['open_runs'],again['interrupted_runs'],again['aborted_runs'])==(1,1,0)
    finally:reopened.close()


def test_reviewed_consent_expiring_during_snapshot_does_not_publish(services):
    api,call,profile,_=services
    extension=api.owners['local-owner'].extension
    reviewed=extension.reviewed_actions
    body=dict(family='hermes',path=str(profile),agent_id='agent-a',confirmed=True)
    status,review=call('actions/prepare',dict(action='manual/connect',request=body));assert status==200
    now=[review['expires_at']-1];original=reviewed.snapshot
    def crosses(*args):
        value=original(*args);now[0]=review['expires_at']+1;return value
    with patch('arvyx_control.reviewed_actions.time.time',side_effect=lambda:now[0]),patch.object(reviewed,'snapshot',side_effect=crosses):
        status,result=call('actions/commit',dict(consent_id=review['consent_id'],consent_sha256=review['sha256'],confirmed=True))
    assert status==400,result
    assert call('targets')[1]['items']==[]
    assert reviewed.db.execute('SELECT status FROM reviewed_actions WHERE id=?',(review['consent_id'],)).fetchone()[0]=='prepared'

from test_session_workspace_journey import journey, plan, commit


@pytest.fixture
def native_journey(journey, tmp_path):
    from arvyx_control.native_lifecycle import NativeLifecycle, OwnerProducer
    from arvyx_control.local_executor import ExecutionPolicy
    api,call,target,root,_=journey;extension=api.owners['local-owner'].extension
    owner=LocalCockpit(tmp_path/'native-owner',extension.vault,tmp_path/'native-events.jsonl','machine-a')
    extension.native=NativeLifecycle(extension,OwnerProducer(owner,policy=ExecutionPolicy(host_uid=os.geteuid(),allow_host=True)))
    yield extension.native,owner,call,target,root
    owner.close()


def test_native_snapshot_expiry_prevents_mkdir_and_launch(native_journey):
    native,owner,call,target,root=native_journey
    req=dict(plan(target,'create','fresh'),environment='host',harness='shell',root_acknowledged=False)
    status,review=call('native/prepare',req);assert status==200,review
    now=[review['expires_at']-1];original=native.snapshot
    def crosses(body):
        result=original(body);now[0]=review['expires_at']+1;return result
    with patch('arvyx_control.native_lifecycle.time.time',side_effect=lambda:now[0]),patch.object(native,'snapshot',side_effect=crosses),patch.object(owner,'_start') as process:
        status,result=call('native/commit',commit(review))
    assert status==400,result
    assert not (root/'fresh').exists();process.assert_not_called()


def test_native_expiry_after_selection_prevents_directory_publication(native_journey):
    from contextlib import contextmanager
    native,owner,call,target,root=native_journey
    req=dict(plan(target,'create','fresh'),environment='host',harness='shell',root_acknowledged=False)
    status,review=call('native/prepare',req);assert status==200
    now=[review['expires_at']-1];original=native.extension.workspaces.selection;calls=[]
    @contextmanager
    def crosses(body):
        with original(body) as result:
            calls.append(body)
            if len(calls)==2:now[0]=review['expires_at']+1
            yield result
    with patch('arvyx_control.native_lifecycle.time.time',side_effect=lambda:now[0]),patch.object(native.extension.workspaces,'selection',side_effect=crosses),patch.object(owner,'_start') as process:
        status,result=call('native/commit',commit(review))
    assert status==503,result
    assert not (root/'fresh').exists();process.assert_not_called()


def test_native_original_expiry_reaches_final_owner_fork_admission(native_journey):
    native,owner,call,target,root=native_journey
    req=dict(plan(target,'existing','existing'),environment='host',harness='shell',root_acknowledged=False)
    status,review=call('native/prepare',req);assert status==200
    now=[review['expires_at']-1];original=os.pipe2
    def crosses(flags):
        pair=original(flags);now[0]=review['expires_at']+1;return pair
    with patch('arvyx_control.native_lifecycle.time.time',side_effect=lambda:now[0]),patch('os.pipe2',side_effect=crosses),patch('pty.fork',side_effect=AssertionError('expired consent reached process')) as process:
        status,result=call('native/commit',commit(review))
    assert status==503,result
    process.assert_not_called()


def test_reviewed_consent_covers_dispatch_validation_before_publication(services):
    api,call,profile,_=services;extension=api.owners['local-owner'].extension
    body=dict(family='hermes',path=str(profile),agent_id='agent-a',confirmed=True)
    status,review=call('actions/prepare',dict(action='manual/connect',request=body));assert status==200
    now=[review['expires_at']-1];original=extension.route
    def crosses(*args,**kwargs):
        now[0]=review['expires_at']+1
        return original(*args,**kwargs)
    with patch('arvyx_control.reviewed_actions.time.time',side_effect=lambda:now[0]),patch.object(extension,'route',side_effect=crosses):
        status,result=call('actions/commit',commit(review))
    assert status==503,result
    assert call('targets')[1]['items']==[]


def test_native_attachment_expiry_during_owner_validation_never_grants_lease(launch_owner):
    owner,sid=launch_owner
    target=dict(machine_id=owner.host,agent_id='a',workspace_id='p',connection_id='c')
    epoch=owner.native_lifecycle(action='inspect',actor='operator')['epoch']
    with owner.db:
        owner.db.execute("UPDATE sessions SET status='running' WHERE id=?",(sid,))
        owner.db.execute('INSERT INTO native_bindings VALUES(?,?,?)',(sid,'shell',sid))
        owner.db.execute('INSERT INTO lifecycle_bindings VALUES(?,?,?,?,?,?)',('a'*32,sid,json.dumps(target,sort_keys=True),owner.incarnation,epoch,'host'))
    # Synthetic exact running process generation (no process is started); the
    # proof must name it, as the real producer's create/resolve result does.
    owner.live[sid]=dict(fd=1,attached=False,process_generation='synthetic-'+sid)
    proof=dict(owner_session=sid,owner_incarnation=owner.incarnation,epoch=epoch,conversation=sid,
               process_generation='synthetic-'+sid)
    expected=owner.native_lifecycle(action='inspect',actor='operator')
    try:
        now=[99.0];original=owner.native
        def crosses(*args,**kwargs):
            result=original(*args,**kwargs);now[0]=101.0;return result
        with patch('arvyx_control.reviewed_actions.time.time',side_effect=lambda:now[0]),patch.object(owner,'native',side_effect=crosses),patch.object(owner,'attach',wraps=owner.attach) as grant:
            with pytest.raises(ValueError,match='consent expired'):
                owner.native_lifecycle(action='attach',actor='operator',expected=expected,confirmed=True,result=proof,target=target,consent_expires_at=100.0)
            grant.assert_not_called()
        assert owner.live[sid]['attached'] is False and 'attachment_deadline' not in owner.live[sid]
        # Pre-expiry control: the same unchanged owner/process grants exactly one lease.
        now=[99.0]
        with patch('arvyx_control.reviewed_actions.time.time',side_effect=lambda:now[0]):
            lease=owner.native_lifecycle(action='attach',actor='operator',expected=expected,confirmed=True,result=proof,target=target,consent_expires_at=100.0)
        assert isinstance(lease['attachment'],str) and owner.live[sid]['attached']==lease['attachment']
        # A changed process generation is never admitted, even before expiry.
        with patch('arvyx_control.reviewed_actions.time.time',side_effect=lambda:now[0]):
            with pytest.raises(PermissionError,match='process generation changed'):
                owner.native_lifecycle(action='attach',actor='operator',expected=expected,confirmed=True,
                    result=dict(proof,process_generation='replaced'),target=target,consent_expires_at=100.0)
    finally:
        owner.live.clear()  # Synthetic fd must never reach OS cleanup.


@pytest.mark.parametrize('bridge_delay',['after_expiry','during_owner_dispatch','before_expiry'])
def test_rev0550_recorded_pane_command_bridge_after_expiry_grants_no_attachment(launch_owner,tmp_path,bridge_delay):
    """REV-0550: record the real pane command under consent, run its bridge later.

    Substituted boundaries only: the native frontend API is a recorder, the
    bridge 'process' is cockpit_arvyx.main() in a fresh context (no inherited
    consent ContextVar), the owner socket is in-memory framing into the real
    LocalCockpit.handle_connection, and the interactive terminal is a recorder.
    """
    import contextvars,shlex,sys,time as clock
    from io import BytesIO
    from arvyx_control import cockpit_arvyx,cockpit_client
    from arvyx_control.cockpit import handle_connection
    from arvyx_control.native_presentation import NativePresentation
    from arvyx_control.reviewed_actions import consent_scope
    owner,sid=launch_owner
    target=dict(machine_id=owner.host,agent_id='a',workspace_id='p',connection_id='c')
    epoch=owner.native_lifecycle(action='inspect',actor='operator')['epoch']
    with owner.db:
        owner.db.execute("UPDATE sessions SET status='running' WHERE id=?",(sid,))
        owner.db.execute('INSERT INTO native_bindings VALUES(?,?,?)',(sid,'shell',sid))
        owner.db.execute('INSERT INTO lifecycle_bindings VALUES(?,?,?,?,?,?)',('b'*32,sid,json.dumps(target,sort_keys=True),owner.incarnation,epoch,'host'))
    owner.live[sid]=dict(fd=1,attached=False,process_generation='synthetic-'+sid)
    proof=dict(owner_session=sid,owner_incarnation=owner.incarnation,epoch=epoch,conversation=sid,process_generation='synthetic-'+sid)
    owner_home=tmp_path/'pilot'
    frontend=tmp_path/'frontend';frontend.mkdir()
    (frontend/'bindings.json').write_text(json.dumps(dict(authority_home=str(owner_home),binary_sha256='f'*64,bindings=[])))
    panes=[];calls=[]
    class Native:
        digest='f'*64
        def __init__(self,*args,**kwargs):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def invoke(self,operation,args,**kwargs):
            calls.append(args);command=args[2:]
            if command==['api','snapshot']:result=dict(snapshot=dict(panes=panes))
            elif command[:2]==['workspace','create']:
                panes[:]=[dict(pane_id='w_1-1',workspace_id='w_1',tab_id='w_1:1',focused=False)]
                result=dict(root_pane=panes[0],workspace=dict(workspace_id='w_1'),tab=dict(tab_id='w_1:1'))
            else:result={}
            return json.dumps(dict(result=result)).encode()
    def focus(_frontend,pane):
        for row in panes:row['focused']=row['pane_id']==pane
    producer=SimpleNamespace(verify=lambda observed,route:None,record_pane=lambda *args:None)
    presentation=NativePresentation(owner_home,frontend,tmp_path/'not-executed',sqlite3.connect(tmp_path/'attempts.db'))
    expires=clock.time()+300
    try:
        with consent_scope(expires),patch('arvyx_control.native_presentation.VerifiedNative',Native),\
                patch('arvyx_control.native_presentation._focus_pane',side_effect=focus):
            presentation.present(proof,target,producer=producer)
        runs=[c for c in calls if c[2:4]==['pane','run']]
        assert len(runs)==1
        argv=shlex.split(runs[0][-1])
        assert argv[1:3]==['-m','arvyx_control.cockpit_arvyx']
        assert float(argv[argv.index('--native-consent-expires')+1])==expires
        wire=[]
        def exchange(endpoint,payload,**options):
            assert endpoint==owner_home/'runtime/cockpit.sock' and options=={}
            wire.append(json.loads(payload))
            if bridge_delay=='during_owner_dispatch' and wire[-1].get('action')=='attach':
                now[0]=expires+1  # bridge checks passed; delayed in transit to the owner
            class Memory:
                def __init__(self):self.input,self.output=BytesIO(payload),BytesIO()
                def settimeout(self,seconds):pass
                def recv(self,size):return self.input.read(size)
                def sendall(self,data):self.output.write(data)
            transport=Memory();handle_connection(transport,owner,owner);return transport.output.getvalue()
        now=[expires+1 if bridge_delay=='after_expiry' else expires-1]
        def bridge_process():
            with patch.object(sys,'argv',['cockpit_arvyx',*argv[3:]]):
                cockpit_arvyx.main()
        with patch('arvyx_control.reviewed_actions.time.time',side_effect=lambda:now[0]),\
                patch.object(cockpit_client,'exchange',side_effect=exchange),\
                patch.object(cockpit_client,'attach') as terminal,patch.object(owner,'attach',wraps=owner.attach) as grant:
            if bridge_delay!='before_expiry':
                with pytest.raises(ValueError,match='consent expired'):
                    contextvars.Context().run(bridge_process)
            else:
                contextvars.Context().run(bridge_process)
        attach_requests=[r for r in wire if r.get('operation')=='native_lifecycle' and r.get('action')=='attach']
        if bridge_delay!='before_expiry':
            # Zero granted attachment tokens: no owner grant, no lease, no terminal.
            grant.assert_not_called();terminal.assert_not_called()
            assert owner.live[sid]['attached'] is False and 'attachment_epoch' not in owner.live[sid]
            if bridge_delay=='after_expiry':
                assert attach_requests==[]
            else:
                # The request reached the real owner carrying the original expiry;
                # the owner refused it on its own clock check.
                assert len(attach_requests)==1 and attach_requests[0]['consent_expires_at']==expires
        else:
            assert len(attach_requests)==1 and attach_requests[0]['consent_expires_at']==expires
            grant.assert_called_once()
            lease=terminal.call_args.kwargs['existing_lease']
            assert isinstance(lease['attachment'],str) and owner.live[sid]['attached']==lease['attachment']
    finally:
        owner.live.clear()  # Synthetic fd must never reach OS cleanup.


def test_rev0550_owner_rechecks_original_expiry_without_bridge_cooperation(launch_owner):
    """Final owner admission enforces the transported expiry itself."""
    owner,sid=launch_owner
    target=dict(machine_id=owner.host,agent_id='a',workspace_id='p',connection_id='c')
    epoch=owner.native_lifecycle(action='inspect',actor='operator')['epoch']
    with owner.db:
        owner.db.execute("UPDATE sessions SET status='running' WHERE id=?",(sid,))
        owner.db.execute('INSERT INTO native_bindings VALUES(?,?,?)',(sid,'shell',sid))
        owner.db.execute('INSERT INTO lifecycle_bindings VALUES(?,?,?,?,?,?)',('c'*32,sid,json.dumps(target,sort_keys=True),owner.incarnation,epoch,'host'))
    owner.live[sid]=dict(fd=1,attached=False,process_generation='synthetic-'+sid)
    proof=dict(owner_session=sid,owner_incarnation=owner.incarnation,epoch=epoch,conversation=sid,process_generation='synthetic-'+sid)
    expected=owner.native_lifecycle(action='inspect',actor='operator')
    try:
        with patch('arvyx_control.reviewed_actions.time.time',return_value=101.0):
            with pytest.raises(ValueError,match='consent expired'):
                owner.native_lifecycle(action='attach',actor='operator',expected=expected,confirmed=True,result=proof,target=target,consent_expires_at=100.0)
        assert owner.live[sid]['attached'] is False
    finally:
        owner.live.clear()


@pytest.mark.parametrize('prepared_expiry',[1234.5,2000.0,None])
def test_socket_producer_carries_exact_original_consent_expiry(tmp_path,prepared_expiry):
    from arvyx_control.native_lifecycle import SocketOwnerProducer
    from arvyx_control.reviewed_actions import consent_scope
    producer=SocketOwnerProducer(tmp_path/'owner',vault=tmp_path/'vault',state=tmp_path/'events',machine='m')
    expected=dict(owner={'epoch':1},workspace_identity=[1,2],consent_expires_at=prepared_expiry)
    request=dict(target={'machine_id':'m'},environment='host',root_acknowledged=False,harness='shell')
    calls=[]
    def transport(home,operation,**fields):
        calls.append((operation,fields))
        return dict(epoch=1)
    with patch('arvyx_control.cockpit_client.request',side_effect=transport),patch('arvyx_control.reviewed_actions.time.time',return_value=1200):
        with consent_scope(1234.5):
            producer.create('a'*32,request,'/workspace',expected)
            producer.attach({'owner_session':'s'},request['target'])
    effects=[fields for _,fields in calls if fields['action'] in ('new','attach')]
    assert len(effects)==2 and all(row['consent_expires_at']==1234.5 for row in effects)


def test_ordinary_unicode_is_deliverable_outside_private_block(tmp_path):
    owner=owner_at(tmp_path/'capture.db')
    try:
        recorder=archive.WorkCapture(owner,'s')
        recorder.feed('Béatrice shares public text\nVisible later\n'.encode());recorder.finish()
        received=delivery_bytes(owner)
        assert b'Visible later' in received
        assert 'Béatrice' in str(archive.export_capture(owner,actor='operator'))
    finally:owner.db.close()


def test_incomplete_unicode_ending_candidate_cannot_close_after_reopen(tmp_path):
    path=tmp_path/'capture.db';owner=owner_at(path)
    recorder=archive.WorkCapture(owner,'s');recorder.feed(b'BEGIN RSA PRIVATE KEY\nEN\xc4');recorder.finish();owner.db.close()
    owner=owner_at(path)
    try:
        recorder=archive.WorkCapture(owner,'s');recorder.feed(b'D RSA PRIVATE KEY\nLATER_PRIVATE_BODY\n');recorder.finish()
        assert b'LATER_PRIVATE_BODY' not in delivery_bytes(owner)
    finally:owner.db.close()


def test_native_workspace_replacement_at_final_effect_never_forks(native_journey):
    native,owner,call,target,root=native_journey
    req=dict(plan(target,'existing','existing'),environment='host',harness='shell',root_acknowledged=False)
    status,review=call('native/prepare',req);assert status==200
    original=os.pipe2
    def replaces(flags):
        result=original(flags)
        (root/'existing').rename(root/'reviewed-original')
        (root/'existing').mkdir()
        return result
    with patch('os.pipe2',side_effect=replaces),patch('pty.fork',side_effect=AssertionError('replacement reached process')) as process:
        status,result=call('native/commit',commit(review))
    assert status==503,result
    process.assert_not_called()
    assert (root/'reviewed-original').is_dir() and (root/'existing').is_dir()


def test_native_expiry_at_last_checkpoint_never_forks(native_journey):
    native,owner,call,target,root=native_journey
    req=dict(plan(target,'existing','existing'),environment='host',harness='shell',root_acknowledged=False)
    status,review=call('native/prepare',req);assert status==200
    now=[review['expires_at']-1]
    def expires():
        now[0]=review['expires_at']+1
        return 1
    with patch('arvyx_control.reviewed_actions.time.time',side_effect=lambda:now[0]),patch('arvyx_control.cockpit.checkpoint',side_effect=expires),patch('pty.fork',side_effect=AssertionError('checkpoint expiry reached process')) as process:
        status,result=call('native/commit',commit(review))
    assert status==503,result
    process.assert_not_called()


def test_owner_producer_forwards_exact_delegation_fence_and_original_expiry(launch_owner):
    from arvyx_control.native_lifecycle import OwnerProducer
    owner,_=launch_owner
    producer=OwnerProducer(owner,policy=owner.execution_policy)
    ticket=dict(authority_id='authority',token='a'*64)
    expected=dict(owner={'epoch':1},workspace_identity=[1,2],delegation_fence=ticket,consent_expires_at=1234.5)
    request=dict(target={'machine_id':owner.host},environment='host',root_acknowledged=False,harness='shell')
    with patch('arvyx_control.reviewed_actions.time.time',return_value=1200),patch.object(owner,'native_lifecycle',return_value={}) as effect:
        producer.create('a'*32,request,'/workspace',expected)
    assert effect.call_args.kwargs['delegation_fence']==ticket
    assert effect.call_args.kwargs['consent_expires_at']==1234.5


def test_owner_missing_config_never_accepts_delegated_ticket(launch_owner):
    owner,_=launch_owner
    expected=owner.native_lifecycle(action='inspect',actor='operator')
    assert expected.get('organizer_effect_fence') is False
    before=len(owner.list())
    with patch('pty.fork') as process:
        with pytest.raises(PermissionError,match='delegat'):
            owner.native_lifecycle(action='new',actor='operator',expected=expected,confirmed=True,attempt='a'*32,target={'machine_id':owner.host,'agent_id':'a'},workspace=str(owner.root),environment='host',workspace_identity=[owner.root.stat().st_dev,owner.root.stat().st_ino],delegation_fence=dict(authority_id='authority',token='a'*64))
        process.assert_not_called()
    assert len(owner.list())==before


@pytest.fixture
def delegated_owner(launch_owner,tmp_path):
    from arvyx_control.organizer_authority import OrganizerAuthority
    from arvyx_control.native_lifecycle import OwnerProducer
    from dataclasses import asdict
    import time
    owner,_=launch_owner;database=tmp_path/'organizer.sqlite'
    with authority_context(owner.vault,owner.state):
        policy=OrganizerAuthority(database=database)
        organizer=policy.provision_identity('organizer',kind='internal',organizer=True)
        worker=policy.provision_identity('worker',kind='internal')
        policy.enroll_machine(owner.host);policy.bind_agent(worker,machine=owner.host,root=True)
        policy.bind_executor(worker,machine=owner.host,environments=['host'])
        expires=time.time()+60
        with policy._lock:
            decision=asdict(policy.authorize(organizer,operation='invoke_host',machine=owner.host,executing_agent=worker))
            effect=dict(request_id='b'*32,machine=owner.host,executing_agent='worker',session='leaf',operation='invoke_host',environment='host',root_acknowledged=False,decision=decision,consent_expires_at=expires)
            ticket=policy._backend.issue_effect_ticket(effect,expires)
    owner.delegation_authority_database=database
    producer=OwnerProducer(owner,policy=owner.execution_policy)
    request=dict(target={'machine_id':owner.host,'agent_id':'worker'},harness='shell',environment='host',root_acknowledged=False)
    workspace=owner.root
    expected=producer.plan(request,workspace)
    expected.update(delegation_fence=ticket,consent_expires_at=expires)
    yield owner,producer,policy,organizer,request,workspace,expected
    policy.close()


@pytest.mark.parametrize('revocation',['organizer','machine'])
def test_actual_owner_fork_is_inside_authenticated_policy_fence(delegated_owner,revocation):
    import threading
    owner,producer,policy,organizer,request,workspace,expected=delegated_owner
    started=threading.Event();finished=threading.Event();errors=[];workers=[]
    def revoke():
        try:
            with authority_context(owner.vault,owner.state):
                started.set()
                if revocation=='organizer':policy.set_organizer(organizer,False)
                else:policy.set_machine_state(owner.host,'disconnected')
                finished.set()
        except BaseException as error:errors.append(error)
    def fork_recorder():
        worker=threading.Thread(target=revoke);workers.append(worker);worker.start()
        assert started.wait(1)
        assert not finished.wait(.05),'revocation crossed unsettled final fork admission'
        raise RuntimeError('harmless fork recorder; no process created')
    try:
        with patch('pty.fork',side_effect=fork_recorder) as process:
            with pytest.raises(RuntimeError,match='harmless fork recorder'):
                producer.create('b'*32,request,str(workspace),expected)
            assert process.call_count==1
        for worker in workers:worker.join(2)
        assert finished.is_set() and not errors
        assert archive.capture_status(owner)['interrupted_runs']==1
        with authority_context(owner.vault,owner.state),policy._lock:
            assert policy._backend.db.execute('SELECT status FROM organizer_effect_tickets').fetchone()[0]=='admitted'
        with patch('pty.fork') as process:
            with pytest.raises((PermissionError,ValueError)):
                producer.create('c'*32,request,str(workspace),expected)
            process.assert_not_called()
    finally:
        for worker in workers:worker.join(2)


def test_actual_owner_fenced_success_publishes_once_with_process_recorders(delegated_owner):
    owner,producer,policy,_,request,workspace,expected=delegated_owner
    pipes=[];original=os.pipe2
    def pipe(flags):
        result=original(flags);pipes.append(result);return result
    def fork():
        os.write(pipes[-1][1],b'X')
        return 2147483647,os.open(os.devnull,os.O_RDWR)
    class PumpRecorder:
        def __init__(self,**kwargs):self.ident=None
        def start(self):self.ident=1
        def join(self,**kwargs):pass
        def is_alive(self):return False
    try:
        with patch('os.pipe2',side_effect=pipe),patch('pty.fork',side_effect=fork) as process,patch('os.waitid',return_value=None),patch('arvyx_control.cockpit.threading.Thread',PumpRecorder):
            result=producer.create('b'*32,request,str(workspace),expected)
            assert result['status']=='running' and result['native_session_created'] is True
            assert owner._get(result['owner_session'])['status']=='running'
            with pytest.raises(ValueError,match='already recorded'):
                producer.create('b'*32,request,str(workspace),expected)
            assert process.call_count==1
        with authority_context(owner.vault,owner.state),policy._lock:
            status,expiry=policy._backend.db.execute('SELECT status,expires FROM organizer_effect_tickets').fetchone()
            assert status=='admitted' and expiry==expected['consent_expires_at']
    finally:
        # No kernel child or pump exists. Retire only disposable recorder state.
        for sid,live in list(owner.live.items()):
            if live.get('fd') is not None:os.close(live['fd'])
            live['recorder'].finish()
            with owner.db:
                owner.db.execute('DELETE FROM cleanup_ownership WHERE session=?',(sid,))
                owner.db.execute("UPDATE sessions SET status='stopped',pid=NULL WHERE id=?",(sid,))
        owner.live.clear()


def test_owner_rejects_ticket_from_authority_replacement_before_final_effect(delegated_owner,tmp_path):
    from arvyx_control.organizer_authority import OrganizerAuthority
    from dataclasses import asdict
    owner,producer,policy,_,request,workspace,expected=delegated_owner
    original_database=owner.delegation_authority_database
    replacement=tmp_path/'replacement-policy.sqlite'
    with authority_context(owner.vault,owner.state):
        other=OrganizerAuthority(database=replacement)
        try:
            actor=other.provision_identity('organizer',kind='internal',organizer=True)
            worker=other.provision_identity('worker',kind='internal')
            other.enroll_machine(owner.host);other.bind_agent(worker,machine=owner.host,root=True)
            other.bind_executor(worker,machine=owner.host,environments=['host'])
            with other._lock:
                decision=asdict(other.authorize(actor,operation='invoke_host',machine=owner.host,executing_agent=worker))
                effect=dict(request_id='b'*32,machine=owner.host,executing_agent='worker',session='leaf',operation='invoke_host',environment='host',root_acknowledged=False,decision=decision,consent_expires_at=expected['consent_expires_at'])
                foreign=other._backend.issue_effect_ticket(effect,expected['consent_expires_at'])
        finally:other.close()
    policy.close()  # Close disposable WAL handles before replacing either file.
    original=os.pipe2
    def replaces(flags):
        pair=original(flags)
        original_database.rename(tmp_path/'reviewed-original-policy.sqlite')
        replacement.rename(original_database)
        return pair
    with patch('os.pipe2',side_effect=replaces),patch('pty.fork',side_effect=RuntimeError('foreign authority reached fork')) as process:
        with pytest.raises(PermissionError,match='authority'):
            producer.create('b'*32,request,str(workspace),dict(expected,delegation_fence=foreign))
        process.assert_not_called()
