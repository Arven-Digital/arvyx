"""Supplemental ledger regressions: synthetic state, no providers or sockets."""
from contextlib import contextmanager
import json, os, time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from test_session_workspace_journey import journey, plan, commit
from test_local_onboarding_services import services
from test_hermes_history import history
import os

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='host-shell execution policy (host_uid) and the PTY owner are POSIX-only')


@pytest.mark.parametrize('mode', ['create', 'existing'])
def test_workspace_original_consent_crosses_validation(journey, mode):
    api, call, target, root, _ = journey
    preview = call('sessions/prepare', plan(target, mode, 'fresh' if mode == 'create' else 'existing'))[1]
    extension = api.owners['local-owner'].extension
    from arvyx_control.session_workspaces import SessionWorkspaces
    original = SessionWorkspaces.selection
    clock = [preview['expires_at'] - 1]
    @contextmanager
    def delayed(self, body):
        with original(self, body) as selection:
            clock[0] = preview['expires_at'] + 1
            yield selection
    with patch.object(SessionWorkspaces, 'selection', delayed), patch('time.time', side_effect=lambda: clock[0]):
        status, result = call('sessions/commit', commit(preview))
    assert status in (400, 503), result
    assert not (root/'fresh').exists()
    assert api.owners['local-owner'].creation.db.execute("SELECT status FROM session_preparations WHERE id=?", (preview['consent_id'],)).fetchone()[0] != 'completed'


@pytest.mark.parametrize('tool, metadata', [('gemini', []), ('claude', []), ('codex', []), ('codex', {'type':'session_meta','payload':[]})])
def test_native_metadata_shape_is_typed_refusal(tmp_path, tool, metadata):
    from arvyx_control.cockpit_native_runtime import NativeRuntime
    home=tmp_path/'home'; home.mkdir(); store=home/'session.json'; store.write_text(json.dumps(metadata))
    executable=home/'fake'; executable.write_text('#!/bin/false\n'); executable.chmod(0o700)
    runtime=NativeRuntime(tool=tool, executable=executable, home=home, store=store)
    with pytest.raises(ValueError, match='metadata|object'):
        runtime.plan('synthetic-conversation', home)


def test_decision_platform_rejects_credential_shape_without_append(tmp_path):
    from test_decisions import DecisionTests
    from arvyx_control.replica_authority import authority_context
    from arvyx_control.control import read_events
    helper=DecisionTests(); state=tmp_path/'state'; vault=tmp_path/'vault'; vault.mkdir()
    with authority_context(vault, state):
        execution=helper._leased(state); decision=helper._ask(state, execution); helper._deliver_card(state)
        before=read_events(state)
        with pytest.raises(ValueError, match='platform'):
            helper._answer(state, decision, platform='ghp_' + 'Q'*36)
        assert read_events(state) == before


@pytest.mark.parametrize('change', ['expire','remove','replace','unchanged','clock-expire'])
def test_secret_session_rechecked_after_receipt_reservation(tmp_path, change):
    import io
    from email.message import Message
    from arvyx_control.secret_delivery import SecretDelivery, Session, COOKIE
    from arvyx_control.secret_delivery_protocol import Receipts, Principal
    from arvyx_control.replica_authority import authority_context
    from arvyx_control.vault import init_vault
    vault=tmp_path/'vault'; init_vault(vault); tmp_path.chmod(0o700)
    calls=[]
    target=SimpleNamespace(id='synthetic', agent='demobot', runtime='codex-demo', allowed_keys=('OTHER',), exchange=lambda v: calls.append(v) or {'status':'saved'})
    # In-memory receipt DB exercises real reserve/finish without pretending the
    # configured scratch's group-writable ancestor is a production safe path.
    import sqlite3, threading
    class InMemoryReceipts(Receipts):
        def __init__(self):
            self.lock=threading.Lock();self.db=sqlite3.connect(':memory:')
            self.db.execute('CREATE TABLE receipts (id TEXT PRIMARY KEY,target TEXT,key TEXT,status TEXT,actor TEXT,created INTEGER,actor_bound INTEGER)')
        @contextmanager
        def connect(self):
            with self.db:yield self.db
    receipts=InMemoryReceipts(); service=SecretDelivery('https://synthetic.invalid', [target], receipts, vault=vault)
    session=Session('human', 'csrf-synthetic', time.time()+100); service.sessions['sid']=session
    session.preparations['confirmation']=('synthetic','OTHER','version',False,time.time()+90)
    payload=dict(target='synthetic',key='OTHER',value='synthetic value',delivery_id='synthetic-id',confirmation='confirmation',overwrite=False)
    raw=json.dumps(payload).encode();headers=Message()
    for k,v in [('Origin',service.origin),('X-Secret-Delivery','1'),('Cookie',COOKIE+'=sid'),('X-Secret-CSRF',session.csrf),('Content-Type','application/json'),('Content-Length',str(len(raw)))]:headers[k]=v
    handler=SimpleNamespace(connection=SimpleNamespace(settimeout=lambda _:None),path='/secret-delivery/send',command='POST',headers=headers,rfile=io.BytesIO(raw),wfile=io.BytesIO(),send_response=lambda *a:None,send_header=lambda *a:None,end_headers=lambda:None)
    real=receipts.reserve
    clock=[time.time()]
    def reserve(*args):
        value=real(*args)
        if change=='expire':session.expires=0
        elif change=='remove':service.sessions.pop('sid')
        elif change=='replace':service.sessions['sid']=Session('human','csrf-synthetic',time.time()+100)
        elif change=='clock-expire':clock[0]=session.expires+1
        return value
    principal=Principal('human',clock[0]+200)
    with patch.object(receipts,'reserve',reserve),patch('time.time',side_effect=lambda:clock[0]):
        service.handle(handler,principal)
    assert len(calls)==(1 if change=='unchanged' else 0)
    assert receipts.get('synthetic-id','human')['status']==('saved' if change=='unchanged' else 'ambiguous')
    assert 'synthetic value' not in handler.wfile.getvalue().decode()


def test_terminal_pairing_selects_exact_claim():
    from arvyx_control.shared_onboarding_cli import menu
    calls=[]
    def call(path, body=None):
        calls.append((path,body))
        if path=='capabilities':return {'pairing':True,'mode':'SYNTHETIC'}
        if path=='pairing/pending':return {'claims':[dict(claim_id='claim-a',fingerprint='fingerprint-a',name='Synthetic remote',expires=9999999999)]}
        return {}
    with patch('builtins.input',side_effect=['pair','approve','1','yes','quit']):menu(call)
    decisions=[b for p,b in calls if p=='pairing/decide']
    assert decisions == [dict(claim_id='claim-a',fingerprint='fingerprint-a',approved=True,confirmed=True)]


def test_composition_retry_repeats_ancestor_barriers(tmp_path):
    from arvyx_control import composition_recovery as composition
    destination=tmp_path/'existing'/'cut'; destination.mkdir(parents=True)
    synced=[]
    with patch.object(composition,'sync',side_effect=lambda p:synced.append(Path(p))):composition.mkdir_durable(destination)
    assert destination in synced and destination.parent in synced and tmp_path in synced


def test_retrieval_nonregular_never_enters_blocking_reader(tmp_path):
    from arvyx_control import index
    root=tmp_path/'projects'/'demo';root.mkdir(parents=True);fifo=root/'note.md';os.mkfifo(fifo)
    original=Path.read_bytes
    def read(path):
        if path==fifo:pytest.fail('FIFO reached blocking pathname reader')
        return original(path)
    with patch.object(Path,'read_bytes',read):assert index._source_snapshot(tmp_path,'projects/demo/note.md') is None


def test_newline_recovery_repeats_namespace_barrier(tmp_path):
    from arvyx_control import control
    from arvyx_control.replica_authority import authority_context
    state=tmp_path/'events';vault=tmp_path/'vault';vault.mkdir()
    with authority_context(vault,state):
        control.post_thread(state,title='Synthetic',actor='human',target='test',thread_type='ask',actor_identity_bound=True)
        state.write_bytes(state.read_bytes().rstrip(b'\n'))
        calls=[]
        with patch('arvyx_control.filesystem.fsync_directory',side_effect=lambda p:calls.append(Path(p))):
            assert control.recover_torn_final_event(state)['repair']=='missing_final_newline'
        assert state.parent in calls


def test_native_bridge_carries_original_expiry_to_final_owner():
    from arvyx_control.cockpit_arvyx import bridge
    observed=[];expires=time.time()+10
    proof=dict(owner_session='synthetic-session',owner_incarnation='incarnation',epoch=1)
    def request(home,op,**kw):
        observed.append((op,kw))
        if op=='native_lifecycle' and kw.get('action')=='inspect':return dict(incarnation='incarnation',epoch=1)
        return {}
    with patch('arvyx_control.cockpit_client.request',request),patch('arvyx_control.cockpit_client.attach'),patch('arvyx_control.cockpit_arvyx.pane_binding'):
        bridge(Path('/synthetic-owner'),proof['owner_session'],proof=proof,target={},consent_expires_at=expires)
    assert [v for op,v in observed if v.get('action')=='attach'][0]['consent_expires_at']==expires


def test_sandbox_refuses_launcher_without_directory_fd_protocol(tmp_path):
    from arvyx_control.local_executor import ExecutionPolicy
    launcher=tmp_path/'synthetic-launcher';launcher.write_text('fake recorder bytes');launcher.chmod(0o700)
    with patch('os.geteuid',return_value=1001):
        with pytest.raises(PermissionError,match='directory-fd'):
            ExecutionPolicy(host_uid=1001,sandbox_launcher=launcher).plan('sandbox',tmp_path)


def test_trusted_sandbox_fd_argument_survives_workspace_replacement(tmp_path):
    from arvyx_control.local_executor import ExecutionPolicy
    from arvyx_control.external_workspace import _open_root
    launcher=tmp_path/'synthetic-launcher';launcher.write_bytes(b'synthetic nonexecuted launcher bytes');launcher.chmod(0o700)
    workspace=tmp_path/'workspace';workspace.mkdir();(workspace/'original').write_text('synthetic original')
    with patch('os.geteuid',return_value=1001):
        policy=ExecutionPolicy(host_uid=1001,sandbox_launcher=launcher,sandbox_fd_protocol='arvyx-directory-fd-v1')
        plan=policy.plan('sandbox',workspace)
    # Explicit sealing recorder. This interpreter lacks some sealing constants;
    # it does not establish an actual kernel seal or a sandbox mount.
    import fcntl
    from contextlib import ExitStack
    with ExitStack() as stack:
        for key,value in dict(F_ADD_SEALS=1033,F_SEAL_WRITE=8,F_SEAL_GROW=4,F_SEAL_SHRINK=2,F_SEAL_SEAL=1).items():stack.enter_context(patch.object(fcntl,key,value,create=True))
        stack.enter_context(patch.object(os,'MFD_CLOEXEC',1,create=True));stack.enter_context(patch.object(os,'MFD_ALLOW_SEALING',2,create=True))
        stack.enter_context(patch.object(os,'memfd_create',side_effect=lambda *a:os.open(tmp_path/'SYNTHETIC-seal-recorder',os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600),create=True))
        seals=stack.enter_context(patch.object(fcntl,'fcntl',return_value=0))
        with _open_root(workspace) as fd,policy.sealed_launcher(plan,workspace_fd=fd) as argv:
            workspace.rename(tmp_path/'original-workspace');workspace.mkdir();(workspace/'foreign').write_text('replacement')
            received=int(argv[argv.index('--bind-fd')+1])
            assert received==fd and os.listdir(received)==['original']
            assert str(workspace) not in argv and not os.get_inheritable(received)
        assert seals.call_count==1


def test_descriptor_root_preserves_effect_refusal_type(tmp_path):
    from arvyx_control.external_workspace import _open_root
    with pytest.raises(PermissionError,match='synthetic effect refusal'):
        with _open_root(tmp_path):raise PermissionError('synthetic effect refusal')


def test_remote_private_config_permission_check_binds_the_read_inode(tmp_path):
    from arvyx_control.remote_effect_fence import private_config
    from arvyx_control import external_workspace
    path=tmp_path/'trusted.json';path.write_text('{"synthetic":"untrusted-old-inode"}');path.chmod(0o666)
    original=external_workspace._read
    def replace_after_read(*args,**kwargs):
        result=original(*args,**kwargs)
        path.unlink();path.write_text('{"synthetic":"trusted-new-inode"}');path.chmod(0o600)
        return result
    with patch.object(external_workspace,'_read',side_effect=replace_after_read):
        with pytest.raises(PermissionError):private_config(path)


@pytest.mark.parametrize('failure',['missing','invalid','namespace','conflict','in_progress'])
@pytest.mark.parametrize('notification',[False,True])
def test_mcp_early_admission_errors_keep_wire_envelope(tmp_path,failure,notification):
    from arvyx_control import api
    from arvyx_control.replica_authority import authority_context
    from arvyx_control.vault import init_vault
    from arvyx_control.operation_journal import JournalNamespaceError
    from arvyx_control.auth import OPERATOR_IDENTITY
    vault=tmp_path/'vault';init_vault(vault);state=tmp_path/'events'
    arguments=dict(title='Synthetic',target='worker')
    if failure!='missing':arguments['idempotency_key']='key' if failure=='invalid' else 'synthetic-idempotency-key'
    body=dict(jsonrpc='2.0',method='tools/call',params=dict(name='control.thread_post',arguments=arguments))
    if not notification:body['id']='current-rpc-id'
    claim=SimpleNamespace(operation_id='synthetic-op',conflict=failure=='conflict',created=False,state='dispatching' if failure=='in_progress' else 'completed')
    with authority_context(vault,state),patch.object(api,'resolve_identity',return_value=OPERATOR_IDENTITY),patch.object(api,'claim_mutation',side_effect=JournalNamespaceError('synthetic namespace') if failure=='namespace' else None,return_value=claim):
        response=api.handle_api_request('POST','/mcp',body,vault,state,mcp_profile='operator')
    if notification:assert response.body==''
    else:
        value=json.loads(response.body) if isinstance(response.body,str) else response.body
        assert value['jsonrpc']=='2.0' and value['id']=='current-rpc-id'
        assert 'error' in value and 'data' in value['error']


@pytest.mark.parametrize('failure',['missing','invalid','namespace','conflict','in_progress','audit'])
@pytest.mark.parametrize('notification',[False,True])
def test_actual_mcp_http_writer_preserves_admission_envelope(tmp_path,failure,notification):
    from arvyx_control import api
    from arvyx_control.vault import init_vault
    from arvyx_control.operation_journal import JournalNamespaceError
    from test_local_handler_wire import Wire
    import secrets,threading
    vault=tmp_path/'vault';init_vault(vault);state=tmp_path/'events';credential=secrets.token_urlsafe(40)
    arguments=dict(title='Synthetic',target='worker')
    if failure!='missing':arguments['idempotency_key']='short' if failure=='invalid' else 'synthetic-mcp-key-0001'
    body=dict(jsonrpc='2.0',method='tools/call',params=dict(name='control.thread_post',arguments=arguments))
    if not notification:body['id']='http-current-id'
    claim=SimpleNamespace(operation_id='synthetic-op',conflict=failure=='conflict',created=failure=='audit',state='dispatching' if failure=='in_progress' else 'claimed')
    handler=api.make_handler(vault,state,bearer_secret=credential,mcp_profile='operator')
    with patch.object(api,'claim_mutation',side_effect=JournalNamespaceError('synthetic namespace') if failure=='namespace' else None,return_value=claim),patch.object(api,'_audit_api_intent',return_value=False):
        raw=json.dumps(body).encode()
        if os.environ.get('AMC_FIX5_MCP_HOST_HTTP')=='1':
            import http.client
            server=api.BoundedThreadingHTTPServer(('127.0.0.1',0),handler)
            thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);thread.start()
            try:
                connection=http.client.HTTPConnection(*server.server_address,timeout=3)
                try:
                    connection.request('POST','/mcp',raw,{'Authorization':'Bearer '+credential,'Content-Type':'application/json'})
                    response=connection.getresponse();status=response.status;payload=response.read()
                finally:connection.close()
            finally:server.shutdown();server.server_close();thread.join(3)
        else:
            class HTTPWire(Wire):
                def gettimeout(self):return None
                def settimeout(self,value):pass
            wire=HTTPWire(('POST /mcp HTTP/1.0\r\nAuthorization: Bearer '+credential+'\r\nContent-Type: application/json\r\nContent-Length: '+str(len(raw))+'\r\n\r\n').encode()+raw)
            handler(wire,('127.0.0.1',1),SimpleNamespace())
            head,payload=bytes(wire.output).split(b'\r\n\r\n',1);status=int(head.split()[1])
    if notification:assert status==202 and payload==b''
    else:
        value=json.loads(payload);assert status>=400
        assert value['jsonrpc']=='2.0' and value['id']=='http-current-id' and 'data' in value['error']


def test_issuer_explicit_expiry_is_exact_and_bounded(tmp_path):
    from datetime import timedelta
    from test_completion_fix5_E import authority
    with authority(tmp_path) as (api,store,now):
        expiry=(now+timedelta(hours=2)).isoformat()
        body=dict(recipient='reader',resources=['task:A'],operations=['read'],provenance='synthetic reviewed expiry',expires_at=expiry)
        status,result=api.dispatch('POST','/external/grants','Bearer fixture-issuer',body)
        assert status==201,result
        assert api.dispatch('GET','/external/grants/'+result['id'],'Bearer fixture-issuer',{})[1]['expires_at']==expiry
        for invalid in [(now-timedelta(seconds=1)).isoformat(),(now+timedelta(hours=25)).isoformat(),'invalid']:
            assert api.dispatch('POST','/external/grants','Bearer fixture-issuer',dict(body,expires_at=invalid))[0]==400


def test_import_link_crash_recovers_exact_owned_witness(tmp_path):
    import subprocess,sys
    from arvyx_control.replica_authority import authority_context
    from arvyx_control.promotion_transaction import memory_mutation
    source=tmp_path/'note.md';source.write_text('Synthetic imported text');vault=tmp_path/'vault';vault.mkdir()
    child='''import os,sys
from pathlib import Path
from arvyx_control.importers import import_markdown
from arvyx_control.replica_authority import authority_context
source,vault=map(Path,sys.argv[1:]);real=os.link
def crash(*a,**k):
 real(*a,**k);os._exit(77)
os.link=crash
with authority_context(vault):import_markdown(source,vault,'demo')
'''
    result=subprocess.run([sys.executable,'-c',child,str(source),str(vault)],timeout=10)
    assert result.returncode==77
    target=vault/'projects/demo/imported/note.md';before=target.read_bytes();assert target.stat().st_nlink==2
    with authority_context(vault),memory_mutation(vault):pass
    assert target.read_bytes()==before and target.stat().st_nlink==1
    assert list(target.parent.glob('.import-*.stage'))==[]


def test_local_archive_offload_never_fabricates_sink_delivery(tmp_path):
    from retention_fixture_helpers import retention_receipt
    from test_pass3_capture_offload import owner
    from arvyx_control.cockpit_archive import WorkCapture
    from arvyx_control.capture_offload import prepare_offload,acknowledge_offload,bundle_read
    o=owner(tmp_path);directory=tmp_path/'offload';directory.mkdir()
    o._get=lambda sid:{'id':sid,'kind':'local'} # local-only session: shared export permanently refused
    try:
        stream=WorkCapture(o,'sid');stream.feed(b'Synthetic local-only archive\n');stream.finish()
        review=prepare_offload(o,directory,actor='operator',acknowledgement='local-archive')
        rows=bundle_read(directory,review['sha256'])['records']
        assert rows and all(row['delivered']==0 for row in rows)
        assert o.db.execute('SELECT count(*) FROM work_capture').fetchone()[0]==len(rows)
        with pytest.raises(ValueError):acknowledge_offload(o,directory,review['sha256'],actor='operator')
        assert acknowledge_offload(o,directory,review['sha256'],actor='operator',confirmed=True,retention_receipt=retention_receipt(o,directory,review['sha256']))['released']==len(rows)
    finally:o.db.close()


def test_offload_lifetime_crosses_a_bounded_page_without_reset(tmp_path):
    from arvyx_control import capture_offload as offload
    storage=offload.storage_identity(tmp_path);previous='';through=0
    for i in range(5):
        bundle=dict(schema=2,previous=previous,after=through,through=i+1,storage=storage,records=[dict(sequence=i+1,event_id='event-'+str(i),delivered=1)])
        raw=offload.encoded(bundle);import hashlib
        previous=hashlib.sha256(raw).hexdigest();(tmp_path/(previous+'.json')).write_bytes(raw);through=i+1
    with patch.object(offload,'MAX_CHAIN',2):
        assert len(list(offload.chain(tmp_path,previous,through=through)))==5


def test_composition_materializes_only_completed_exact_forget_links(tmp_path):
    from test_pass3_composition_recovery import topology
    from arvyx_control.composition_recovery import capture,restore
    from arvyx_control.replica_authority import authority_context
    from arvyx_control.forget import soft_forget
    t=topology(tmp_path);vault=t.root/'vault';source=vault/'projects/demo-agent/notes/note.md';source.parent.mkdir(parents=True)
    source.write_text('---\nid: synthetic-memory\nstatus: promoted\n---\n\nSynthetic retained original\n')
    original=source.read_bytes()
    with authority_context(vault):
        result=soft_forget(vault,'demo-agent',source.relative_to(vault).as_posix(),'superseded','synthetic-batch','operator','synthetic-forget-key')
        archive=vault/result.archive_path;assert archive.stat().st_nlink==2
        capture(t,tmp_path/'bundle');restore(tmp_path/'bundle',tmp_path/'candidate')
    copied=tmp_path/'candidate/vault'/result.archive_path
    assert copied.read_bytes()==original and copied.stat().st_nlink==1
    assert archive.stat().st_nlink==2 # retained original witness is untouched


def test_composition_recovers_promotions_before_inventory(tmp_path):
    from test_pass3_composition_recovery import topology
    from arvyx_control.composition_recovery import capture
    t=topology(tmp_path);seen=[]
    from arvyx_control import promotion_transaction as promotion
    with patch.object(promotion,'recover',side_effect=lambda vault:seen.append(vault)):
        capture(t,tmp_path/'bundle')
    assert seen==[t.root/t.vault]


def test_history_process_requires_effective_execution_policy(history,tmp_path):
    with patch('os.geteuid',return_value=1001),patch('os.isatty',return_value=True),patch.object(history.profile,'reserve',return_value=SimpleNamespace(release=lambda:None)),patch.object(history.profile,'assert_idle'),patch('subprocess.call',return_value=0) as process:
        with pytest.raises((ValueError,PermissionError),match='policy|mode'):
            history.launch(tmp_path,authorized=True,session_id='id-2')
        process.assert_not_called()


def test_history_host_policy_is_rechecked_after_reservation(history,tmp_path):
    from arvyx_control.local_executor import ExecutionPolicy
    policy=ExecutionPolicy(host_uid=1001,allow_host=True)
    def reserve(*a,**k):policy.allow_host=False;return SimpleNamespace(release=lambda:None)
    with patch('os.geteuid',return_value=1001),patch('os.isatty',return_value=True),patch.object(history.profile,'reserve',side_effect=reserve),patch('subprocess.call') as process:
        with pytest.raises((PermissionError,ValueError)):history.launch(tmp_path,authorized=True,session_id='id-2',execution_policy=policy,environment='host')
        process.assert_not_called()


def test_history_host_recorder_receives_held_workspace(history,tmp_path):
    from arvyx_control.local_executor import ExecutionPolicy
    policy=ExecutionPolicy(host_uid=1001,allow_host=True)
    observed=[]
    def process(argv,**kwargs):
        fd=kwargs['pass_fds'][0]
        assert os.fstat(fd).st_ino==tmp_path.stat().st_ino
        assert kwargs['cwd']=='/proc/self/fd/'+str(fd) and argv[argv.index('--in')+1]==kwargs['cwd']
        observed.append(argv);return 0
    with patch('os.geteuid',return_value=1001),patch('os.isatty',return_value=True),patch.object(history.profile,'reserve',return_value=SimpleNamespace(release=lambda:None)),patch.object(history.profile,'assert_idle'),patch('subprocess.call',side_effect=process):
        assert history.launch(tmp_path,authorized=True,session_id='id-2',execution_policy=policy,environment='host')==0
    assert len(observed)==1


def test_production_observer_membership_is_explicit_and_reopens(tmp_path):
    import hashlib
    from test_completion_fix5_E import authority
    from arvyx_control.external_presentation import load_presentation
    with authority(tmp_path) as (api,store,now):
        credential=tmp_path/'issuer.credential';credential.write_text('fixture-issuer');credential.chmod(0o600)
        spec=dict(grants=str(tmp_path/'grants.db'),work=str(tmp_path/'presentation-work.db'),credentials={
            hashlib.sha256(b'fixture-issuer').hexdigest():dict(name='issuer',role='issuer'),
            hashlib.sha256(b'fixture-observer').hexdigest():dict(name='observer',role='observer')},issuer_credential=str(credential),workspaces={},documents={},memory_selections={},tasks=['A','B'],recipients={},observers=['observer'])
        config=tmp_path/'presentation.json';config.write_text(json.dumps(spec));config.chmod(0o600)
        for i in range(2):
            with __import__('arvyx_control.replica_authority',fromlist=['authority_context']).authority_context(api.vault,api.state):presentation=load_presentation(config,vault=api.vault,state=api.state)
            assert presentation.api.observers==frozenset({'observer'});presentation.api.close();presentation.api.store.close()
        config.write_text(json.dumps(dict(spec,observers=['issuer'])))
        with pytest.raises(ValueError,match='observer'):load_presentation(config,vault=api.vault,state=api.state)


def test_offload_verification_continues_across_bounded_calls_and_reopen(tmp_path):
    from retention_fixture_helpers import retention_receipt
    from arvyx_control import capture_offload as offload
    from test_pass3_capture_offload import owner
    from arvyx_control.cockpit_archive import WorkCapture,sync_capture
    o=owner(tmp_path);directory=tmp_path/'offload';directory.mkdir()
    try:
        for i in range(6):
            stream=WorkCapture(o,'sid');stream.feed(('synthetic '+str(i)+'\n').encode());stream.finish();sync_capture(o,lambda row:row['event_id'])
            review=offload.prepare_offload(o,directory,actor='operator');offload.acknowledge_offload(o,directory,review['sha256'],actor='operator',confirmed=True,retention_receipt=retention_receipt(o,directory,review['sha256']))
        stream=WorkCapture(o,'sid');stream.feed(b'next retained row\n');stream.finish();sync_capture(o,lambda row:row['event_id'])
        before=o.db.execute('SELECT count(*) FROM work_capture').fetchone()[0]
        with patch.object(offload,'MAX_VERIFY_BUNDLES',2,create=True):
            with pytest.raises(ValueError,match='continuation'):offload.prepare_offload(o,directory,actor='operator')
            assert o.db.execute('SELECT count(*) FROM work_capture').fetchone()[0]==before
            retained=o._synthetic_retention_stores
            o.db.close();o=owner(tmp_path)
            o._synthetic_retention_stores=retained
            review=None
            for attempt in range(5):
                try:review=offload.prepare_offload(o,directory,actor='operator');break
                except ValueError as error:assert 'continuation' in str(error)
            else:pytest.fail('verification never finished')
            assert review is not None
            receipt=retention_receipt(o,directory,review['sha256'])
            for attempt in range(5):
                try:result=offload.acknowledge_offload(o,directory,review['sha256'],actor='operator',confirmed=True,retention_receipt=receipt);break
                except ValueError as error:
                    assert 'continuation' in str(error)
                    assert o.db.execute('SELECT count(*) FROM work_capture').fetchone()[0]==before
            else:pytest.fail('acknowledgement never finished')
            assert result['released']==before and len(offload.read_offload_chain(directory,result['sha256']))==7
    finally:o.db.close()
