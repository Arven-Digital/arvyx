"""Disposable owner integration; recorder substitutes ONLY the process boundary."""
from contextlib import closing
import json,sqlite3
from pathlib import Path
from unittest.mock import patch
import pytest
from test_session_workspace_journey import journey, plan, commit
from test_local_onboarding_services import services
import os

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='the native runtime (Linux x86_64 artifact, host-shell policies) is POSIX-only')


def test_effective_executor_modes_never_collapse(tmp_path):
    from arvyx_control.local_executor import ExecutionPolicy
    workspace=tmp_path/'work';workspace.mkdir()
    with patch('os.geteuid',return_value=1000):
        policy=ExecutionPolicy(host_uid=1000,allow_host=True,allow_root=False)
        host=policy.plan('host',workspace,root_acknowledged=False)
        assert host.argv==('/bin/sh','-i') and host.uid==1000
        with pytest.raises(PermissionError):policy.plan('root',workspace,root_acknowledged=True)
        with pytest.raises(PermissionError):policy.plan('sandbox',workspace,root_acknowledged=False)
    launcher=tmp_path/'bwrap';launcher.write_text('fake inspected executable');launcher.chmod(0o700)
    with patch('os.geteuid',return_value=1000):
        sandbox=ExecutionPolicy(host_uid=1000,sandbox_launcher=launcher,sandbox_fd_protocol='arvyx-directory-fd-v1').plan('sandbox',workspace)
        assert sandbox.argv[0]==str(launcher) and '--unshare-all' in sandbox.argv
        assert '--ro-bind' in sandbox.argv and '--die-with-parent' in sandbox.argv
        assert sandbox.argv[-2:]==('/bin/sh','-i') and sandbox.mode=='sandbox'
    with patch('os.geteuid',return_value=0):
        policy=ExecutionPolicy(host_uid=1000,allow_host=True,allow_root=True)
        with pytest.raises(PermissionError):policy.plan('host',workspace)
        with pytest.raises(PermissionError):policy.plan('root',workspace)
        assert policy.plan('root',workspace,root_acknowledged=True).uid==0


@pytest.mark.parametrize('workspace_mode',['existing','current','create'])
def test_new_owner_binding_and_single_use_review(journey,tmp_path,workspace_mode):
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control.native_lifecycle import OwnerProducer,NativeLifecycle
    from arvyx_control.local_executor import ExecutionPolicy
    api,call,target,root,_=journey
    extension=api.owners['local-owner'].extension
    owner=LocalCockpit(tmp_path/'owner',extension.vault,tmp_path/'events.jsonl','machine-a')
    recorder=[]
    def process(sid,**kwargs):
        recorder.append((sid,kwargs['argv']))
        owner.db.execute("UPDATE sessions SET status='running',pid=12345 WHERE id=?",(sid,));owner.db.commit()
        owner.live[sid]=dict(fd=1,attached=False,process_generation='synthetic-'+sid)
        return owner._get(sid)
    producer=OwnerProducer(owner,policy=ExecutionPolicy(host_uid=__import__('os').geteuid(),allow_host=True))
    extension.native=NativeLifecycle(extension,producer)
    selected_path='fresh' if workspace_mode=='create' else 'existing'
    request=dict(plan(target,workspace_mode,selected_path),environment='host',harness='shell',root_acknowledged=False)
    with patch.object(owner,'_start',side_effect=process):
        status,review=call('native/prepare',request);assert status==200,review
        assert recorder==[]
        status,result=call('native/commit',commit(review));assert status==201,result
        assert len(recorder)==1 and recorder[0][1]==['/bin/sh','-i']
        assert result['native_session_created'] and result['owner_incarnation']==owner.incarnation
        sid=result['owner_session'];assert owner._get(sid)['workspace']==str(root/selected_path)
        assert owner.native(sid,actor='operator')['conversation']==result['conversation']
        assert call('native/commit',commit(review))[0]==400
        assert call('native/sessions',dict(target=target))[1]['items'][0]['owner_session']==sid
        producer.revoke()
        assert call('native/open',dict(target=target,owner_session=sid,confirmed=True))[0] in (400,403,409)
    owner.live.clear()  # Synthetic process recorder only; no real descriptor/PID.
    owner.close()


def test_lost_ack_reopen_and_incarnation_refuse_replay(journey,tmp_path):
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control.native_lifecycle import OwnerProducer,NativeLifecycle
    from arvyx_control.local_executor import ExecutionPolicy
    api,call,target,root,_=journey;extension=api.owners['local-owner'].extension
    owner=LocalCockpit(tmp_path/'owner',extension.vault,tmp_path/'events.jsonl','machine-a')
    producer=OwnerProducer(owner,policy=ExecutionPolicy(host_uid=__import__('os').geteuid(),allow_host=True))
    extension.native=NativeLifecycle(extension,producer)
    req=dict(plan(target,'existing','existing'),environment='host',harness='shell',root_acknowledged=False)
    review=call('native/prepare',req)[1]
    with patch.object(owner,'_start',side_effect=OSError('lost ack')) as process:
        assert call('native/commit',commit(review))[0]==503
        assert process.call_count==1
    extension.native=NativeLifecycle(extension,producer)
    assert call('native/commit',commit(review))[0]==400
    assert len(owner.list())==1 # persisted real owner binding precedes effect
    review=call('native/prepare',req)[1];owner.incarnation='changed-owner'
    with patch.object(owner,'_start') as process:
        assert call('native/commit',commit(review))[0] in (400,403,409);process.assert_not_called()
    owner.live.clear()  # Synthetic process recorder only; no real descriptor/PID.
    owner.close()


def test_independently_authenticated_leaf_creates_only_closed_shell_action(journey,tmp_path):
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control.native_lifecycle import OwnerProducer
    from arvyx_control.local_executor import ExecutionPolicy
    from arvyx_control.local_executor_service import LocalExecutorService
    from arvyx_control.organizer_authority import OrganizerAuthority
    from arvyx_control.replica_authority import authority_context
    from delegation_fixture_helpers import issue
    from contextlib import ExitStack
    api,call,target,root,_=journey;extension=api.owners['local-owner'].extension
    database=tmp_path/'authority.sqlite'
    with authority_context(extension.vault):
        policy=OrganizerAuthority(database=database)
        actor=policy.provision_identity('organizer',kind='internal',organizer=True)
        worker=policy.provision_identity('agent-a',kind='internal')
        policy.enroll_machine('machine-a');policy.bind_agent(worker,machine='machine-a')
        policy.bind_executor(worker,machine='machine-a',environments=['host'])
    owner=LocalCockpit(tmp_path/'owner',extension.vault,tmp_path/'events.jsonl','machine-a',delegation_authority_database=database)
    producer=OwnerProducer(owner,policy=ExecutionPolicy(host_uid=__import__('os').geteuid(),allow_host=True))
    leaf=LocalExecutorService(tmp_path/'leaf.db',credential='x'*48,producer=producer,target=target,session='leaf-lease-a',workspace=root/'existing',environments=['host'],identity_store=Path(extension.owner.creation.db.execute('PRAGMA database_list').fetchone()[2]),authority_database=database)
    with authority_context(owner.vault,owner.state):
        request=issue(policy,actor,worker,dict(machine='machine-a',executing_agent='agent-a',session='leaf-lease-a',operation='invoke_host',environment='host',goal='new-local-shell'),receiving_leaf=leaf.receiving_leaf)
    def call(body,auth='x'*48):return leaf.dispatch('POST','/api/public-onboarding/executor/execute','Bearer '+auth,body)
    def process(sid,**kwargs):
        assert kwargs['argv']==['/bin/sh','-i']
        with kwargs['effect_guard']() as check:
            kwargs['admission']();check()
            owner.db.execute("UPDATE sessions SET status='running',pid=12345 WHERE id=?",(sid,));owner.db.commit()
        owner.live[sid]=dict(fd=1,attached=False,process_generation='synthetic-'+sid)
    with patch.object(owner,'_start',side_effect=process) as recorder:
        assert call(request,auth='browser-test')[0]==401
        assert call({k:v for k,v in request.items() if k!='delegation_fence'})[0]==400
        assert call(dict(request,goal='run any provider'))[0]==403
        assert call(request)[0]==200 and recorder.call_count==1
        assert call(request)[0]==400 and recorder.call_count==1
        producer.revoke()
        assert call(dict(request,request_id='b'*32))[0]==403
    owner.live.clear()  # Synthetic recorder created no real process.
    leaf.close();owner.close();policy.close()


def test_hermes_new_uses_confirmed_native_producer_id_not_workspace_id(journey,tmp_path):
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control.cockpit_native_runtime import NativeRuntime
    from arvyx_control.native_lifecycle import NativeLifecycle,OwnerProducer
    from arvyx_control.local_executor import ExecutionPolicy
    api,call,target,root,connect=journey;extension=api.owners['local-owner'].extension
    exe=tmp_path/'hermes';exe.write_text('#!/bin/false\n');exe.chmod(0o700)
    runtime=NativeRuntime(tool='hermes',executable=exe,home=connect['path'],store=Path(connect['path'])/'state.db',new_protocol='hermes-titled-create-v1')
    owner=LocalCockpit(tmp_path/'owner',extension.vault,tmp_path/'events.jsonl','machine-a',native_runtimes={'hermes':runtime})
    extension.native=NativeLifecycle(extension,OwnerProducer(owner,policy=ExecutionPolicy(host_uid=__import__('os').geteuid(),allow_host=True)))
    req=dict(plan(target,'existing','existing'),environment='host',harness='hermes',root_acknowledged=False,provider_start_acknowledged=True)
    def process(sid,**kwargs):
        argv=kwargs['argv'];assert argv[0]==str(exe) and '--create-if-missing' in argv
        title=argv[argv.index('-c')+1]
        with closing(sqlite3.connect(Path(connect['path'])/'state.db')) as db, db:
            db.execute('INSERT INTO sessions(id,title,started_at,cwd) VALUES(?,?,?,?)',('harness-created-immutable-id',title,2000,str(root/'existing')))
        owner.db.execute("UPDATE sessions SET status='running',pid=12345 WHERE id=?",(sid,));owner.db.commit()
        owner.live[sid]=dict(fd=1,attached=False,process_generation='synthetic-'+sid)
    with patch.object(owner,'_start',side_effect=process) as recorder:
        status,review=call('native/prepare',dict(req,provider_start_acknowledged=False));assert status in (400,403)
        status,review=call('native/prepare',req);assert status==200,review
        assert recorder.call_count==0
        status,result=call('native/commit',commit(review));assert status==201,result
        assert result['conversation']=='harness-created-immutable-id' and result['owner_session']!=result['conversation']
        assert owner.native(result['owner_session'],actor='operator')['conversation']==result['conversation']
        assert call('native/commit',commit(review))[0]==400
    owner.live.clear()  # Synthetic process recorder only; no real descriptor/PID.
    owner.close()


def test_existing_hermes_attach_uses_durable_review_and_exact_owner_lease(journey,tmp_path):
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control.cockpit_native_runtime import NativeRuntime
    from arvyx_control.native_lifecycle import NativeLifecycle,OwnerProducer
    from arvyx_control.local_executor import ExecutionPolicy
    api,call,target,root,connect=journey;extension=api.owners['local-owner'].extension
    exe=tmp_path/'hermes';exe.write_text('#!/bin/false\n');exe.chmod(0o700)
    runtime=NativeRuntime(tool='hermes',executable=exe,home=connect['path'],store=Path(connect['path'])/'state.db')
    owner=LocalCockpit(tmp_path/'owner',extension.vault,tmp_path/'events.jsonl','machine-a',native_runtimes={'hermes':runtime})
    owner.db.execute("INSERT INTO sessions VALUES('owner-sid',NULL,NULL,'existing-hermes',?,'running',12345,'organizer')",(str(root/'existing'),))
    owner.db.execute("INSERT INTO native_bindings VALUES('owner-sid','hermes','1204')")
    owner.db.execute("INSERT INTO native_organizers VALUES('agent-a','owner-sid')");owner.db.commit()
    owner.live['owner-sid']={'process_generation':'synthetic-owner-sid'}
    extension.native=NativeLifecycle(extension,OwnerProducer(owner,policy=ExecutionPolicy(host_uid=__import__('os').geteuid(),allow_host=True)))
    with patch.object(owner,'attach',return_value=dict(attachment='disposable-lease')) as attachment:
        status,result=call('native/attach',dict(target=target,session_id='1204',confirmed=True));assert status==200,result
        attachment.assert_called_once()
        assert attachment.call_args.args==('owner-sid',)
        assert attachment.call_args.kwargs['actor']=='operator'
        recorded_expiry=extension.owner.creation.db.execute("SELECT expires FROM reviewed_actions WHERE action='native/attach'").fetchone()[0]
        assert attachment.call_args.kwargs['consent_expires_at']==recorded_expiry
        assert result['conversation']=='1204'
        assert 'disposable-lease' not in extension.owner.creation.db.execute("SELECT result FROM reviewed_actions WHERE action='native/attach'").fetchone()[0]
        assert call('native/attach',dict(target=target,session_id='1203',confirmed=True))[0]==403
    owner.live.clear();owner.close()


def test_expired_live_attachment_cannot_supply_input_or_renew_itself():
    from arvyx_control.cockpit import LocalCockpit
    with pytest.raises(ValueError,match='expired'):
        LocalCockpit._attachment(dict(attached='exact-lease',attachment_deadline=0),'exact-lease')


def test_owner_change_after_durable_review_never_revokes_replacement(journey,tmp_path):
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control.native_lifecycle import NativeLifecycle,OwnerProducer
    from arvyx_control.local_executor import ExecutionPolicy
    api,call,target,root,_=journey;extension=api.owners['local-owner'].extension
    owner=LocalCockpit(tmp_path/'owner',extension.vault,tmp_path/'events.jsonl','machine-a')
    extension.native=NativeLifecycle(extension,OwnerProducer(owner,policy=ExecutionPolicy(host_uid=__import__('os').geteuid(),allow_host=True)))
    status,review=call('actions/prepare',dict(action='native/revoke',request=dict(confirmed=True)));assert status==200
    original=owner.native_lifecycle
    def replacement(**fields):
        if fields['action']=='revoke':owner.incarnation='replacement-owner'
        return original(**fields)
    with patch.object(owner,'native_lifecycle',side_effect=replacement):
        status,result=call('actions/commit',commit(review));assert status==503 and result['reconcile_required']
    assert owner.db.execute('SELECT epoch FROM lifecycle_policy').fetchone()[0]==0
    assert call('actions/commit',commit(review))[0]==400
    owner.live.clear()  # Synthetic process recorder only; no real descriptor/PID.
    owner.close()
