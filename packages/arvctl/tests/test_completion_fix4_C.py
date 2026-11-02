"""Lane C: maintained admission boundaries, disposable metadata, no native launch."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from test_local_onboarding_services import services
from test_session_workspace_journey import journey, plan, commit
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.local_executor import ExecutionPolicy
from arvyx_control.native_lifecycle import NativeLifecycle, OwnerProducer


@pytest.fixture
def native_owner(journey, tmp_path):
    api, call, target, root, connect = journey
    extension = api.owners['local-owner'].extension
    owner = LocalCockpit(tmp_path/'owner', extension.vault, tmp_path/'events.jsonl', 'machine-a',
                         execution_policy=ExecutionPolicy(host_uid=os.geteuid(), allow_host=True))
    producer = OwnerProducer(owner, policy=owner.execution_policy)
    extension.native = NativeLifecycle(extension, producer)
    yield owner, producer, extension, call, target, root, connect
    owner.live.clear()  # All live entries below are harmless fixture dictionaries.
    owner.close()


def saved_session(owner, db, target, root, index, *, running=True):
    sid = 'fixture-session-'+str(index)
    owner.db.execute("INSERT INTO sessions VALUES(?,NULL,NULL,?, ?,?,NULL,'local')",
                     (sid, sid, str(root/'existing'), 'running' if running else 'stopped'))
    owner.db.execute('INSERT INTO native_bindings VALUES(?,?,?)', (sid, 'shell', sid))
    owner.db.execute('INSERT INTO lifecycle_bindings VALUES(?,?,?,?,?,?)',
                     (str(index), sid, json.dumps(target, sort_keys=True), owner.incarnation, 0, 'host'))
    result = dict(owner_session=sid, conversation=sid, tool='shell', owner_incarnation=owner.incarnation,
                  epoch=0, native_session_created=True, environment='host', status='running', target=target,
                  process_generation='synthetic-'+sid)
    db.execute("INSERT INTO native_attempts VALUES(?,?,?,?,?,'completed',?)",
               (str(index), 'fixture', '{}', '{}', 9999999999, json.dumps(result)))
    if running:owner.live[sid]=dict(fd=1,attached=False,process_generation='synthetic-'+sid)
    owner.db.commit(); db.commit()
    return result


def test_reviewed_exact_open_survives_unrelated_history_and_reopen(native_owner):
    owner, producer, ext, call, target, root, _ = native_owner
    old = saved_session(owner, ext.owner.creation.db, target, root, 0)
    for i in range(1, 106):
        saved_session(owner, ext.owner.creation.db, dict(target, agent_id='unrelated'), root, i, running=False)
    owner.live[old['owner_session']] = dict(fd=1, attached=False,process_generation=old['process_generation'])
    ext.native=NativeLifecycle(ext,producer)  # Reload persisted attempts before exact opening.
    status, result = call('native/open', dict(target=target, owner_session=old['owner_session'], confirmed=True))
    assert status == 200, result
    token = result['attachment']['attachment']
    assert owner.live[old['owner_session']]['attached'] == token
    producer.revoke()
    assert call('native/open', dict(target=target, owner_session=old['owner_session'], confirmed=True))[0] == 403


def test_native_listing_target_pagination_crosses_stopped_rows(native_owner):
    owner, _, ext, call, target, root, _ = native_owner
    expected = []
    for i in range(111):
        result = saved_session(owner, ext.owner.creation.db, target, root, i, running=i % 7 != 0)
        if i % 7: expected.append(result['owner_session'])
    for i in range(111, 216):
        saved_session(owner, ext.owner.creation.db, dict(target, agent_id='unrelated'), root, i, running=False)
    cursor = None; seen = []
    while True:
        status, page = call('native/sessions', dict(target=target, limit=13, **({'cursor':cursor} if cursor else {})))
        assert status == 200, page
        seen.extend(r['owner_session'] for r in page['items'])
        cursor = page['next_cursor']
        if cursor is None: break
    assert seen == list(reversed(expected))
    assert len(seen) == len(set(seen))
    assert call('native/sessions', dict(target=target, cursor='bad'))[0] == 400


def test_reviewed_expired_attachment_recovers_without_old_token_authority(native_owner):
    owner, _, ext, call, target, root, _ = native_owner
    proof = saved_session(owner, ext.owner.creation.db, target, root, 0)
    sid = proof['owner_session']; owner.live[sid] = dict(fd=1, attached=False,process_generation=proof['process_generation'])
    request = dict(target=target, owner_session=sid, confirmed=True)
    with patch('time.monotonic', return_value=1000):
        status, first = call('native/open', request); assert status == 200, first
    old = first['attachment']['attachment']
    def io(token, operation, fields):
        return call('native/io', dict(target=target, proof=proof, attachment=token, operation=operation, fields=fields))
    with patch('time.monotonic', return_value=1301):
        assert io(old, 'read', dict(cursor=0))[0] == 400
        assert io(old, 'send', dict(draft_id='none', sha256='none'))[0] == 400
        status, second = call('native/open', request); assert status == 200, second
        new = second['attachment']['attachment']; assert new != old
        assert io(old, 'detach', {})[0] == 400
        assert owner.live[sid]['attached'] == new
        assert io(new, 'detach', {})[0] == 200


def test_local_archive_refusal_does_not_stop_governed_work_delivery(native_owner):
    from arvyx_control.cockpit_archive import WorkCapture, pending_capture
    owner, _, ext, _, target, root, _ = native_owner
    local = saved_session(owner, ext.owner.creation.db, target, root, 0)['owner_session']
    owner.db.execute("INSERT INTO sessions VALUES('work','project','task','work',?,'stopped',NULL,'work')", (str(root/'existing'),));owner.db.commit()
    projects = owner.vault/'registry/projects';projects.mkdir(exist_ok=True)
    (projects/'project.json').write_text(json.dumps(dict(owner_agent_id='agent-a')))
    for sid in (local, 'work'): WorkCapture(owner, sid).feed(b'harmless line\n')
    receipts = {}; sent = []
    def team_call(method, path, payload=None):
        if method == 'POST':
            sent.append(payload)
            canonical = {k:v for k,v in payload.items() if k not in {'actor','idempotency_key'}}
            receipt = dict(event_id=payload['event_id'], sha256=hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest(), recorded=True)
            receipts[payload['event_id']] = receipt
            return SimpleNamespace(status=201, body=receipt)
        return SimpleNamespace(status=200, body=receipts[path.rsplit('/',1)[1]])
    owner.team = SimpleNamespace(_call=team_call)
    with patch.object(owner.archive_stop, 'wait', side_effect=[False, False, True]): owner._sync_archive()
    assert len(sent) == 1 and sent[0]['session'] == 'work'
    assert [row['session'] for row in pending_capture(owner)] == [local]
    attention = owner.db.execute('SELECT kind,reason FROM session_attention WHERE session=?', (local,)).fetchone()
    assert attention and attention['kind'] == 'archive-refused' and 'local' in attention['reason']
    assert owner.db.execute("SELECT delivered FROM work_capture WHERE session='work'").fetchone()[0] == 1


@pytest.fixture
def restart_owner(native_owner, tmp_path):
    from arvyx_control.cockpit_native_runtime import NativeRuntime
    from arvyx_control.cockpit_terminal_runner import JsonOperator
    import arvyx_control.cockpit_restart as restart
    owner, _, _, _, _, root, connect = native_owner
    executable = tmp_path/'harmless-native';executable.write_text('#!/bin/false\n');executable.chmod(0o700)
    def runtime(): return NativeRuntime(tool='hermes', executable=executable, home=connect['path'], store=Path(connect['path'])/'state.db')
    owner.native_runtimes['hermes'] = runtime()
    owner.db.execute("INSERT INTO sessions VALUES('restart',NULL,NULL,'restart',?,'running',NULL,'local')", (str(root/'existing'),))
    owner.db.execute("INSERT INTO native_bindings VALUES('restart','hermes','1204')");owner.db.commit()
    owner.operator_drivers['worker'] = JsonOperator([str(executable)], cwd=root/'existing')
    owner.delegate('restart', operator='worker', goal='approved', limits='bounded', actor='operator')
    with patch.object(restart, 'boot_id', return_value='old-boot'), patch.object(restart.time, 'time', return_value=1000):
        lease = owner.authorize_native_restart('restart', actor='operator', confirmed=True, allow_provider_restart=True, ttl=5)
    owner.db.execute("UPDATE sessions SET status='stopped' WHERE id='restart'")
    owner.db.execute("UPDATE delegations SET status='paused' WHERE session='restart'")
    owner.db.execute("INSERT INTO cleanup_ownership VALUES('restart',987654)");owner.db.commit()
    yield owner, lease, runtime


@pytest.mark.parametrize('change', ['directory', 'missing-directory-binding'])
def test_restart_profile_directory_binding_survives_owner_reopen(restart_owner, change):
    import arvyx_control.cockpit_restart as restart
    owner, lease, runtime = restart_owner
    if change == 'directory':
        home = owner.native_runtimes['hermes'].home
        old = home.with_name('old-profile');home.rename(old);home.mkdir(mode=0o700)
        (old/'state.db').rename(home/'state.db')
        owner.native_runtimes['hermes'] = runtime()
    else:
        row = owner.db.execute('SELECT payload FROM native_restart_leases').fetchone()
        saved = json.loads(row[0]);saved.pop('profile_home_identity', None)
        owner.db.execute('UPDATE native_restart_leases SET payload=?', (json.dumps(saved),));owner.db.commit()
    args=(owner.root,owner.vault,owner.state,owner.host)
    policy=owner.execution_policy;drivers=dict(owner.operator_drivers);runtimes=dict(owner.native_runtimes)
    owner.close()
    LocalCockpit.__init__(owner,*args,execution_policy=policy,driver=drivers,native_runtimes=runtimes)
    with patch.object(restart, 'boot_id', return_value='new-boot'), patch.object(restart.time, 'time', return_value=1001), patch.object(owner, 'start_native') as start:
        with pytest.raises(PermissionError): owner.resume_native_restart(lease['id'], actor='operator')
        start.assert_not_called()
    assert owner.db.execute('SELECT pid FROM cleanup_ownership').fetchone()[0] == 987654


@pytest.mark.parametrize('crossing', ['snapshot', 'state-lock', 'reservation'])
def test_restart_expiry_never_admits_fork_or_clears_cleanup(restart_owner, crossing):
    import arvyx_control.cockpit_restart as restart
    owner, lease, _ = restart_owner
    clock = [1001];original = restart.snapshot
    def snapshot(*args):
        result = original(*args)
        if crossing == 'snapshot':clock[0] = 1006
        return result
    from contextlib import contextmanager
    import arvyx_control.cockpit as cockpit
    real_lock=cockpit._locked_state
    @contextmanager
    def delayed_lock(state):
        with real_lock(state):
            if crossing=='state-lock':clock[0]=1006
            yield
    reservation = Mock()
    def reserve(*args):
        if crossing == 'reservation':clock[0] = 1006
        return reservation
    with patch.object(restart, 'boot_id', return_value='new-boot'), patch.object(restart.time, 'time', side_effect=lambda:clock[0]), patch.object(restart, 'snapshot', side_effect=snapshot), patch.object(owner.native_runtimes['hermes'], 'reserve', side_effect=reserve), patch.object(cockpit,'_locked_state',delayed_lock), patch('pty.fork', side_effect=AssertionError('expired consent reached fork')) as fork:
        with pytest.raises(PermissionError, match='expir'):owner.resume_native_restart(lease['id'], actor='operator')
        fork.assert_not_called()
    assert owner.db.execute('SELECT pid FROM cleanup_ownership').fetchone()[0] == 987654
    assert owner.db.execute('SELECT expires FROM native_restart_leases').fetchone()[0] == lease['expires_at']
    if crossing == 'reservation':reservation.release.assert_called_once()


def test_native_new_failed_publication_joins_pump_without_owner_lock(native_owner):
    owner, producer, ext, call, target, root, _ = native_owner
    import arvyx_control.cockpit as cockpit
    joined = []; released = []; pumps = []
    exec_pipe = []; real_pipe = os.pipe2
    def pipe(flags):
        pair = real_pipe(flags);exec_pipe[:] = pair;return pair
    def fork():
        os.write(exec_pipe[1], b'X')
        return 987654, os.open(root/'fixture-pty', os.O_RDONLY)
    (root/'fixture-pty').write_bytes(b'harmless')
    def pump(sid, live):
        with owner.lock: pumps.append(sid)
    real_join=threading.Thread.join
    def join(thread,timeout=None):
        joined.append(owner.lock._is_owned())
        real_join(thread,timeout=.2)
    owner.native_runtimes['shell']=SimpleNamespace(reserve=lambda conversation:SimpleNamespace(release=lambda:released.append(conversation)))
    owner.db.execute("CREATE TRIGGER fail_publication BEFORE UPDATE ON sessions WHEN NEW.status='running' BEGIN SELECT RAISE(ABORT,'synthetic running-publication failure'); END")
    owner.db.commit()
    request = dict(plan(target,'existing','existing'), environment='host', harness='shell', root_acknowledged=False)
    with patch.object(cockpit.os,'pipe2',side_effect=pipe), patch('pty.fork',side_effect=fork), patch.object(cockpit.os,'waitid',return_value=None), patch.object(owner,'_pump',side_effect=pump), patch.object(threading.Thread,'join',join), patch.object(owner,'_terminate',side_effect=lambda live:live.update(terminated=True)):
        preview = call('native/prepare', request)[1]
        status, result = call('native/commit', commit(preview))
        assert status == 503 and result['reconcile_required']
    assert joined == [False]
    assert len(pumps) == len(released) == 1
    assert owner.db.execute('SELECT count(*) FROM cleanup_ownership').fetchone()[0] == 0
    assert call('native/commit', commit(preview))[0] == 400


@pytest.mark.parametrize('operation', ['start', 'start_native'])
@pytest.mark.parametrize('selected_environment',[None,'host','root'])
def test_legacy_launch_requires_execution_policy_before_process(native_owner, operation, selected_environment):
    owner, _, ext, _, target, root, _ = native_owner
    sid = saved_session(owner, ext.owner.creation.db, target, root, 0, running=False)['owner_session']
    if operation == 'start':
        owner.db.execute('DELETE FROM native_bindings WHERE session=?', (sid,));owner.db.commit()
    else:
        owner.db.execute("UPDATE native_bindings SET tool='hermes',conversation='1204' WHERE session=?", (sid,));owner.db.commit()
        owner.native_runtimes['hermes'] = SimpleNamespace(plan=lambda *args:(['/never-exec'], {}))
    owner.execution_policy = ExecutionPolicy(host_uid=os.geteuid(), allow_host=False, allow_root=False)
    with patch.object(owner, '_start', return_value={}) as start:
        with pytest.raises(PermissionError):
            getattr(owner, operation)(sid, actor='operator',environment=selected_environment,root_acknowledged=selected_environment=='root', **({'allow_provider':True} if operation=='start_native' else {}))
        start.assert_not_called()


def test_manual_profile_review_carries_directory_identity(services):
    api, call, profile, _ = services
    status, review = call('actions/prepare', dict(action='manual/connect', request=dict(family='hermes',path=str(profile),agent_id='agent-a',confirmed=True)))
    assert status == 200, review
    info = profile.stat()
    assert review['snapshot']['home_identity'] == [info.st_dev,info.st_ino]


@pytest.mark.parametrize('mutation', ['epoch','incarnation','binding','policy'])
def test_native_new_rechecks_authority_after_state_lock_wait(native_owner, mutation):
    from contextlib import contextmanager
    import arvyx_control.cockpit as cockpit
    owner, _, _, call, target, root, _ = native_owner
    request = dict(plan(target,'existing','existing'), environment='host', harness='shell', root_acknowledged=False)
    preview = call('native/prepare', request)[1]
    original=cockpit._locked_state
    @contextmanager
    def delayed(state):
        with original(state):
            if mutation=='epoch':owner.db.execute('UPDATE lifecycle_policy SET epoch=epoch+1')
            elif mutation=='incarnation':owner.incarnation='replacement'
            elif mutation=='binding':owner.db.execute("UPDATE native_bindings SET conversation='replacement'")
            else:owner.execution_policy=ExecutionPolicy(host_uid=os.geteuid())
            owner.db.commit()
            yield
    with patch.object(cockpit,'_locked_state',delayed), patch('pty.fork') as fork:
        status,result=call('native/commit',commit(preview))
        assert status==503 and result['reconcile_required']
        fork.assert_not_called()
    assert call('native/commit',commit(preview))[0]==400


def test_expired_attachment_concurrent_recovery_issues_one_token(native_owner):
    owner, producer, ext, _, target, root, _ = native_owner
    proof=saved_session(owner,ext.owner.creation.db,target,root,0)
    sid=proof['owner_session'];owner.live[sid]=dict(fd=1,attached='expired',attachment_deadline=0,process_generation=proof['process_generation'])
    start=threading.Barrier(3);tokens=[];errors=[]
    def attach():
        start.wait()
        try:tokens.append(producer.attach(proof,target)['attachment'])
        except ValueError as exc:errors.append(str(exc))
    threads=[threading.Thread(target=attach) for _ in range(2)]
    for thread in threads:thread.start()
    start.wait()
    for thread in threads:thread.join(timeout=3);assert not thread.is_alive()
    assert len(tokens)==len(errors)==1
    assert owner.live[sid]['attached']==tokens[0]
    with pytest.raises(ValueError):owner.detach(sid,actor='operator',attachment='expired')
    assert owner.live[sid]['attached']==tokens[0]


@pytest.mark.parametrize('mode', ['host','root','sandbox'])
@pytest.mark.parametrize('operation',['start','start_native'])
def test_legacy_socket_dispatch_preserves_execution_mode(native_owner, tmp_path, mode, operation):
    from arvyx_control.cockpit import handle_connection
    owner, _, ext, _, target, root, _ = native_owner
    sid=saved_session(owner,ext.owner.creation.db,target,root,0,running=False)['owner_session']
    if operation=='start':owner.db.execute('DELETE FROM native_bindings WHERE session=?',(sid,))
    else:
        owner.db.execute("UPDATE native_bindings SET tool='hermes',conversation='1204' WHERE session=?",(sid,))
        owner.native_runtimes['hermes']=SimpleNamespace(plan=lambda *args:(['/never-executed','--resume','1204'],{}))
    owner.db.commit()
    launcher=tmp_path/'bwrap';launcher.write_bytes(b'harmless launcher bytes');launcher.chmod(0o700)
    uid=0 if mode=='root' else 1000
    with patch('os.geteuid',return_value=uid):
        owner.execution_policy=ExecutionPolicy(host_uid=1000,allow_host=True,allow_root=True,sandbox_launcher=launcher,sandbox_fd_protocol='arvyx-directory-fd-v1')
        frames=[]
        def invoke(**fields):
            raw=json.dumps(dict(operation=operation,sid=sid,actor='operator',**({'allow_provider':True} if operation=='start_native' else {}),**fields)).encode()
            with patch('arvyx_control.cockpit_client.receive_frame',return_value=raw),patch('arvyx_control.cockpit_client.send_frame',side_effect=lambda client,payload,*rest:frames.append(json.loads(payload))):
                handle_connection(object(),owner,owner)
            return frames[-1]
        with patch.object(owner,'_start',return_value={}) as process:
            assert invoke()['ok'] is False;process.assert_not_called()
            if mode=='root':
                assert invoke(environment=mode)['ok'] is False;process.assert_not_called()
            if operation=='start_native' and mode=='sandbox':
                response=invoke(environment=mode)
                assert response['ok'] is False and 'provider sandbox' in response['error'];process.assert_not_called()
                return
            import fcntl
            if mode=='sandbox' and not hasattr(fcntl,'F_ADD_SEALS'):
                response=invoke(environment=mode,root_acknowledged=False)
                assert response['ok'] is False and 'sealing' in response['error'];process.assert_not_called()
                return
            assert invoke(environment=mode,root_acknowledged=mode=='root')['ok'] is True
            argv=process.call_args.kwargs['argv']
            if operation=='start_native':assert argv==['/never-executed','--resume','1204']
            else:assert argv[-2:]==['/bin/sh','-i']
            if mode=='sandbox':assert argv[0].startswith('/proc/self/fd/') and '--unshare-all' in argv


@pytest.mark.parametrize('crossing', ['pipe','unexpired'])
def test_restart_final_boundary_and_single_use(restart_owner, crossing):
    import arvyx_control.cockpit_restart as restart
    owner,lease,_=restart_owner;clock=[1001];real_pipe=os.pipe2
    def pipe(flags):
        pair=real_pipe(flags)
        if crossing=='pipe':clock[0]=1006
        return pair
    class ProcessBoundaryObserved(Exception):pass
    with patch.object(restart,'boot_id',return_value='new-boot'),patch.object(restart.time,'time',side_effect=lambda:clock[0]),patch.object(owner.native_runtimes['hermes'],'reserve',return_value=Mock()),patch('os.pipe2',side_effect=pipe),patch('pty.fork',side_effect=ProcessBoundaryObserved) as fork:
        if crossing=='pipe':
            with pytest.raises(PermissionError,match='expir'):owner.resume_native_restart(lease['id'],actor='operator')
            fork.assert_not_called()
        else:
            with pytest.raises(ProcessBoundaryObserved):owner.resume_native_restart(lease['id'],actor='operator')
            fork.assert_called_once()
        with pytest.raises(PermissionError):owner.resume_native_restart(lease['id'],actor='operator')
        assert fork.call_count==(crossing=='unexpired')
    assert owner.db.execute('SELECT pid FROM cleanup_ownership').fetchone()[0]==987654
    assert owner.db.execute('SELECT expires FROM native_restart_leases').fetchone()[0]==lease['expires_at']


def test_native_new_preserves_reviewed_executable_through_lock_wait(native_owner, tmp_path):
    from contextlib import contextmanager
    import arvyx_control.cockpit as cockpit
    from arvyx_control.cockpit_native_runtime import NativeRuntime
    owner, _, _, call, target, root, connect = native_owner
    exe=tmp_path/'hermes';exe.write_bytes(b'original harmless bytes');exe.chmod(0o700)
    runtime=NativeRuntime(tool='hermes',executable=exe,home=connect['path'],store=Path(connect['path'])/'state.db',new_protocol='hermes-titled-create-v1')
    owner.native_runtimes['hermes']=runtime
    request=dict(plan(target,'existing','existing'),environment='host',harness='hermes',root_acknowledged=False,provider_start_acknowledged=True)
    status,review=call('native/prepare',request);assert status==200,review
    real=cockpit._locked_state
    @contextmanager
    def delayed(state):
        with real(state):
            exe.write_bytes(b'replacement harmless bytes')
            yield
    with patch.object(cockpit,'_locked_state',delayed),patch.object(runtime,'reserve',return_value=Mock()),patch('pty.fork',side_effect=AssertionError('changed executable admitted')) as fork:
        status,result=call('native/commit',commit(review))
        assert status==503 and result['reconcile_required']
        fork.assert_not_called()


def test_sandbox_without_kernel_sealing_returns_typed_refusal(tmp_path, monkeypatch):
    import fcntl
    launcher=tmp_path/'bwrap';launcher.write_bytes(b'harmless launcher');launcher.chmod(0o700)
    with patch('os.geteuid',return_value=1000):
        policy=ExecutionPolicy(host_uid=1000,sandbox_launcher=launcher,sandbox_fd_protocol='arvyx-directory-fd-v1')
        plan=policy.plan('sandbox',tmp_path)
    monkeypatch.delattr(fcntl,'F_ADD_SEALS',raising=False)
    from arvyx_control.external_workspace import _open_root
    with _open_root(tmp_path) as fd, pytest.raises(PermissionError,match='sealing'):
        with policy.sealed_launcher(plan,workspace_fd=fd):pytest.fail('unsealed sandbox admitted')


@pytest.mark.parametrize('workspace_mode',['existing','create'])
def test_native_new_retains_reviewed_identity_and_successful_ack(native_owner,tmp_path,workspace_mode):
    from arvyx_control.cockpit_native_runtime import NativeRuntime
    owner, _, _, call, target, root, connect = native_owner
    exe=tmp_path/'hermes';exe.write_bytes(b'harmless executable');exe.chmod(0o700)
    owner.native_runtimes['hermes']=NativeRuntime(tool='hermes',executable=exe,home=connect['path'],store=Path(connect['path'])/'state.db',new_protocol='hermes-titled-create-v1')
    request=dict(plan(target,workspace_mode,'fresh' if workspace_mode=='create' else 'existing'),environment='host',harness='hermes',root_acknowledged=False,provider_start_acknowledged=True)
    effects=[]
    def process(sid,**fields):
        # Only substitute process creation; run the exact production admission.
        fields['admission']()
        marker=fields['argv'][fields['argv'].index('-c')+1]
        with sqlite3.connect(Path(connect['path'])/'state.db') as db:
            db.execute('INSERT INTO sessions(id,title,started_at,cwd) VALUES(?,?,1,?)',('acknowledged-native-id',marker,owner._get(sid)['workspace']))
        owner.db.execute("UPDATE sessions SET status='running' WHERE id=?",(sid,));owner.db.commit();effects.append(sid)
        owner.live[sid]=dict(fd=1,attached=False,process_generation='synthetic-'+sid)
    with patch.object(owner,'_start',side_effect=process):
        status,review=call('native/prepare',request);assert status==200,review
        status,result=call('native/commit',commit(review));assert status==201,result
        assert len(effects)==1 and result['conversation']=='acknowledged-native-id'
        assert call('native/commit',commit(review))[0]==400


def test_restart_expiry_with_failed_release_retains_original_cleanup(restart_owner):
    import arvyx_control.cockpit_restart as restart
    owner,lease,_=restart_owner;clock=[1001];real_pipe=os.pipe2
    reservation=Mock();reservation.release.side_effect=OSError('synthetic reservation release barrier')
    def pipe(flags):
        pair=real_pipe(flags);clock[0]=1006;return pair
    with patch.object(restart,'boot_id',return_value='new-boot'),patch.object(restart.time,'time',side_effect=lambda:clock[0]),patch.object(owner.native_runtimes['hermes'],'reserve',return_value=reservation),patch('os.pipe2',side_effect=pipe),patch('pty.fork') as fork:
        with pytest.raises(OSError,match='release barrier'):owner.resume_native_restart(lease['id'],actor='operator')
        fork.assert_not_called()
    assert owner.db.execute('SELECT pid FROM cleanup_ownership').fetchone()[0]==987654
    assert owner.db.execute('SELECT status FROM native_restart_leases').fetchone()[0]=='ambiguous'


@pytest.mark.parametrize('mutation',['epoch','incarnation','delegation'])
def test_restart_result_cannot_reactivate_changed_authority(restart_owner, mutation):
    import arvyx_control.cockpit_restart as restart
    owner,lease,_=restart_owner
    def process(*args,**fields):
        if mutation=='epoch':owner.db.execute('UPDATE lifecycle_policy SET epoch=epoch+1')
        elif mutation=='incarnation':owner.incarnation='replacement-owner'
        else:owner.db.execute("UPDATE delegations SET status='revoked' WHERE session='restart'")
        owner.db.commit()
    with patch.object(restart,'boot_id',return_value='new-boot'),patch.object(restart.time,'time',return_value=1001),patch.object(owner,'start_native',side_effect=process) as start:
        with pytest.raises(PermissionError):owner.resume_native_restart(lease['id'],actor='operator')
        start.assert_called_once()
        with pytest.raises(PermissionError):owner.resume_native_restart(lease['id'],actor='operator')
    assert owner.db.execute('SELECT status FROM delegations').fetchone()[0]!='active'
    assert owner.db.execute('SELECT status FROM native_restart_leases').fetchone()[0]=='ambiguous'


def test_restart_unchanged_profile_reopen_completes_once(restart_owner):
    import arvyx_control.cockpit_restart as restart
    owner,lease,runtime=restart_owner
    args=(owner.root,owner.vault,owner.state,owner.host)
    policy=owner.execution_policy;drivers=dict(owner.operator_drivers)
    owner.close();LocalCockpit.__init__(owner,*args,execution_policy=policy,driver=drivers,native_runtimes={'hermes':runtime()})
    def process(*args,**fields):
        assert not owner.lock._is_owned()
        fields['_restart_admission']()
    with patch.object(restart,'boot_id',return_value='new-boot'),patch.object(restart.time,'time',return_value=1001),patch.object(owner,'start_native',side_effect=process) as start:
        result=owner.resume_native_restart(lease['id'],actor='operator')
        assert result['status']=='active' and result['expires_at']==lease['expires_at']
        assert result['input_replayed'] is False
        with pytest.raises(PermissionError):owner.resume_native_restart(lease['id'],actor='operator')
        start.assert_called_once()
    assert owner.db.execute('SELECT status FROM native_restart_leases').fetchone()[0]=='completed'


# Integrator: exercise actual legacy CLI parsing without launching an owner/process.
@pytest.mark.parametrize('command', ['start', 'new', 'native'])
@pytest.mark.parametrize('mode', ['sandbox', 'host', 'root'])
def test_legacy_cli_forwards_explicit_mode_and_ack(tmp_path, command, mode):
    from arvyx_control import cockpit_client as cli
    root=tmp_path/'pilot';root.mkdir(mode=0o700);(root/'pilot.json').write_text('{}')
    args=['pilot', '--home', str(root), command]
    args+=['resume','sid','--allow-provider'] if command=='native' else ['name','--title','explicit'] if command=='new' else ['sid']
    args+=['--environment',mode]
    if mode=='root':args+=['--root-acknowledged']
    calls=[]
    def request(home, operation, **fields):
        calls.append((operation,fields));return [] if operation=='list' else dict(id='sid')
    with patch.object(cli,'initialize',return_value=dict(host='test',project='demo-agent')), patch.object(cli,'request',side_effect=request), patch.object(cli,'create_task',return_value=SimpleNamespace(task=SimpleNamespace(id='task'))), patch('sys.argv',args):
        cli.main()
    operation, fields=calls[-1]
    assert operation==('start_native' if command=='native' else 'start')
    assert fields['environment']==mode and fields['root_acknowledged']==(mode=='root')


@pytest.mark.parametrize('command', ['start','new','native'])
def test_legacy_cli_missing_mode_refuses_before_any_effect(tmp_path,command):
    from arvyx_control import cockpit_client as cli
    root=tmp_path/'pilot';root.mkdir(mode=0o700);(root/'pilot.json').write_text('{}')
    args=['pilot','--home',str(root),command]
    args+=['resume','sid'] if command=='native' else ['name','--title','explicit'] if command=='new' else ['sid']
    with patch.object(cli,'initialize',return_value={}),patch.object(cli,'request') as effect,patch.object(cli,'create_task') as task,patch('sys.argv',args):
        with pytest.raises(SystemExit):cli.main()
        effect.assert_not_called();task.assert_not_called()


def test_pilot_serve_passes_only_explicit_policy(tmp_path):
    from arvyx_control import cockpit_client as cli
    root=tmp_path/'pilot';root.mkdir(mode=0o700);(root/'pilot.json').write_text('{}')
    policy=tmp_path/'policy.json';policy.write_text('{}');policy.chmod(0o600)
    with patch.object(cli,'initialize',return_value=dict(host='test')),patch('arvyx_control.cockpit.main') as serve,patch('sys.argv',['pilot','--home',str(root),'serve','--execution-policy',str(policy)]):
        cli.main();serve.assert_called_once()
        import sys
        assert sys.argv[sys.argv.index('--execution-policy')+1]==str(policy)
