from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from test_hermes_history import history
import os

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='the native runtime (Linux x86_64 artifact, host-shell policies) is POSIX-only')


def test_delayed_native_inspection_never_dispatches_attachment():
    from arvyx_control.cockpit_arvyx import bridge
    clock=[100.0];calls=[]
    proof=dict(owner_session='synthetic',owner_incarnation='boot',epoch=1)
    def request(home,op,**fields):
        calls.append((op,fields))
        if fields.get('action')=='inspect':
            clock[0]=201.0
            return dict(incarnation='boot',epoch=1)
        return []
    with patch('time.time',side_effect=lambda:clock[0]),patch('arvyx_control.cockpit_client.request',request),patch('arvyx_control.cockpit_client.attach') as attach,patch('arvyx_control.cockpit_arvyx.pane_binding'):
        with pytest.raises(ValueError,match='expired'):
            bridge(Path('/synthetic'), 'synthetic',proof=proof,target={},consent_expires_at=200.0)
    assert not any(fields.get('action')=='attach' for _,fields in calls)
    attach.assert_not_called()


@pytest.mark.parametrize('session_id',[None,'id-2'])
@pytest.mark.parametrize('mode,allow_host,allow_root,ack',[
    (None,True,True,True),('host',False,False,False),
    ('root',False,True,False),('sandbox',False,False,False)])
def test_history_new_and_resume_denials_never_dispatch(history,tmp_path,session_id,mode,allow_host,allow_root,ack):
    from arvyx_control.local_executor import ExecutionPolicy
    policy=ExecutionPolicy(host_uid=1001,allow_host=allow_host,allow_root=allow_root)
    # The refusal matrix must not depend on an installed provider executable.
    history.executable='/synthetic/not-executed-hermes'
    uid=0 if mode=='root' else 1001
    with patch('os.geteuid',return_value=uid),patch('os.isatty',return_value=True),patch('subprocess.call') as process,patch.object(history.profile,'reserve') as reserve:
        with pytest.raises((PermissionError,ValueError)):
            history.launch(tmp_path,authorized=True,session_id=session_id,execution_policy=policy,environment=mode,root_acknowledged=ack)
    process.assert_not_called();reserve.assert_not_called()


def test_named_new_requires_policy_before_profile_publication(history,tmp_path):
    from arvyx_control.terminal_sessions import history_menu
    (tmp_path/'.hermes').mkdir(mode=0o700)
    # Keep even constructor path resolution inside this fixture's owned tree.
    with patch('pathlib.Path.home',return_value=tmp_path),patch('builtins.input',side_effect=['new','NEW synthetic','quit']),patch('arvyx_control.hermes_profile_launch.NewHermesProfile.prepare') as prepare:
        assert history_menu(history.home,workspace=tmp_path,new_profile='synthetic',authorize_launch=True)==0
    prepare.assert_not_called()


def test_retained_lifetime_reopen_relocation_and_local_recovery(tmp_path):
    from test_pass3_capture_offload import owner
    from retention_fixture_helpers import retention_receipt
    from arvyx_control import capture_offload as offload
    from arvyx_control.capture_offload_verify import OffloadContinuationRequired
    from arvyx_control.cockpit_archive import WorkCapture,sync_capture
    local=lambda sid:{'id':sid,'kind':'local'} # local-only session: shared export permanently refused
    o=owner(tmp_path);o._get=local;directory=tmp_path/'cache';directory.mkdir()
    expected=[]
    def complete(effect):
        for _ in range(32):
            try:return effect()
            except OffloadContinuationRequired:pass
        pytest.fail('bounded continuation failed to complete')
    try:
        with patch.object(offload,'MAX_CHAIN',2),patch.object(offload,'MAX_VERIFY_BUNDLES',2):
            for index in range(6):
                text='synthetic local '+str(index)+'\n';expected.append(text)
                stream=WorkCapture(o,'sid');stream.feed(text.encode());stream.finish()
                # No sink acknowledgement is invented for local-only records.
                assert all(row[0]==0 for row in o.db.execute('SELECT delivered FROM work_capture'))
                review=complete(lambda:offload.prepare_offload(o,directory,actor='operator',acknowledgement='local-archive'))
                receipt=retention_receipt(o,directory,review['sha256'])
                complete(lambda:offload.acknowledge_offload(o,directory,review['sha256'],actor='operator',confirmed=True,retention_receipt=receipt))
                assert o.db.execute('SELECT count(*) FROM work_capture').fetchone()[0]==0
                if index==2:
                    fixtures=o._synthetic_retention_stores;o.db.close();o=owner(tmp_path);o._get=local;o._synthetic_retention_stores=fixtures
                    target=tmp_path/'target';target.mkdir()
                    retained=retention_receipt(o,target,review['sha256'],kind='relocate',retained_source=directory)
                    complete(lambda:offload.relocate_offload_storage(o,target,actor='operator',expected_head=review['sha256'],confirmed=True,copy_from_bound=True,retention_receipt=retained))
                    directory=target
            rows=offload.read_offload_chain(directory,review['sha256'])
            assert [row['text'] for row in rows]==expected
            assert all(row['delivered']==0 for row in rows)
            # Capture still advances after more than the historical budget.
            stream=WorkCapture(o,'sid');stream.feed(b'subsequent local output\n');stream.finish()
            assert o.db.execute('SELECT count(*) FROM work_capture').fetchone()[0]>0
    finally:o.db.close()


# REV-0547 branch-level regression through the real history menu. Only the
# provider process boundary (a recorder), the effective UID, TTY detection and
# live-writer reservation are substituted; policy admission runs unchanged.
_HISTORY_DENIALS = {
    'missing-policy': (None, 'host', 1001, False),
    'missing-mode': (dict(host_uid=1001, allow_host=True), None, 1001, False),
    'denied-host': (dict(host_uid=1001, allow_host=False), 'host', 1001, False),
    'host-uid-mismatch': (dict(host_uid=1001, allow_host=True), 'host', 1002, False),
    'unacknowledged-root': (dict(host_uid=1001, allow_root=True), 'root', 0, False),
    'root-not-allowed': (dict(host_uid=1001, allow_root=False), 'root', 0, True),
    'sandbox-no-host-fallback': (dict(host_uid=1001, allow_host=True), 'sandbox', 1001, False),
}
_HISTORY_DENIAL_REASONS = {
    'missing-policy': 'explicit execution policy and mode required',
    'missing-mode': 'explicit execution policy and mode required',
    'denied-host': 'host executor effective UID mismatch or denied',
    'host-uid-mismatch': 'host executor effective UID mismatch or denied',
    'unacknowledged-root': 'independent root policy, effective root and fresh risk acknowledgement required',
    'root-not-allowed': 'independent root policy, effective root and fresh risk acknowledgement required',
    'sandbox-no-host-fallback': 'sandbox',
}
_HISTORY_CONTROLS = {
    'authorized-host': (dict(host_uid=1001, allow_host=True), 'host', 1001, False),
    'authorized-root': (dict(host_uid=1001, allow_root=True), 'root', 0, True),
}
_HISTORY_BRANCHES = {
    'new': (None, ['new', 'NEW']),
    'named-new': ('fixture-named', ['new', 'NEW fixture-named']),
    'cold-resume': (None, ['search', 'id-2', '1', 'RESUME id-2']),
}


def _run_history_branch(history, tmp_path, branch, case):
    from arvyx_control.hermes_profile import HermesProfile
    from arvyx_control.local_executor import ExecutionPolicy
    from arvyx_control.terminal_sessions import history_menu
    config, mode, uid, ack = case
    new_profile, answers = _HISTORY_BRANCHES[branch]
    user_home = tmp_path/'user-home'; (user_home/'.hermes').mkdir(parents=True, mode=0o700)
    workspace = tmp_path/'workspace'; workspace.mkdir(mode=0o700)
    if branch == 'cold-resume':
        workspace = tmp_path  # The fixture conversation's exact recorded cwd.
    policy = None if config is None else ExecutionPolicy(**config)
    dispatched = []
    def recorder(argv, **kwargs):
        dispatched.append(dict(argv=list(argv), cwd=kwargs['cwd'], env=kwargs['env']))
        return 0
    with patch('pathlib.Path.home', return_value=user_home), \
            patch('arvyx_control.hermes_history.shutil.which', return_value='/synthetic/not-executed-hermes'), \
            patch('builtins.input', side_effect=answers+['quit']), \
            patch('os.geteuid', return_value=uid), patch('os.isatty', return_value=True), \
            patch.object(HermesProfile, 'reserve', return_value=SimpleNamespace(release=lambda: None)) as reserve, \
            patch.object(HermesProfile, 'assert_idle'), \
            patch('arvyx_control.hermes_history.subprocess.call', side_effect=recorder):
        result = history_menu(history.home, workspace=workspace, new_profile=new_profile, authorize_launch=True,
                              execution_policy=policy, environment=mode, root_acknowledged=ack)
    named_home = user_home/'.hermes/profiles/fixture-named'
    return result, dispatched, reserve, named_home


@pytest.mark.parametrize('branch', sorted(_HISTORY_BRANCHES))
@pytest.mark.parametrize('denial', sorted(_HISTORY_DENIALS))
def test_rev0547_history_menu_branch_denials_never_dispatch(history, tmp_path, branch, denial, capsys):
    result, dispatched, reserve, named_home = _run_history_branch(history, tmp_path, branch, _HISTORY_DENIALS[denial])
    assert result == 0 and dispatched == []
    reserve.assert_not_called()
    assert not named_home.exists()  # No named identity is published before admission.
    refusals = [line for line in capsys.readouterr().out.splitlines() if line.startswith('Unavailable: ')]
    assert len(refusals) == 1 and _HISTORY_DENIAL_REASONS[denial] in refusals[0], refusals


@pytest.mark.parametrize('branch', sorted(_HISTORY_BRANCHES))
@pytest.mark.parametrize('control', sorted(_HISTORY_CONTROLS))
def test_rev0547_history_menu_authorized_controls_dispatch_once(history, tmp_path, branch, control):
    result, dispatched, reserve, named_home = _run_history_branch(history, tmp_path, branch, _HISTORY_CONTROLS[control])
    assert result == 0 and len(dispatched) == 1
    reserve.assert_called_once()
    argv = dispatched[0]['argv']
    assert argv[0] == '/synthetic/not-executed-hermes'
    assert argv[argv.index('--in')+1] == dispatched[0]['cwd'] and dispatched[0]['cwd'].startswith('/proc/self/fd/')
    if branch == 'cold-resume':
        assert argv[-2:] == ['--resume', 'id-2']
    else:
        assert '--resume' not in argv
    expected_home = named_home if branch == 'named-new' else history.home
    assert dispatched[0]['env']['HERMES_HOME'] == str(expected_home)
    assert named_home.exists() is (branch == 'named-new')
