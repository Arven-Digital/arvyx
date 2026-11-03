import sqlite3
from pathlib import Path
from unittest.mock import patch
import pytest
from test_session_workspace_journey import journey
from test_local_onboarding_services import services
import os

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='the native runtime (Linux x86_64 artifact, host-shell policies) is POSIX-only')

def test_reboot_continuation_is_exact_single_use_and_never_renews_consent(journey,tmp_path):
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control.cockpit_native_runtime import NativeRuntime
    from arvyx_control.cockpit_terminal_runner import JsonOperator
    from arvyx_control.cockpit_restart import grant,resume
    api,call,target,root,connect=journey;extension=api.owners['local-owner'].extension
    exe=tmp_path/'native';exe.write_text('#!/bin/false\n');exe.chmod(0o700)
    runtime=NativeRuntime(tool='hermes',executable=exe,home=connect['path'],store=Path(connect['path'])/'state.db')
    owner=LocalCockpit(tmp_path/'owner',extension.vault,tmp_path/'events.jsonl','machine-a',native_runtimes={'hermes':runtime})
    owner.db.execute("INSERT INTO sessions VALUES('sid',NULL,NULL,'exact',?,'running',12345,'local')",(str(root/'existing'),))
    owner.db.execute("INSERT INTO native_bindings VALUES('sid','hermes','1204')");owner.db.commit()
    owner.operator_drivers={'worker':JsonOperator([str(exe)],cwd=root/'existing')}
    owner.delegate('sid',operator='worker',goal='approved goal',limits='bounded scope',actor='operator')
    with patch('arvyx_control.cockpit_restart.boot_id',return_value='prior-kernel'):
        lease=grant(owner,'sid',actor='operator',confirmed=True,allow_provider_restart=True)
        with patch.object(owner,'start_native') as recorder:
            with pytest.raises(PermissionError,match='same-boot'):resume(owner,lease['id'],actor='operator')
            recorder.assert_not_called()
    owner.db.execute("UPDATE sessions SET status='stopped',pid=NULL WHERE id='sid'")
    owner.db.execute("UPDATE delegations SET status='paused' WHERE session='sid'");owner.db.commit()
    owner.incarnation='new-owner'
    with patch('arvyx_control.cockpit_restart.boot_id',return_value='new-kernel'),patch.object(owner,'start_native',return_value={}) as recorder:
        result=resume(owner,lease['id'],actor='operator')
        assert result['expires_at']==lease['expires_at'] and result['input_replayed'] is False
        from arvyx_control.cockpit_restart import RestartAdmission
        guard=recorder.call_args.kwargs['_restart_admission']
        assert type(guard) is RestartAdmission and guard.owner is owner and guard.sid=='sid'
        assert guard.expires==lease['expires_at']
        recorder.assert_called_once_with('sid',actor='operator',allow_provider=True,environment='host',_restart_admission=guard)
        with pytest.raises(PermissionError):resume(owner,lease['id'],actor='operator')
        owner.db.execute('UPDATE delegation_expiries SET expires=0');owner.db.commit()
        with pytest.raises(ValueError,match='expired'):owner._delegated('sid',owner.delegation('sid',actor='operator')['generation'],'worker')
    owner.close()


@pytest.mark.parametrize('failure',['pending','revoked','expired','lost-ack'])
def test_reopened_restart_refuses_uncertainty_revocation_expiry_and_replay(journey,tmp_path,failure):
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control.cockpit_native_runtime import NativeRuntime
    from arvyx_control.cockpit_terminal_runner import JsonOperator
    from arvyx_control.cockpit_restart import grant,resume
    api,call,target,root,connect=journey;extension=api.owners['local-owner'].extension
    exe=tmp_path/'native';exe.write_text('#!/bin/false\n');exe.chmod(0o700)
    runtime=NativeRuntime(tool='hermes',executable=exe,home=connect['path'],store=Path(connect['path'])/'state.db')
    def open_owner():
        owner=LocalCockpit(tmp_path/'owner',extension.vault,tmp_path/'events.jsonl','machine-a',native_runtimes={'hermes':runtime})
        owner.operator_drivers={'worker':JsonOperator([str(exe)],cwd=root/'existing')}
        return owner
    owner=open_owner()
    owner.db.execute("INSERT INTO sessions VALUES('sid',NULL,NULL,'exact',?,'running',12345,'local')",(str(root/'existing'),))
    owner.db.execute("INSERT INTO native_bindings VALUES('sid','hermes','1204')");owner.db.commit()
    owner.delegate('sid',operator='worker',goal='approved goal',limits='bounded scope',actor='operator')
    with patch('arvyx_control.cockpit_restart.boot_id',return_value='prior-kernel'):
        lease=grant(owner,'sid',actor='operator',confirmed=True,allow_provider_restart=True)
    owner.close();owner=open_owner()
    if failure=='pending':owner.db.execute("UPDATE delegations SET status='ambiguous',pending='uncertain' WHERE session='sid'")
    if failure=='revoked':owner.take_control('sid',actor='operator')
    if failure=='expired':owner.db.execute('UPDATE native_restart_leases SET expires=0')
    owner.db.commit()
    with patch('arvyx_control.cockpit_restart.boot_id',return_value='new-kernel'),patch.object(owner,'start_native',side_effect=OSError('lost reply')) as recorder:
        if failure=='lost-ack':
            with pytest.raises(OSError):resume(owner,lease['id'],actor='operator')
            assert owner.db.execute('SELECT status FROM native_restart_leases').fetchone()[0]=='ambiguous'
            with pytest.raises(PermissionError):resume(owner,lease['id'],actor='operator')
            assert recorder.call_count==1
        else:
            with pytest.raises(PermissionError):resume(owner,lease['id'],actor='operator')
            recorder.assert_not_called()
    owner.close()
