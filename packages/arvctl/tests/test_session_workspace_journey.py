"""New-workspace preparation via real authenticated handlers, no native launch."""
from contextlib import closing
import json,os,sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from test_local_onboarding_services import services
from test_local_handler_wire import request
from arvyx_control.public_onboarding_api import handler_for

def private(path):
    if os.name=='posix': return path.stat().st_mode&0o777==0o700
    from arvyx_control import windows_acl
    return windows_acl.private_path_problem(str(path)) is None

@pytest.fixture
def journey(services,tmp_path):
    api,_,profile,root=services
    workspace=tmp_path/'work';workspace.mkdir(mode=0o700);(workspace/'existing').mkdir()
    with closing(sqlite3.connect(profile/'state.db')) as db, db:
        db.execute('ALTER TABLE sessions ADD COLUMN cwd TEXT');db.execute('ALTER TABLE sessions ADD COLUMN end_reason TEXT')
        db.execute('UPDATE sessions SET cwd=?',(str(workspace/'existing'),))
    api.owners['local-owner'].extension.workspace_roots={'work':workspace}
    server=SimpleNamespace(server_address=('127.0.0.1',12345),server_port=12345,origin='http://127.0.0.1:12345')
    handler=handler_for(api)
    def raw(path,body=None,**kw):return request(handler,server,'/api/public-onboarding/'+path,body,**kw)
    from reviewed_action_helpers import reviewed_call
    def call(path,body=None,**kw):return reviewed_call(raw,path,body,**kw)
    connect=dict(family='hermes',path=str(profile),agent_id='agent-a',confirmed=True)
    target=call('manual/connect',connect)[1]['target']
    yield api,call,target,workspace,connect

def plan(target,mode='create',path='fresh'):
    return dict(target=target,workspace=dict(mode=mode,root_id='work',**({'session_id':'1204'} if mode=='current' else {'path':path})),environment='metadata')

def commit(preview):return dict(consent_id=preview['consent_id'],consent_sha256=preview['sha256'],confirmed=True)

def test_actual_http_prepare_commit_new_workspace_is_reviewed_and_single_use(journey):
    api,call,target,root,_=journey
    assert call('sessions/workspaces',dict(target=target),auth=False)[0]==401
    assert call('sessions/workspaces',dict(target=target),origin=False)[0]==403
    status,catalog=call('sessions/workspaces',dict(target=target));assert status==200
    assert catalog['roots'][0]['id']=='work' and catalog['execution'] is False
    status,preview=call('sessions/prepare',plan(target));assert status==200,preview
    assert not (root/'fresh').exists()
    assert call('sessions/commit',dict(commit(preview),consent_sha256='changed'))[0]==400
    with patch('subprocess.Popen') as process:
        status,result=call('sessions/commit',commit(preview));assert status==201,result
        process.assert_not_called()
    assert (root/'fresh').is_dir() and private(root/'fresh')
    assert result['status']=='workspace_ready' and result['native_session_created'] is False
    assert result['execution'] is False and result['target']==target
    assert call('sessions/commit',commit(preview))[0]==400
    assert call('sessions/commit',dict(confirmed=True))[0]==400

@pytest.mark.parametrize('mode',['existing','current'])
def test_existing_and_recorded_current_workspace_share_exact_review(journey,mode):
    _,call,target,root,_=journey
    status,p=call('sessions/prepare',plan(target,mode,'existing'));assert status==200,p
    status,result=call('sessions/commit',commit(p));assert status==201,result
    assert result['workspace']==str(root/'existing')
    assert list((root/'existing').iterdir())==[]

def test_expired_changed_target_and_root_fail_before_filesystem_mutation(journey):
    api,call,target,root,connect=journey
    p=call('sessions/prepare',plan(target))[1];assert 'consent_id' in p,p
    db=api.owners['local-owner'].creation.db
    with db:db.execute('UPDATE session_preparations SET expires=0')
    assert call('sessions/commit',commit(p))[0]==400
    p=call('sessions/prepare',plan(target))[1]
    call('manual/connect',connect)
    assert call('sessions/commit',commit(p))[0] in (400,403,409)
    assert not (root/'fresh').exists()

def test_traversal_symlink_preexisting_destination_and_execution_denied(journey):
    _,call,target,root,_=journey
    (root/'outside').symlink_to(root.parent,target_is_directory=True)
    for name in ('../escape','outside/escape','existing','/absolute'):
        assert call('sessions/prepare',plan(target,path=name))[0]==400
    for mode in ('sandbox','host','root'):
        assert call('sessions/prepare',dict(plan(target),environment=mode))[0]==501
    assert not (root/'fresh').exists()


def test_recorded_workspace_can_be_the_authorized_root_itself(journey):
    _,call,target,root,connect=journey
    with closing(sqlite3.connect(Path(connect['path'])/'state.db')) as db, db:db.execute('UPDATE sessions SET cwd=?',(str(root),))
    status,p=call('sessions/prepare',plan(target,'current'));assert status==200,p
    assert call('sessions/commit',commit(p))[1]['workspace']==str(root)


@pytest.mark.skipif(os.name!='posix',reason='directory fsync barriers are not performed on Windows (docs/limitations.md, Windows durability)')
def test_changed_root_and_ambiguous_directory_effect_are_never_replayed(journey):
    api,call,target,root,_=journey
    p=call('sessions/prepare',plan(target))[1]
    root.rename(root.with_name('old-work'));root.mkdir(mode=0o700)
    assert call('sessions/commit',commit(p))[0]==400 and not (root/'fresh').exists()
    p=call('sessions/prepare',plan(target))[1]
    with patch('arvyx_control.session_workspaces.os.fsync',side_effect=OSError('lost acknowledgement after mkdir')):
        assert call('sessions/commit',commit(p))[0]==503
    assert (root/'fresh').is_dir()
    assert call('sessions/commit',commit(p))[0]==400
