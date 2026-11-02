from arvyx_control.local_executor import ExecutionPolicy
from arvyx_control.replica_authority import authority_context
"""Actual start_native dispatch, with process creation replaced by a recorder."""
import sqlite3
from unittest.mock import Mock
import pytest
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_native_runtime import NativeRuntime
from arvyx_control.cockpit_client import initialize
from arvyx_control.control import create_task

@pytest.fixture
def configured(tmp_path):
    root=tmp_path/'owner';initialize(root)
    home=tmp_path/'profile';home.mkdir(mode=0o700)
    workspace=tmp_path/'workspace';workspace.mkdir()
    store=home/'state.db'
    with sqlite3.connect(store) as db:
        db.execute('CREATE TABLE sessions(id TEXT,cwd TEXT,end_reason TEXT)')
        db.execute('INSERT INTO sessions VALUES(?,?,?)',('exact-id',str(workspace),None))
    runtime=NativeRuntime(tool='hermes',executable='/usr/bin/python3',home=home,store=store)
    owner=LocalCockpit(root/'runtime',root/'vault',root/'events.jsonl','disposable-host',native_runtimes={'hermes':runtime}, execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))
    try:
        with authority_context(owner.vault, owner.state):
            task=create_task(owner.state,'Exact native metadata',owner='demobot').task
        session=owner.open(project='demo-agent',task=task.id,name='exact-metadata',workspace=workspace,actor='operator')
        owner.bind_native(session['id'],tool='hermes',conversation='exact-id',actor='operator')
        owner._start=Mock(return_value={'test_process_boundary_only':True})
        yield owner,session['id'],runtime,store,workspace
    finally:
        owner.close()

@pytest.mark.parametrize('change',['compression','workspace','absent','ambiguous','database_replaced','profile_replaced'])
def test_invalid_exact_profile_refuses_before_process_creation(configured,change,tmp_path):
    owner,sid,runtime,store,workspace=configured
    if change in ('compression','workspace','absent','ambiguous'):
        with sqlite3.connect(store) as db:
            if change=='compression':db.execute("UPDATE sessions SET end_reason='compression'")
            if change=='workspace':db.execute('UPDATE sessions SET cwd=?',(str(tmp_path),))
            if change=='absent':db.execute('DELETE FROM sessions')
            if change=='ambiguous':db.execute('INSERT INTO sessions SELECT * FROM sessions')
    elif change=='database_replaced':
        replacement=store.with_name('replacement.db')
        with sqlite3.connect(replacement) as db:
            db.execute('CREATE TABLE sessions(id,cwd,end_reason)');db.execute('INSERT INTO sessions VALUES(?,?,NULL)',('exact-id',str(workspace)))
        replacement.replace(store)
    else:
        runtime.home.rename(runtime.home.with_name('old-profile'));runtime.home.mkdir(mode=0o700)
        with sqlite3.connect(store) as db:
            db.execute('CREATE TABLE sessions(id,cwd,end_reason)');db.execute('INSERT INTO sessions VALUES(?,?,NULL)',('exact-id',str(workspace)))
    try:
        with pytest.raises(ValueError):owner.start_native(sid,actor='operator',allow_provider=True, environment='host')
    finally:owner._start.assert_not_called()


def test_valid_start_sets_exact_home_and_profile_without_provider_execution(configured):
    owner,sid,runtime,store,workspace=configured
    owner.start_native(sid,actor='operator',allow_provider=True, environment='host')
    args=owner._start.call_args.kwargs
    assert args['environment']['HERMES_HOME']==str(runtime.home)
    assert args['environment']['HOME']==str(runtime.home)
    assert args['argv'][-2:]==['--resume','exact-id']


def test_noncanonical_hermes_store_cannot_describe_another_profile(configured):
    owner,sid,runtime,store,workspace=configured
    alias=runtime.home/'other.db'
    with sqlite3.connect(alias) as db:db.execute('CREATE TABLE sessions(id)')
    with pytest.raises(ValueError):NativeRuntime(tool='hermes',executable='/usr/bin/python3',home=runtime.home,store=alias)
