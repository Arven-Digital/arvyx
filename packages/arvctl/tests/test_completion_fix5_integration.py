"""Synthetic, disposable integration regressions. No native/provider effects."""
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from unittest.mock import patch
import pytest
from arvyx_control import cockpit_archive as archive
from arvyx_control import promotion_transaction as promotion
from arvyx_control.cockpit import LocalCockpit
from test_sol24_archive import owner_at
from test_sol27_archive_pem import native_owner


@pytest.mark.parametrize('name',['a'*252+'.md','界'*83+'abc.md'])
@pytest.mark.parametrize('fail',[False,True])
def test_promotion_maximum_parent_basename_preserves_atomicity(tmp_path,name,fail):
    vault=tmp_path/'vault';vault.mkdir()
    source=vault/'pending'/'note.md';source.parent.mkdir();source.write_bytes(b'pending original')
    parent=vault/'curated'/name;parent.parent.mkdir();parent.write_bytes(b'parent original')
    target=parent.parent/'new.md'
    original_stage=promotion.stage
    def stage(path,data,mode=0o600):
        if fail and path.name=='committed.stage':raise OSError('synthetic commit barrier')
        return original_stage(path,data,mode)
    with patch.object(promotion,'stage',side_effect=stage):
        if fail:
            with pytest.raises(OSError,match='synthetic commit'):
                promotion.publish(vault,source,target,b'new',{parent:(b'parent original',b'superseded')},source_bytes=b'pending original')
            assert source.read_bytes()==b'pending original' and parent.read_bytes()==b'parent original' and not target.exists()
        else:
            promotion.publish(vault,source,target,b'new',{parent:(b'parent original',b'superseded')},source_bytes=b'pending original')
            assert not source.exists() and parent.read_bytes()==b'superseded' and target.read_bytes()==b'new'


LEGACY_STATES=[['RSA PRIVATE KEY','END R',None,''],['RSA PRIVATE KEY','END R',None,'c3'],[False,'',None,''],[True,'',None,'']]
@pytest.mark.parametrize('state',LEGACY_STATES)
def test_persisted_legacy_capture_provenance_is_quarantined(tmp_path,state):
    path=tmp_path/'capture.db';owner=owner_at(path)
    capture=archive.WorkCapture(owner,'s');capture.feed(b'ordinary historical record\n');capture.finish()
    with owner.db:owner.db.execute('UPDATE capture_screen_context SET pem=? WHERE session=?',(json.dumps(state),'s'))
    before=archive.pending_capture(owner);owner.db.close();owner=owner_at(path)
    try:
        with pytest.raises(ValueError,match='provenance|legacy'):
            capture=archive.WorkCapture(owner,'s');capture.feed(b'SA PRIVATE KEY\nSYNTHETIC_SUFFIX\n');capture.finish()
        assert archive.pending_capture(owner)==before
        assert owner.db.execute('SELECT pem FROM capture_screen_context WHERE session=?',('s',)).fetchone()[0]==json.dumps(state)
    finally:owner.db.close()


@pytest.mark.parametrize('state',LEGACY_STATES)
def test_persisted_legacy_native_cursor_provenance_is_quarantined(tmp_path,state):
    store=tmp_path/'state.db'
    with sqlite3.connect(store) as db:
        db.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY,session_id TEXT,role TEXT,content TEXT)')
        db.execute('INSERT INTO messages VALUES(1,?,?,?)',('conversation','assistant','ordinary historical record'))
    path=tmp_path/'capture.db';owner=native_owner(path,store)
    LocalCockpit.native_archive(owner,'s',actor='operator')
    with owner.db:owner.db.execute('UPDATE native_archive_context SET pem=?',(json.dumps(state),))
    before=archive.pending_capture(owner);owner.db.close();owner=native_owner(path,store)
    with sqlite3.connect(store) as db:
        db.executemany('INSERT INTO messages VALUES(?,?,?,?)',[(2,'conversation','assistant','SA PRIVATE KEY'),(3,'conversation','assistant','SYNTHETIC_SUFFIX')])
    try:
        with pytest.raises(ValueError,match='provenance|legacy'):
            LocalCockpit.native_archive(owner,'s',actor='operator')
        assert archive.pending_capture(owner)==before
        assert owner.db.execute('SELECT cursor FROM native_archive_context').fetchone()[0]==1
    finally:owner.db.close()


def test_agent_creation_consent_after_validation_before_directory(tmp_path):
    from arvyx_control.agent_creation import AgentCreation,CreationRequest
    from arvyx_control.reviewed_actions import consent_scope
    profiles=tmp_path/'profiles';profiles.mkdir()
    creation=AgentCreation(sqlite3.connect(tmp_path/'agents.db'),profiles,workspace_id='workspace',local_host='host',isolated_harnesses={'fixture'})
    validate=creation._validate;clock=[time.time()]
    def delayed(request):
        result=validate(request);clock[0]+=30;return result
    with patch.object(creation,'_validate',side_effect=delayed),patch('time.time',side_effect=lambda:clock[0]),consent_scope(clock[0]+10):
        with pytest.raises((PermissionError,ValueError),match='expired'):
            creation.create(CreationRequest('synthetic','fixture','host'))
    assert list(profiles.iterdir())==[] and creation.list_agents()==()


def test_session_selection_rechecks_after_blocking_metadata():
    from arvyx_control.agent_sessions import AgentSessions,SessionTarget,SessionRoute,SessionMetadata
    from arvyx_control.reviewed_actions import consent_scope
    target=SessionTarget('machine','agent','workspace','connection');route=SessionRoute(target,'session');clock=[time.time()];effects=[]
    class Adapter:
        connected=True
        def metadata(self,requested):clock[0]+=30;return [SessionMetadata(route,'synthetic',0)]
        def perform(self,*args,**kwargs):effects.append(args)
    adapter=Adapter();adapter.target=target;sessions=AgentSessions({target:adapter})
    with patch('time.time',side_effect=lambda:clock[0]),consent_scope(clock[0]+10):
        with pytest.raises((PermissionError,ValueError),match='expired'):sessions.select(route)
    assert not effects


def test_new_context_reopen_keeps_safe_capture_and_legacy_reset_is_exact(tmp_path):
    path=tmp_path/'capture.db';owner=owner_at(path)
    owner._get=lambda sid:dict(status='stopped')
    recorder=archive.WorkCapture(owner,'s');recorder.feed(b'normal Unicode: \xe7\x95\x8c\n');recorder.finish()
    before=archive.pending_capture(owner)
    with owner.db:owner.db.execute('UPDATE capture_screen_context SET pem=?',(json.dumps(LEGACY_STATES[0]),))
    inspect=getattr(archive,'inspect_context_recovery',None)
    assert callable(inspect),'an exact operator recovery path is required'
    proof=inspect(owner,'s',actor='operator',kind='capture')
    with pytest.raises(ValueError):archive.reconcile_context(owner,'s',actor='operator',kind='capture',expected=dict(proof,sha256='0'*64),confirmed=True,clean_boundary_confirmed=True)
    archive.reconcile_context(owner,'s',actor='operator',kind='capture',expected=proof,confirmed=True,clean_boundary_confirmed=True)
    owner.db.close();owner=owner_at(path)
    recorder=archive.WorkCapture(owner,'s');recorder.feed(b'new safe epoch\n');recorder.finish()
    assert archive.pending_capture(owner)[:len(before)]==before
    assert 'new safe epoch' in str(archive.pending_capture(owner))
    persisted=owner.db.execute("SELECT pem FROM capture_screen_context WHERE session='s'").fetchone()[0]
    assert json.loads(persisted)['version']==2 and 'safe epoch' not in persisted
    owner.db.close()


def test_native_quarantine_recovery_reimports_from_zero_retaining_original_rows(tmp_path):
    store=tmp_path/'state.db'
    with sqlite3.connect(store) as db:
        db.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY,session_id TEXT,role TEXT,content TEXT)')
        db.executemany('INSERT INTO messages VALUES(?,?,?,?)',[(1,'conversation','assistant','BEGIN RSA PRIVATE KEY'),(2,'conversation','assistant','END R\u00e9'),(3,'conversation','assistant','SA PRIVATE KEY'),(4,'conversation','assistant','SYNTHETIC_SUFFIX')])
    path=tmp_path/'archive.db';owner=native_owner(path,store);owner._get=lambda sid:dict(workspace=str(tmp_path/'workspace'),status='stopped')
    archive.import_native(owner,'s',actor='operator')
    before=archive.pending_capture(owner)
    with owner.db:owner.db.execute('UPDATE native_archive_context SET pem=?',(json.dumps(LEGACY_STATES[2]),))
    inspect=getattr(archive,'inspect_context_recovery',None)
    assert callable(inspect),'native reimport needs exact operator recovery'
    proof=inspect(owner,'s',actor='operator',kind='native')
    archive.reconcile_context(owner,'s',actor='operator',kind='native',expected=proof,confirmed=True,clean_boundary_confirmed=False)
    result=archive.import_native(owner,'s',actor='operator')
    assert result['imported']==4
    after=archive.pending_capture(owner);assert after[:len(before)]==before
    assert 'SYNTHETIC_SUFFIX' not in str(after[len(before):])
    owner.db.close();owner=native_owner(path,store)
    assert archive.import_native(owner,'s',actor='operator')['imported']==0
    owner.db.close()


def test_injected_blocking_adapter_checks_original_consent_at_publication():
    from arvyx_control.agent_sessions import AgentSessions,SessionTarget,SessionRoute,SessionMetadata
    from arvyx_control.reviewed_actions import consent_scope
    target=SessionTarget('machine','agent','workspace','connection');route=SessionRoute(target,'session');clock=[time.time()];effects=[]
    class Adapter:
        connected=True
        def metadata(self,requested):return [SessionMetadata(route,'synthetic',0)]
        def perform(self,*args,publication_guard=None):
            clock[0]+=30
            assert callable(publication_guard),'blocking adapters must receive the original publication gate'
            publication_guard();effects.append(args)
    adapter=Adapter();adapter.target=target;sessions=AgentSessions({target:adapter})
    with patch('time.time',side_effect=lambda:clock[0]),consent_scope(clock[0]+10):
        with pytest.raises(ValueError,match='expired'):sessions.select(route)
    assert not effects


@pytest.mark.parametrize('foreign',[False,True])
def test_legacy_promotion_manifest_recovers_only_exact_published_inode(tmp_path,foreign):
    import os,stat
    vault=tmp_path/'vault';vault.mkdir();source=vault/'pending.md';source.write_bytes(b'pending original')
    parent=vault/'parent.md';parent.write_bytes(b'parent original')
    journal=vault/'.arvyx/promotions/legacy'
    journal.mkdir(parents=True)
    rows=[]
    for path,data,source_row in ((parent,b'parent original',False),(source,b'pending original',True)):
        info=path.stat();backup='source.original' if source_row else 'parent-0.original'
        stage_path=path.with_name('.'+path.name+'.'+'a'*32+'.stage')
        row=dict(path=path.name,original=promotion.identity(path),published=None,backup=backup,
            mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,source=source_row,stage=str(stage_path))
        promotion.stage(journal/backup,data)
        if not source_row:
            promotion.stage(stage_path,b'published');row['published']=promotion.identity(stage_path);stage_path.replace(path)
        rows.append(row)
    promotion.stage(journal/'manifest.json',json.dumps(dict(schema=1,files=rows)).encode());source.unlink()
    if foreign:
        parent.unlink();parent.write_bytes(b'unrelated replacement')
        with pytest.raises(OSError,match='conflict'):promotion.recover(vault)
        assert parent.read_bytes()==b'unrelated replacement' and journal.exists()
    else:
        promotion.recover(vault);assert parent.read_bytes()==b'parent original'
    assert source.read_bytes()==b'pending original'

from test_local_onboarding_services import services
from test_session_workspace_journey import journey


def test_injected_connector_rechecks_after_its_own_blocking_preparation(journey):
    api,call,target,root,_=journey;owner=api.owners['local-owner'];effects=[];clock=[time.time()]
    from arvyx_control.agent_sessions import SessionTarget
    api._candidates['local-owner']={'synthetic':dict(id='synthetic',family='synthetic')}
    def connector(candidate,*,publication_guard):
        clock[0]+=1000;publication_guard();effects.append(candidate);return SessionTarget(**target)
    owner.connectors['synthetic']=connector
    with patch('time.time',side_effect=lambda:clock[0]):
        status,value=call('connect',dict(candidate_id='synthetic',confirmed=True))
    assert status==503 and not effects


def test_agent_creation_original_expiry_rechecked_after_content_sync(tmp_path):
    from arvyx_control.agent_creation import AgentCreation,CreationRequest
    from arvyx_control.reviewed_actions import consent_scope
    profiles=tmp_path/'profiles';profiles.mkdir();creation=AgentCreation(sqlite3.connect(tmp_path/'agents.db'),profiles,workspace_id='workspace',local_host='host',isolated_harnesses={'fixture'})
    clock=[time.time()]
    def delayed_sync(fd):clock[0]+=30
    with patch('os.fsync',side_effect=delayed_sync),patch('time.time',side_effect=lambda:clock[0]),consent_scope(clock[0]+10):
        with pytest.raises(ValueError,match='expired'):creation.create(CreationRequest('synthetic','fixture','host'))
    assert not list(profiles.iterdir()) and creation.list_agents()==()


def test_versioned_uncertain_capture_requires_stopped_clean_stream_recovery(tmp_path):
    owner=owner_at(tmp_path/'archive.db');status=['running'];owner._get=lambda sid:dict(status=status[0],pid=None)
    recorder=archive.WorkCapture(owner,'s');recorder.feed('BEGIN RSA PRIVATE KEY\nEND RéSA PRIVATE KEY\n'.encode());recorder.finish()
    proof=archive.inspect_context_recovery(owner,'s',actor='operator',kind='capture')
    with pytest.raises(ValueError,match='stopped'):archive.reconcile_context(owner,'s',actor='operator',kind='capture',expected=proof,confirmed=True,clean_boundary_confirmed=True)
    status[0]='ended'
    archive.reconcile_context(owner,'s',actor='operator',kind='capture',expected=proof,confirmed=True,clean_boundary_confirmed=True)
    recorder=archive.WorkCapture(owner,'s');recorder.feed(b'new clean safe process\n');recorder.finish()
    assert 'new clean safe process' in str(archive.pending_capture(owner))


def test_missing_legacy_native_context_cannot_adopt_a_cursor(tmp_path):
    store=tmp_path/'state.db'
    with sqlite3.connect(store) as db:
        db.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY,session_id TEXT,role TEXT,content TEXT)');db.execute("INSERT INTO messages VALUES(1,'conversation','assistant','safe')")
    owner=native_owner(tmp_path/'archive.db',store);archive.import_native(owner,'s',actor='operator')
    with owner.db:
        owner.db.execute('DELETE FROM native_archive_context');owner.db.execute('DELETE FROM native_archive_cursor_provenance')
    with pytest.raises(archive.ContextProvenanceRequired):archive.import_native(owner,'s',actor='operator')
