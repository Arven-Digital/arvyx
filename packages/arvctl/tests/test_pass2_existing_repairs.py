"""Small real producer/consumer rechecks for earlier unverified repairs."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit,parse_qs
import pytest
from arvyx_control.replica_authority import authority_context
from arvyx_control.vault import init_vault


def test_concurrent_imports_keep_both_original_bodies(tmp_path):
    from arvyx_control.importers import import_markdown
    vault=tmp_path/'vault';init_vault(vault)
    sources=[]
    for i in range(2):
        source=tmp_path/str(i);source.mkdir();(source/'same.md').write_text(f'# Different fact {i}\nValue {i}');sources.append(source)
    def write(source):
        with authority_context(vault):return import_markdown(source,vault,'demo-agent')
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(write,sources))
    files=list((vault/'projects/demo-agent/imported').glob('*.md'))
    assert len(files)==2 and all(len(result.imported)==1 for result in results)
    assert any('Different fact 0' in p.read_text() for p in files)
    assert any('Different fact 1' in p.read_text() for p in files)


def test_hot_session_readers_never_observe_partial_replacement(tmp_path):
    from arvyx_control.session import set_session,get_session
    vault=tmp_path/'vault';init_vault(vault)
    payloads=['Complete A '*1000,'Complete B '*1000]
    with authority_context(vault):set_session(vault,'demobot',payloads[0])
    def writer(text):
        with authority_context(vault):
            for _ in range(8):set_session(vault,'demobot',text)
    def reader(_):
        for _ in range(60):assert get_session(vault,'demobot').content.strip() in [p.strip() for p in payloads]
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures=[pool.submit(writer,text) for text in payloads]+[pool.submit(reader,n) for n in range(2)]
        for future in futures:future.result(timeout=10)


def test_replica_fault_replaces_prior_success_and_never_certifies_partial_copy(tmp_path):
    from arvyx_control import replica
    primary=tmp_path/'primary';init_vault(primary);target=tmp_path/'replica'
    with authority_context(primary):manifest=replica.build_manifest(primary)
    def fetch(url,**kwargs):
        if url.endswith('/replica/manifest'):return manifest
        path=parse_qs(urlsplit(url).query)['path'][0]
        return replica.read_vault_file(primary,path)
    with patch.object(replica,'_get_json',side_effect=fetch):replica.sync_replica('http://127.0.0.1:12345',target)
    assert replica.replica_status(target).sync_complete is True
    note=primary/'projects/demo-agent/STATUS.md';note.write_text('Changed authoritative fact')
    with authority_context(primary):manifest=replica.build_manifest(primary)
    def fail(path,data):raise OSError('fixture publication failure')
    real_write=replica._durable_write
    def write(path,data):
        if Path(path).name=='STATUS.md':return fail(path,data)
        return real_write(path,data)
    with patch.object(replica,'_get_json',side_effect=fetch),patch.object(replica,'_durable_write',side_effect=write):
        with pytest.raises(OSError):replica.sync_replica('http://127.0.0.1:12345',target)
    assert replica.replica_status(target).sync_complete is False
    with patch.object(replica,'_get_json',side_effect=fetch):replica.sync_replica('http://127.0.0.1:12345',target)
    assert replica.replica_status(target).sync_complete is True
    assert (target/'projects/demo-agent/STATUS.md').read_bytes()==note.read_bytes()


def test_crlf_relations_and_superseded_index_use_shared_reader(tmp_path):
    from arvyx_control.index import load_index
    from arvyx_control.writes import refine_memory
    vault=tmp_path/'vault';init_vault(vault)
    note=vault/'projects/demo-agent/notes/obsolete.md';note.parent.mkdir(exist_ok=True)
    note.write_bytes(b'---\r\ntitle: Obsolete\r\nstatus: superseded\r\n---\r\nUnique obsolete statement\r\n')
    pending=vault/'projects/demo-agent/pending/forged.md';pending.parent.mkdir(exist_ok=True)
    pending.write_bytes(b'---\r\nrelations: [{"type":"updates","parent_source_path":"projects/other/notes/parent.md"}]\r\n---\r\nForged relation\r\n')
    with authority_context(vault):
        assert all(chunk.relative_path!='projects/demo-agent/notes/obsolete.md' for chunk in load_index(vault))
        with pytest.raises(ValueError):refine_memory(vault,'demo-agent','pending/forged.md','operator')
    assert pending.exists() and b'\r\n' in pending.read_bytes()


def test_refinement_traversal_never_mutates_curated_truth(tmp_path):
    from arvyx_control.writes import refine_memory
    vault=tmp_path/'vault';init_vault(vault)
    note=vault/'projects/demo-agent/notes/kept.md';note.parent.mkdir(exist_ok=True);note.write_bytes(b'Original curated bytes')
    for path in ('pending/../notes/kept.md','pending/../../demo-agent/notes/kept.md',str(note)):
        with authority_context(vault),pytest.raises(ValueError):refine_memory(vault,'demo-agent',path,'operator')
    assert note.read_bytes()==b'Original curated bytes'


def test_renewal_waits_for_revocation_and_never_revives_slot(tmp_path):
    import threading
    from arvyx_control import auth
    vault=tmp_path/'vault';init_vault(vault)
    auth.issue_token(vault,'demobot',scopes=['memory.read'],slot='fixture')
    entered=threading.Event();release=threading.Event();real=auth._write_record
    def paused(path,record):
        if record.get('revoked') is True:
            entered.set();assert release.wait(3)
        return real(path,record)
    def revoke():
        with authority_context(vault):auth.revoke_token(vault,'demobot',slot='fixture')
    def renew():
        with authority_context(vault):return auth.renew_token(vault,'demobot',slot='fixture')
    with patch.object(auth,'_write_record',side_effect=paused),ThreadPoolExecutor(max_workers=2) as pool:
        first=pool.submit(revoke);assert entered.wait(2)
        second=pool.submit(renew)
        assert not second.done()
        release.set();first.result(timeout=3)
        with pytest.raises(ValueError,match='revoked'):second.result(timeout=3)
    assert next(t for t in auth.list_tokens(vault).tokens if t.slot=='fixture').revoked is True


def test_replica_state_reader_serves_exact_manifest_prefix_after_append(tmp_path):
    from arvyx_control import replica
    vault=tmp_path/'vault';init_vault(vault)
    state=tmp_path/'events.jsonl';audit=tmp_path/'audit.jsonl'
    state.write_bytes(b'{"type":"fixture"}\n');audit.write_bytes(b'original audit bytes\n')
    with authority_context(vault,state):manifest=replica.build_manifest(vault,state,audit)
    original=audit.read_bytes();audit.write_bytes(original+b'newer appended audit bytes\n')
    binding=manifest['state_files']['audit-log.jsonl']
    result=replica.read_state_file('audit-log.jsonl',state,audit,**binding)
    assert base64.b64decode(result['content_b64'])==original
    audit.write_bytes(b'changed prefix'+original)
    with pytest.raises(ValueError,match='changed'):replica.read_state_file('audit-log.jsonl',state,audit,**binding)


def test_stdio_suggestion_and_http_header_keys_fence_real_domain_effects(tmp_path):
    from arvyx_control import mcp,api
    vault=tmp_path/'vault';init_vault(vault);state=tmp_path/'events.jsonl'
    arguments=dict(project='demo-agent',title='Durable suggestion',content='Keep the operational finding.',author='demobot',idempotency_key='fixture-suggestion-key')
    payload=dict(jsonrpc='2.0',id=1,method='tools/call',params=dict(name='memory.suggest',arguments=arguments))
    with authority_context(vault,state):
        first=mcp.handle_request(payload,vault,state=state,allowed_tools={'memory.suggest'},principal_scope='local:fixture')
        assert 'result' in first,first
        payload['id']=2
        replay=mcp.handle_request(payload,vault,state=state,allowed_tools={'memory.suggest'},principal_scope='local:fixture')
        assert 'error' in replay and 'completed' in replay['error']['message']
        pending=list((vault/'projects/demo-agent/pending').glob('*durable-suggestion*.md'))
        assert len(pending)==1
        response=api.handle_api_request('POST','/memory/suggest',dict(project='demo-agent',title='Header suggestion',content='Another recorded observation.',author='operator'),vault,state,bearer_secret='fixture-operator',authorization='Bearer fixture-operator',idempotency_key='header-only-fixture-key')
        assert response.status==201,response.body
        replay=api.handle_api_request('POST','/memory/suggest',dict(project='demo-agent',title='Header suggestion',content='Another recorded observation.',author='operator'),vault,state,bearer_secret='fixture-operator',authorization='Bearer fixture-operator',idempotency_key='header-only-fixture-key')
        assert replay.status==409
        assert len(list((vault/'projects/demo-agent/pending').glob('*header-suggestion*.md')))==1


def test_canonical_idempotent_thread_history_and_authoritative_supersession(tmp_path):
    from arvyx_control import api,control
    from arvyx_control.auth import issue_token
    from arvyx_control.retirement import _validate_thread_history
    from arvyx_control.operator_archive import _validate_archival_thread_history
    vault=tmp_path/'vault';init_vault(vault);state=tmp_path/'events.jsonl'
    token=issue_token(vault,'demobot',scopes=['control.read','control.write']).token
    def call(path,body,credential,key):
        return api.handle_api_request('POST',path,body,vault,state,bearer_secret='fixture-operator',authorization='Bearer '+credential,idempotency_key=key)
    with authority_context(vault,state):
        created=call('/threads',dict(title='Reviewed work',type='ask',target='demobot',actor='operator'),'fixture-operator','create-thread-fixture')
        assert created.status==201,created.body
        identifier=created.body['thread']['id']
        ack=call('/threads/'+identifier+'/ack',{},token,'ack-thread-fixture');assert ack.status==200,ack.body
        done=call('/threads/'+identifier+'/done',dict(actor='operator'),'fixture-operator','done-unbound-fixture');assert done.status==200,done.body
        final=call('/threads/'+identifier+'/done',{},token,'done-bound-fixture');assert final.status==200,final.body
        events=[event for event in control.read_events(state) if event.task_id==identifier and event.type.startswith('thread.')]
        assert events[-1].payload['done_by']=='demobot' and events[-1].payload['actor_identity_bound'] is True
        _validate_thread_history(events,identifier)
        _validate_archival_thread_history(events,identifier)
        from dataclasses import replace
        bound=[replace(event,payload=control._bind_idempotency(event.payload,'canonical-key',None,{'operation':'fixture'})) for event in events]
        _validate_thread_history(bound,identifier)
        _validate_archival_thread_history(bound,identifier)


def test_terminal_between_reconciliation_and_claim_wins_final_lock(tmp_path):
    from arvyx_control import control,execution
    from datetime import datetime,UTC
    state=tmp_path/'events.jsonl';vault=tmp_path/'vault';vault.mkdir()
    with authority_context(vault,state):
        thread=control.post_thread(state,title='Work',actor='operator',target='demobot',actor_identity_bound=True).thread
        original=execution._reconcile_executions
        def finish(*args,**kwargs):
            result=original(*args,**kwargs)
            control.complete_thread(state,thread.id,actor='demobot',actor_identity_bound=True)
            return result
        with patch.object(execution,'_reconcile_executions',side_effect=finish):
            assert execution.claim_execution(state,worker='fixture',execution_capable_targets={'demobot'}) is None
        assert {row.status for row in execution.project_executions(state).values()}=={'completed'}


def test_expired_unreclaimed_execution_never_reaches_delivery(tmp_path):
    from arvyx_control import control,execution
    from arvyx_control.agent_delivery import AgentRoute
    from datetime import datetime,UTC,timedelta
    state=tmp_path/'events.jsonl';vault=tmp_path/'vault';vault.mkdir();now=datetime(2026,10,29,tzinfo=UTC)
    with authority_context(vault,state):
        control.post_thread(state,title='Work',actor='operator',target='demobot',actor_identity_bound=True)
        attempt=execution.claim_execution(state,worker='fixture',execution_capable_targets={'demobot'},now=now,lease_seconds=1)
        with patch.object(execution,'deliver_outbox_item') as transport:
            result=execution.deliver_execution_attempt(attempt,AgentRoute('demobot','hermes-webhook','FIXTURE_URL','FIXTURE_SECRET'),state=state,now=now+timedelta(seconds=1))
            assert result.accepted is False
            transport.assert_not_called()


def test_suggestion_namespace_failure_is_not_acknowledged_or_redispatched(tmp_path):
    from arvyx_control import api,writes
    vault=tmp_path/'vault';init_vault(vault);state=tmp_path/'events.jsonl'
    body=dict(project='demo-agent',title='Barriered suggestion',content='Durable operational fact.',author='operator')
    real=writes.fsync_directory;failed=[]
    def barrier(path):
        if not failed:
            failed.append(path);raise OSError('fixture namespace failure')
        return real(path)
    with authority_context(vault,state):
        with patch.object(writes,'fsync_directory',side_effect=barrier):
            response=api.handle_api_request('POST','/memory/suggest',body,vault,state,bearer_secret='fixture-operator',authorization='Bearer fixture-operator',idempotency_key='suggestion-barrier-fixture')
        assert response.status==503,response.body
        replay=api.handle_api_request('POST','/memory/suggest',body,vault,state,bearer_secret='fixture-operator',authorization='Bearer fixture-operator',idempotency_key='suggestion-barrier-fixture')
        assert replay.status==409
        assert not list((vault/'projects/demo-agent/pending').glob('*barriered-suggestion*.md'))


def test_task_handoff_canonical_envelopes_survive_archive_validation(tmp_path):
    from arvyx_control import control
    from arvyx_control.operator_archive import _simple_history
    vault=tmp_path/'vault';vault.mkdir();state=tmp_path/'events.jsonl'
    with authority_context(vault,state):
        task=control.create_task(state,'A task',owner='demobot',idempotency_key='task-envelope-fixture',principal_scope='local:fixture').task
        control.complete_task(state,task.id,actor='demobot')
        handoff=control.create_handoff(state,'A handoff',from_agent='demobot',to_agent='vesper',idempotency_key='handoff-envelope-fixture',principal_scope='local:fixture',actor_identity_bound=True).handoff
        control.accept_handoff(state,handoff.id,actor='vesper',actor_identity_bound=True)
        control.complete_handoff(state,handoff.id,actor='operator')
        control.complete_handoff(state,handoff.id,actor='vesper',actor_identity_bound=True)
        events=control.read_events(state)
        for kind,identifier in [('task',task.id),('handoff',handoff.id)]:
            history=[event for event in events if event.task_id==identifier]
            assert 'idempotency_request' in history[0].payload
            _simple_history(history,kind)
