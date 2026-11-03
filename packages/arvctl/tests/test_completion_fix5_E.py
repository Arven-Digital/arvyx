"""Lane E disposable authority, handler and process-recorder regressions."""
import base64
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
from unittest.mock import patch

import os
import pytest
from arvyx_control.external_api import ExternalAPI, Principal
from arvyx_control.external_grants import ExternalGrantStore
from arvyx_control.external_work import ExternalWork, WorkAuthorization
from arvyx_control.external_workspace import snapshot_workspace
from arvyx_control.machine_pairing import MachineIdentity, PairingStore
from arvyx_control.replica_authority import authority_context

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='host-shell execution policy (host_uid) and the PTY owner are POSIX-only')


@contextmanager
def authority(root, operations=('read', 'submit')):
    root=Path(root);vault=root/'vault';vault.mkdir(exist_ok=True)
    (root/'safe.txt').write_text('selected public bytes')
    (root/'SKILL.md').write_text('selected skill')
    now=datetime.now(UTC)
    store=ExternalGrantStore(root/'grants.db',clock=lambda:now)
    resources=['task:A','task:B','workspace:review','prompt:selected','skill:selected','artifact:selected']
    with authority_context(vault,root/'events.jsonl'):
        store.set_authority('issuer',resources=resources,operations=operations,can_issue=True,can_export=True)
        credentials={hashlib.sha256(k.encode()).hexdigest():Principal(*v) for k,v in {
            'fixture-issuer':('issuer','issuer'),'fixture-reader':('reader','external')}.items()}
        documents={kind+':selected':snapshot_workspace(root,['SKILL.md' if kind=='skill' else 'safe.txt']) for kind in ('prompt','skill','artifact')}
        api=ExternalAPI(store,root/'work.db',credentials=credentials,workspaces={'review':snapshot_workspace(root,['safe.txt'])},tasks={'A','B'},documents=documents,vault=vault,state=root/'events.jsonl')
        try:yield api,store,now
        finally:api.close();store.close()


def issue(api, resources, operations):
    return api.dispatch('POST','/external/grants','Bearer fixture-issuer',dict(recipient='reader',resources=resources,operations=operations,provenance='explicit disposable review'))


@pytest.mark.parametrize('kind',['workspace','prompt','skill','artifact'])
def test_submit_only_files_rejected_before_grant_publication(tmp_path,kind):
    with authority(tmp_path) as (api,store,_):
        key='workspace:review' if kind=='workspace' else kind+':selected'
        assert issue(api,[key],['submit'])[0]==400
        assert store.db.execute('SELECT count(*) FROM external_grants').fetchone()[0]==0
        assert not any(r['event']=='created' for r in store.audit())


def test_task_submit_scope_and_mixed_read_scope_remain_usable(tmp_path):
    with authority(tmp_path) as (api,store,_):
        # Mixed read + submit grants retain a useful explicit task endpoint.
        status,row=issue(api,['workspace:review','task:A'],['read','submit']);assert status==201
        prefix='/external/grants/'+row['id']
        assert api.dispatch('GET',prefix+'/resources/workspace/review','Bearer fixture-reader',{})[0]==200
        body=dict(kind='result',text='intentional result',source='fixture',submission_id='ordinary-1')
        assert api.dispatch('POST',prefix+'/tasks/A/results','Bearer fixture-reader',body)[0]==201
        assert api.dispatch('POST',prefix+'/tasks/B/results','Bearer fixture-reader',body)[0]==403


def test_read_only_authority_can_issue_and_exact_read_without_list(tmp_path):
    with authority(tmp_path,('read',)) as (api,store,_):
        assert api.dispatch('GET','/external/config','Bearer fixture-issuer',{})[1]['operations']==['read']
        status,row=issue(api,['workspace:review'],['read']);assert status==201
        status,content=api.dispatch('GET','/external/grants/'+row['id']+'/resources/workspace/review','Bearer fixture-reader',{})
        assert status==200 and base64.b64decode(content['files'][0]['content_base64'])==b'selected public bytes'
        assert store.get(row['id']).operations==frozenset({'read'})


def claims(store):
    a=MachineIdentity('reviewed A',base64.b64encode(b'a'*32).decode())
    b=MachineIdentity('unreviewed B',a.public_key)
    first=store.issue(actor='owner',ttl=100);assert store.claim(first.code,a).allowed
    return a,b


def test_pairing_decision_binds_one_stable_reviewed_claim(tmp_path):
    store=PairingStore(tmp_path/'pair.db',clock=lambda:1000)
    try:
        a,b=claims(store)
        snapshot=store.claim_snapshot(a.fingerprint)
        later=store.issue(actor='owner',ttl=300);assert store.claim(later.code,b).allowed
        result=store.decide(a.fingerprint,actor='owner',approved=True,claim_id=snapshot['claim_id'],review_snapshot=snapshot)
        assert result.allowed
        assert store.db.execute('SELECT name FROM paired_machines').fetchone()[0]=='reviewed A'
        rows=store.db.execute('SELECT name,state FROM machine_pairing_codes ORDER BY expires').fetchall()
        assert [tuple(r) for r in rows]==[('reviewed A','approved'),('unreviewed B','claimed')]
        assert not store.decide(a.fingerprint,actor='owner',approved=True,claim_id=snapshot['claim_id'],review_snapshot=snapshot).allowed
    finally:store.close()


def test_pairing_transaction_rechecks_metadata_and_refuses_fingerprint_ambiguity(tmp_path):
    store=PairingStore(tmp_path/'pair.db',clock=lambda:1000)
    try:
        a,b=claims(store);snapshot=store.claim_snapshot(a.fingerprint)
        with store.db:store.db.execute('UPDATE machine_pairing_codes SET name=?',('changed after review',))
        assert not store.decide(a.fingerprint,actor='owner',approved=True,claim_id=snapshot['claim_id'],review_snapshot=snapshot).allowed
        assert store.db.execute('SELECT count(*) FROM paired_machines').fetchone()[0]==0
        ticket=store.issue(actor='owner');assert store.claim(ticket.code,b).allowed
        assert not store.decide(a.fingerprint,actor='owner',approved=True).allowed
    finally:store.close()


def test_pairing_reviewed_router_forwards_exact_claim(tmp_path):
    from arvyx_control.local_onboarding import local_composition
    from arvyx_control.public_onboarding_api import handler_for
    from test_local_handler_wire import request
    directory=tmp_path/'local';directory.mkdir(mode=0o700)
    store=PairingStore(tmp_path/'pair.db',clock=lambda:1000)
    api=local_composition(directory,vault=tmp_path/'vault',machine_id='m',capability='browser-test',pairing=SimpleNamespace(store=store,close=lambda:None))
    server=SimpleNamespace(server_address=('127.0.0.1',12345),server_port=12345,origin='http://127.0.0.1:12345')
    try:
        a,b=claims(store)
        def call(route,body):return request(handler_for(api),server,'/api/public-onboarding/'+route,body)
        # Missing stable IDs are a separate negative control, not a positive fixture.
        assert call('actions/prepare',dict(action='pairing/decide',request=dict(fingerprint=a.fingerprint,approved=True,confirmed=True)))[0]==400
        status,review=call('actions/prepare',dict(action='pairing/decide',request=dict(fingerprint=a.fingerprint,claim_id=store.claim_snapshot(a.fingerprint)['claim_id'],approved=True,confirmed=True)))
        assert status==200
        assert isinstance(review['snapshot']['claim'],dict) and review['snapshot']['claim']['claim_id']
        ticket=store.issue(actor='owner');assert store.claim(ticket.code,b).allowed
        status,result=call('actions/commit',dict(consent_id=review['consent_id'],consent_sha256=review['sha256'],confirmed=True))
        assert status>=400 or store.db.execute('SELECT name FROM paired_machines').fetchone()[0]=='reviewed A'
        assert store.db.execute("SELECT state FROM machine_pairing_codes WHERE name='unreviewed B'").fetchone()[0]=='claimed'
    finally:api.close();store.close()


def test_reviewed_denial_preserves_existing_enrollment_until_explicit_revoke(tmp_path):
    """NOT EXECUTED in ownership pass: real prepare/commit A then deny same-key B."""
    from arvyx_control.local_onboarding import local_composition
    from arvyx_control.public_onboarding_api import handler_for
    from test_local_handler_wire import request
    directory=tmp_path/'local';directory.mkdir(mode=0o700)
    store=PairingStore(tmp_path/'pair.db',clock=lambda:1000)
    api=local_composition(directory,vault=tmp_path/'vault',machine_id='m',capability='browser-test',pairing=SimpleNamespace(store=store,close=lambda:None))
    server=SimpleNamespace(server_address=('127.0.0.1',12345),server_port=12345,origin='http://127.0.0.1:12345')
    def decide(identity,approved):
        claim_id=store.claim_snapshot(identity.fingerprint)['claim_id']
        status,review=request(handler_for(api),server,'/api/public-onboarding/actions/prepare',dict(action='pairing/decide',request=dict(fingerprint=identity.fingerprint,claim_id=claim_id,approved=approved,confirmed=True)))
        assert status==200,review
        status,result=request(handler_for(api),server,'/api/public-onboarding/actions/commit',dict(consent_id=review['consent_id'],consent_sha256=review['sha256'],confirmed=True))
        assert status==200,result
        return claim_id
    try:
        a,b=claims(store)
        first=decide(a,True)
        before=tuple(store.db.execute('SELECT * FROM paired_machines').fetchone())
        ticket=store.issue(actor='owner',ttl=300);assert store.claim(ticket.code,b).allowed
        second=decide(b,False)
        assert tuple(store.db.execute('SELECT * FROM paired_machines').fetchone())==before
        assert store.check(a).allowed
        states=dict(store.db.execute('SELECT claim_id,state FROM machine_pairing_codes').fetchall())
        assert states[first]=='approved' and states[second]=='denied'
        assert store.revoke(a,actor='owner').allowed
        assert not store.check(a).allowed
    finally:api.close();store.close()


@pytest.mark.parametrize('boundary',['prepare','record'])
def test_secret_shaped_submission_identifiers_never_persist(tmp_path,boundary):
    key='arv_fixture_'+('a'*40)
    from arvyx_control.security import contains_literal_secret
    assert contains_literal_secret(key)
    with authority(tmp_path) as (api,store,now):
        status,row=issue(api,['task:A'],['submit']);assert status==201
        if boundary=='prepare':
            with pytest.raises(ValueError):store.prepare_submission(grant_id=row['id'],principal='reader',task_id='A',submission_id=key,fingerprint='safe-fingerprint')
        else:
            with patch.object(api,'_grant',store.get(row['id'])):
                with pytest.raises(ValueError):api.work.submit('A',actor='reader',kind='result',text='safe',source='fixture',record_id=key)
        for path in tmp_path.glob('*.db*'):assert key.encode() not in path.read_bytes()


def wire_main():
    """Real adapter/API composition over a local line recorder; no listener."""
    import sys
    with tempfile.TemporaryDirectory(prefix='E-wire-') as directory:
        with authority(directory,('read',)) as (api,store,_):
            for line in sys.stdin:
                row=json.loads(line)
                status,body=api.dispatch(row['method'],row['path'],row['authorization'],row.get('body') or {})
                print(json.dumps(dict(status=status,body=body)),flush=True)


if __name__=='__main__':wire_main()


def test_proof_backed_same_key_claim_and_stable_id_reopen(tmp_path):
    from arvyx_control.machine_pairing_transport import PairingTransport, load_identity
    transport=PairingTransport(tmp_path/'main',clock=lambda:1000)
    key=load_identity(tmp_path/'remote')
    def claim(name,ttl):
        ticket=transport.store.issue(actor='owner',ttl=ttl)
        public=transport.public(key,name)
        challenge=transport.challenge(dict(public,purpose='confirm',code=ticket.code))
        signature=base64.b64encode(key.sign(base64.b64decode(challenge['message']))).decode()
        return transport.prove(dict(challenge=challenge['challenge'],signature=signature,code=ticket.code))
    try:
        first=claim('proof-reviewed A',100);snapshot=transport.store.claim_snapshot(first['fingerprint'])
        claim('proof-unreviewed B',300)
        transport.close();transport=PairingTransport(tmp_path/'main',clock=lambda:1000)
        assert transport.store.claim_snapshot(first['fingerprint'],snapshot['claim_id'])==snapshot
        result=transport.store.decide(first['fingerprint'],actor='owner',approved=True,claim_id=snapshot['claim_id'],review_snapshot=snapshot)
        assert result.allowed
        assert transport.store.db.execute('SELECT name FROM paired_machines').fetchone()[0]=='proof-reviewed A'
        assert transport.store.db.execute("SELECT state FROM machine_pairing_codes WHERE name='proof-unreviewed B'").fetchone()[0]=='claimed'
    finally:transport.close()


def test_pairing_and_connection_effects_recheck_original_expiry_after_wait(tmp_path):
    from arvyx_control.reviewed_actions import consent_scope
    store=PairingStore(tmp_path/'pair.db',clock=lambda:1000)
    try:
        a,_=claims(store);snapshot=store.claim_snapshot(a.fingerprint)
        now=[100.0]
        with patch('arvyx_control.reviewed_actions.time.time',side_effect=lambda:now[0]):
            with consent_scope(101):
                original=store._now
                def delayed():now[0]=102;return original()
                with patch.object(store,'_now',side_effect=delayed):
                    with pytest.raises(ValueError,match='consent expired'):
                        store.decide(a.fingerprint,actor='owner',approved=True,claim_id=snapshot['claim_id'],review_snapshot=snapshot)
        assert store.db.execute('SELECT count(*) FROM paired_machines').fetchone()[0]==0
        assert store.claim_snapshot(a.fingerprint)==snapshot
    finally:store.close()


from test_local_onboarding_services import services
from test_session_workspace_journey import journey, plan, commit


def test_persisted_owner_list_reopens_through_new_review_without_another_process(journey,tmp_path):
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control.native_lifecycle import OwnerProducer, NativeLifecycle
    from arvyx_control.local_executor import ExecutionPolicy
    api,call,target,root,_=journey;extension=api.owners['local-owner'].extension
    owner=LocalCockpit(tmp_path/'owner',extension.vault,tmp_path/'events.jsonl','machine-a')
    producer=OwnerProducer(owner,policy=ExecutionPolicy(host_uid=__import__('os').geteuid(),allow_host=True))
    extension.native=NativeLifecycle(extension,producer)
    def process(sid,**kw):
        assert kw['argv']==['/bin/sh','-i']
        # Process recorder: record what a real _start publishes (a running row
        # plus one exact process generation) without forking anything.
        owner.live[sid]=dict(fd=None,attached=False,process_generation='synthetic-'+sid)
        owner.db.execute("UPDATE sessions SET status='running' WHERE id=?",(sid,));owner.db.commit()
    try:
        with patch.object(owner,'_start',side_effect=process) as recorder:
            review=call('native/prepare',dict(plan(target,'existing','existing'),environment='host',harness='shell',root_acknowledged=False))[1]
            status,created=call('native/commit',commit(review));assert status==201,created
            assert recorder.call_count==1
            # Discard lifecycle view while retaining durable attempt rows and owner.
            extension.native=NativeLifecycle(extension,producer)
            status,page=call('native/sessions',dict(target=target,limit=1,cursor=None));assert status==200
            assert page['items'][0]['owner_session']==created['owner_session']
            assert page['items'][0]['target']==target
            assert 'attachment' not in page['items'][0]
            with patch.object(producer,'attach',return_value={'attachment':'fresh-local-recorder'}) as attach:
                status,opened=call('native/open',dict(target=target,owner_session=created['owner_session'],confirmed=True))
                assert status==200,opened
                assert opened['owner_session']==created['owner_session']
                assert opened['attachment']['attachment']=='fresh-local-recorder'
                attach.assert_called_once()
            assert recorder.call_count==1
            results=extension.owner.creation.db.execute("SELECT result FROM reviewed_actions WHERE action='native/open'").fetchall()
            assert results and all('fresh-local-recorder' not in row[0] for row in results)
    finally:
        owner.live.clear()  # Synthetic generation only; no process exists.
        owner.close()


def test_direct_file_submit_grant_and_secret_api_key_create_no_durable_attempt(tmp_path):
    with authority(tmp_path) as (api,store,now):
        with pytest.raises(ValueError,match='explicitly selected task'):
            store.issue(issuer='issuer',recipient='reader',resources=['artifact:selected'],operations=['submit'],expires_at=now+timedelta(hours=1),provenance='direct explicit selection')
        assert store.db.execute('SELECT count(*) FROM external_grants').fetchone()[0]==0
        status,row=issue(api,['task:A'],['submit']);assert status==201
        key='arv_fixture_'+('b'*40)
        body=dict(kind='result',text='public result',source='fixture',submission_id=key)
        assert api.dispatch('POST','/external/grants/'+row['id']+'/tasks/A/results','Bearer fixture-reader',body)[0]==400
        assert store.db.execute('SELECT count(*) FROM external_submission_attempts').fetchone()[0]==0
        assert api.work._db.execute('SELECT count(*) FROM external_work').fetchone()[0]==0
        for path in tmp_path.glob('*.db*'):assert key.encode() not in path.read_bytes()


def test_connection_router_expiry_before_publication_preserves_old_connection(journey):
    api,call,target,_,body=journey;extension=api.owners['local-owner'].extension
    status,review=call('actions/prepare',dict(action='manual/connect',request=body));assert status==200
    now=[review['expires_at']-1]
    original=extension.route
    def after_wait(path,method,payload,**kwargs):
        if path=='manual/connect':now[0]=review['expires_at']+1
        return original(path,method,payload,**kwargs)
    before=extension.owner.creation.db.execute('SELECT target FROM onboarding_connections').fetchone()[0]
    with patch('arvyx_control.reviewed_actions.time.time',side_effect=lambda:now[0]),patch.object(extension,'route',side_effect=after_wait):
        status,result=call('actions/commit',commit(review))
    assert status==503 and result['reconcile_required']
    assert extension.owner.creation.db.execute('SELECT target FROM onboarding_connections').fetchone()[0]==before
    assert len(extension.owner.targets)==1


def test_pairing_claim_arriving_after_review_validation_cannot_replace_reviewed_metadata(tmp_path):
    from arvyx_control.local_onboarding import local_composition
    from arvyx_control.public_onboarding_api import handler_for
    from test_local_handler_wire import request
    directory=tmp_path/'local';directory.mkdir(mode=0o700)
    store=PairingStore(tmp_path/'pair.db',clock=lambda:1000)
    api=local_composition(directory,vault=tmp_path/'vault',machine_id='m',capability='browser-test',pairing=SimpleNamespace(store=store,close=lambda:None))
    server=SimpleNamespace(server_address=('127.0.0.1',12345),server_port=12345,origin='http://127.0.0.1:12345')
    try:
        a,b=claims(store);extension=api.owners['local-owner'].extension
        def call(route,body):return request(handler_for(api),server,'/api/public-onboarding/'+route,body)
        status,review=call('actions/prepare',dict(action='pairing/decide',request=dict(fingerprint=a.fingerprint,claim_id=store.claim_snapshot(a.fingerprint)['claim_id'],approved=True,confirmed=True)));assert status==200
        original=extension.route
        def after_validation(path,method,body,**kwargs):
            if path=='pairing/decide':
                assert kwargs['review_snapshot']['claim']['claim_id']==review['snapshot']['claim']['claim_id']
                ticket=store.issue(actor='owner',ttl=300);assert store.claim(ticket.code,b).allowed
            return original(path,method,body,**kwargs)
        with patch.object(extension,'route',side_effect=after_validation):
            status,result=call('actions/commit',commit(review))
        assert status==200,result
        assert store.db.execute('SELECT name FROM paired_machines').fetchone()[0]=='reviewed A'
        assert store.db.execute("SELECT state FROM machine_pairing_codes WHERE name='unreviewed B'").fetchone()[0]=='claimed'
    finally:api.close();store.close()
