"""Integrate preserved external-audit additions with disposable exact authority."""
from contextlib import contextmanager
from datetime import timedelta
import hashlib,json,os
from urllib.parse import quote
import pytest
from test_completion_fix5_E import authority,issue
from arvyx_control.external_api import ExternalAPI,Principal


@contextmanager
def configured(root):
    with authority(root) as (original,store,now):
        credentials=dict(original.credentials)
        credentials[hashlib.sha256(b'synthetic-observer').hexdigest()]=Principal('observer','observer')
        credentials[hashlib.sha256(b'synthetic-foreign').hexdigest()]=Principal('foreign','issuer')
        api=ExternalAPI(store,root/'audit-work.db',credentials=credentials,workspaces=original.workspaces,
            tasks={'A','B'},documents=original.documents,observers=['observer'],vault=original.vault,state=original.state)
        try:yield api,store,now
        finally:api.close()


def read(api,grant,who='fixture-issuer',cursor=None,limit=1):
    query='?limit='+str(limit)+('&cursor='+quote(cursor,safe='') if cursor else '')
    path='/external/grants/'+grant+'/audit'+query
    if os.environ.get('AMC_FIX5_AUDIT_HOST_HTTP')=='1':
        import http.client,threading
        from arvyx_control.external_api import make_server
        server=make_server(api);thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);thread.start()
        try:
            connection=http.client.HTTPConnection(*server.server_address,timeout=3)
            try:
                connection.request('GET',path,headers={'Authorization':'Bearer '+who})
                response=connection.getresponse();return response.status,json.loads(response.read())
            finally:connection.close()
        finally:server.shutdown();server.server_close();thread.join(3)
    return api.dispatch('GET',path,'Bearer '+who,{})


def test_audit_scope_projection_and_legacy_coverage_are_exact(tmp_path):
    with configured(tmp_path) as (api,store,now):
        status,result=issue(api,['task:A'],['read']);assert status==201;grant=result['id']
        status,result=issue(api,['task:B'],['read']);assert status==201;other=result['id']
        with store.db:
            # Legacy administrative history has no authenticated scope index;
            # it remains retained rather than being guessed/backfilled.
            store.db.execute('INSERT INTO external_grant_audit(timestamp,event,details) VALUES(?,?,?)',(now.isoformat(),'legacy-unindexed',json.dumps(dict(grant_id=grant,reasoning='SYNTHETIC_HIDDEN_LEGACY'))))
            store._record('synthetic-projection',now,grant_id=grant,actor='operator',reasoning='SYNTHETIC_HIDDEN_REASONING',value='SYNTHETIC_HIDDEN_VALUE')
            store._record('foreign-grant-event',now,grant_id=other,actor='foreign')
        status,page=read(api,grant,limit=100);assert status==200,page
        assert page['coverage']=='scope-indexed-events-only'
        assert page['items'] and all(item['details']['grant_id']==grant for item in page['items'])
        raw=json.dumps(page)
        assert 'SYNTHETIC_HIDDEN' not in raw and 'legacy-unindexed' not in raw and 'foreign-grant-event' not in raw
        assert any(r['event']=='legacy-unindexed' for r in store.audit())
        assert read(api,grant,'fixture-reader')[0]==403
        assert read(api,grant,'synthetic-foreign')[0]==403


@pytest.mark.parametrize('change',['revoke','issuer','excluded','expired'])
def test_observer_audit_rechecks_full_authority_on_every_page(tmp_path,change):
    with configured(tmp_path) as (api,store,now):
        grant=issue(api,['task:A'],['read'])[1]['id']
        for i in range(4):store._transaction(lambda:store._record('synthetic-progress',now,grant_id=grant,actor='worker'))
        status,page=read(api,grant,'synthetic-observer');assert status==200 and page['has_more']
        cursor=page['next_cursor']
        if change=='revoke':store.revoke(grant,actor='issuer')
        elif change=='issuer':store.set_authority('issuer',resources=['task:B'],operations=['read'],can_issue=True,can_export=True)
        elif change=='excluded':store.set_excluded('task:A')
        else:store.clock=lambda:now+timedelta(days=2)
        assert read(api,grant,'synthetic-observer',cursor)[0]==403


def test_audit_cursor_is_grant_and_principal_bound_after_reopen(tmp_path):
    from arvyx_control.external_grants import ExternalGrantStore
    with configured(tmp_path) as (api,store,now):
        grant=issue(api,['task:A'],['read'])[1]['id'];other=issue(api,['task:B'],['read'])[1]['id']
        for i in range(4):store._transaction(lambda:store._record('synthetic-progress',now,grant_id=grant,actor='worker'))
        page=read(api,grant)[1];cursor=page['next_cursor'];assert cursor
        assert read(api,other,cursor=cursor)[0]==400
        assert read(api,grant,'synthetic-observer',cursor)[0]==400
        reopened=ExternalGrantStore(tmp_path/'grants.db',clock=lambda:now)
        restored=ExternalAPI(reopened,tmp_path/'reopened-work.db',credentials=api.credentials,
            workspaces=api.workspaces,tasks={'A','B'},documents=api.documents,observers=['observer'],vault=api.vault,state=api.state)
        try:
            status,next_page=read(restored,grant,cursor=cursor);assert status==200
            assert next_page['items'][0]['sequence']>page['items'][-1]['sequence']
        finally:restored.close();reopened.close()


def test_scope_index_failure_rolls_back_the_same_authority_transaction(tmp_path):
    import sqlite3
    with configured(tmp_path) as (api,store,now):
        grant=issue(api,['task:A'],['read'])[1]['id']
        before=store.audit()
        store.db.execute("CREATE TEMP TRIGGER reject_scope BEFORE INSERT ON external_grant_audit_scope BEGIN SELECT RAISE(ABORT,'synthetic scope failure'); END")
        with pytest.raises(sqlite3.IntegrityError):store.revoke(grant,actor='issuer')
        assert store.get(grant).revoked_at is None and store.audit()==before
