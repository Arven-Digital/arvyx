"""Five export units and isolated MCP, real disposable grant and manifest stores."""
import base64,hashlib,json
from datetime import datetime,UTC
import pytest
from arvyx_control.external_api import ExternalAPI,Principal
from arvyx_control.external_grants import ExternalGrantStore
from arvyx_control.external_workspace import snapshot_workspace
from arvyx_control.replica_authority import authority_context


@pytest.fixture
def external(tmp_path):
    vault=tmp_path/'vault';vault.mkdir()
    root=tmp_path/'selected';root.mkdir()
    for name,text in [('prompt.txt','Review this explicit prompt.'),('SKILL.md','Use the explicitly selected skill.'),('artifact.txt','Approved artifact bytes.'),('adjacent.txt','Unselected private context')]:
        (root/name).write_text(text)
    resources=['prompt:request','skill:review','artifact:result','task:A','workspace:project']
    with authority_context(vault):
        store=ExternalGrantStore(tmp_path/'grants.db',clock=lambda:datetime(2026,10,29,tzinfo=UTC))
        store.set_authority('issuer',resources=resources,operations=['read','lookup','list','search'],can_issue=True,can_export=True)
        docs={key:snapshot_workspace(root,[name]) for key,name in [('prompt:request','prompt.txt'),('skill:review','SKILL.md'),('artifact:result','artifact.txt')]}
        api=ExternalAPI(store,tmp_path/'work.db',credentials={hashlib.sha256(k.encode()).hexdigest():Principal(n,r) for k,n,r in [('issuer-test','issuer','issuer'),('cloud-test','cloud','external'),('local-test','local','external')]},documents=docs,workspaces={'project':snapshot_workspace(root,['artifact.txt'])},tasks={'A'},vault=vault)
        def call(method,path,body=None,who='cloud-test'):
            return api.dispatch(method,path,'Bearer '+who,body or {})
        status,grant=call('POST','/external/grants',dict(recipient='cloud',resources=resources,operations=['read','lookup','list','search'],provenance='reviewed selected resources'),who='issuer-test')
        assert status==201,grant
        yield api,store,call,grant['id'],root
        api.close();store.close()


def mcp(call,grant,name,args):
    return call('POST','/external/mcp',dict(jsonrpc='2.0',id=1,method='tools/call',params=dict(grant_id=grant,name=name,arguments=args)))


def test_all_units_have_scoped_manifest_reads_and_no_skill_directory_expansion(external):
    api,store,call,grant,root=external
    status,config=call('GET','/external/config',who='issuer-test')
    assert status==200 and {r['kind'] for r in config['resources']}=={'prompt','task','skill','artifact','workspace'}
    status,reply=mcp(call,grant,'external.read',dict(resource='skill:review'))
    assert status==200,reply
    item=json.loads(reply['result']['content'][0]['text'])
    assert [f['path'] for f in item['files']]==['SKILL.md']
    assert base64.b64decode(item['files'][0]['content_base64'])==(root/'SKILL.md').read_bytes()
    assert mcp(call,grant,'external.read',dict(resource='artifact:adjacent'))[0]==403
    assert mcp(call,grant,'memory.recall',dict(query='private'))[0]==403
    assert call('POST','/mcp',{})[0]==403
    assert call('GET',f'/external/grants/{grant}/resources/skill/review',who='local-test')[0]==403


def test_mcp_discovery_rechecks_revocation_and_manifest_changes(external):
    api,store,call,grant,root=external
    status,reply=call('POST','/external/mcp',dict(jsonrpc='2.0',id=2,method='tools/list',params=dict(grant_id=grant)))
    assert status==200 and {t['name'] for t in reply['result']['tools']}=={'external.lookup','external.read','external.list','external.search'}
    status,reply=mcp(call,grant,'external.list',{})
    assert status==200 and len(json.loads(reply['result']['content'][0]['text']))==5
    status,reply=mcp(call,grant,'external.search',dict(query='SKILL.md'))
    assert status==200 and len(json.loads(reply['result']['content'][0]['text']))==1
    (root/'SKILL.md').write_text('Changed since grant review')
    assert mcp(call,grant,'external.read',dict(resource='skill:review'))[0] in (400,403)
    assert call('POST',f'/external/grants/{grant}/revoke',who='issuer-test')[0]==200
    assert mcp(call,grant,'external.list',{})[0]==403
    assert call('POST','/external/mcp',dict(jsonrpc='2.0',id=2,method='tools/list',params=dict(grant_id=grant)))[0]==403


def test_lookup_without_read_never_returns_document_content(external):
    api,store,call,grant,root=external
    from datetime import timedelta
    from arvyx_control.external_workspace import manifest_fingerprint
    lookup=store.issue(manifest_bindings={'skill:review':manifest_fingerprint(api.documents['skill:review'])},issuer='issuer',recipient='cloud',resources=['skill:review'],operations=['lookup'],expires_at=store.clock()+timedelta(hours=1),provenance='explicit metadata lookup')
    status,result=mcp(call,lookup.id,'external.lookup',dict(resource='skill:review'))
    assert status==200
    item=json.loads(result['result']['content'][0]['text'])
    assert all('content_base64' not in f for f in item['files'])
    assert mcp(call,lookup.id,'external.read',dict(resource='skill:review'))[0]==403


def test_new_document_units_over_real_loopback_socket(external):
    import threading
    from urllib.request import Request,urlopen
    from arvyx_control.external_api import make_server
    api,store,call,grant,root=external
    server=make_server(api);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        data=json.dumps(dict(jsonrpc='2.0',id=1,method='tools/call',params=dict(grant_id=grant,name='external.read',arguments=dict(resource='prompt:request')))).encode()
        request=Request(f'http://127.0.0.1:{server.server_port}/external/mcp',data=data,headers={'Content-Type':'application/json','Authorization':'Bearer cloud-test'})
        with urlopen(request,timeout=2) as response:result=json.load(response)
        item=json.loads(result['result']['content'][0]['text'])
        assert base64.b64decode(item['files'][0]['content_base64'])==(root/'prompt.txt').read_bytes()
    finally:server.shutdown();server.server_close();thread.join(2)


def test_standard_mcp_initialization_on_exact_grant_url(external):
    _,_,call,grant,_=external
    endpoint=f'/external/grants/{grant}/mcp'
    status,result=call('POST',endpoint,dict(jsonrpc='2.0',id=1,method='initialize',params=dict(protocolVersion='2024-11-05',capabilities={},clientInfo=dict(name='fixture',version='1'))))
    assert status==200 and result['result']['capabilities']==dict(tools={})
    assert call('POST',endpoint,dict(jsonrpc='2.0',method='notifications/initialized'))[0]==202
    assert call('POST',endpoint,dict(jsonrpc='2.0',id=2,method='tools/list'))[0]==200
    status,result=call('POST',endpoint,dict(jsonrpc='2.0',id=3,method='tools/call',params=dict(name='external.search',arguments=dict(query='explicitly selected skill'))))
    assert status==200 and len(json.loads(result['result']['content'][0]['text']))==1
