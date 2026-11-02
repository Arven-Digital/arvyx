import base64,hashlib,json
from types import SimpleNamespace
from test_pass2_external_units import external
from test_local_handler_wire import request
from arvyx_control.cockpit_local import LocalHandler

def test_production_issuer_is_explicit_same_origin_and_separate(external):
    from arvyx_control.external_presentation import ExternalPresentation
    api,store,call,grant,root=external
    presentation=ExternalPresentation(api,'issuer-test',vault=api.vault,state=api.state)
    server=SimpleNamespace(origin='http://127.0.0.1:12345',capability='browser-test',external=presentation)
    status,result=request(LocalHandler,server,'/external/config')
    assert status==200 and result['fixture_only'] is False and result['can_export']
    assert 'issuer-test' not in json.dumps(result)
    assert request(LocalHandler,server,'/external/config',auth=False)[0]==403
    assert request(LocalHandler,server,'/external/grants',{},origin=False)[0]==403
    assert request(LocalHandler,server,'/external/mcp',{})[0]==403


def test_large_export_exact_continuation_and_revocation_between_pages(external):
    from arvyx_control.external_workspace import snapshot_workspace,WorkspaceLimits
    api,store,call,grant,root=external
    data=('approved text\n'*60000).encode();(root/'large.txt').write_bytes(data)
    api.workspaces['project']=snapshot_workspace(root,['large.txt'])
    assert call('GET',f'/external/grants/{grant}/resources/workspace/project')[0]==403
    status,fresh=call('POST','/external/grants',dict(recipient='cloud',resources=['workspace:project'],operations=['read','lookup','list','search'],provenance='explicit fresh manifest review'),who='issuer-test')
    assert status==201,fresh
    grant=fresh['id']
    digest=hashlib.sha256(data).hexdigest();offset=0;chunks=[]
    status,manifest=call('POST',f'/external/grants/{grant}/manifest',dict(resource='workspace:project',cursor=None,limit=20))
    assert status==200 and manifest['files']==[dict(path='large.txt',size=len(data),sha256=digest)]
    assert call('GET',f'/external/grants/{grant}/resources/workspace/project')[0]==400  # whole response remains bounded
    while offset is not None:
        status,page=call('POST',f'/external/grants/{grant}/download',dict(resource='workspace:project',path='large.txt',sha256=digest,offset=offset,limit=65536))
        assert status==200,page
        chunks.append(base64.b64decode(page['content_base64']));offset=page['next_offset']
    assert b''.join(chunks)==data
    assert call('POST',f'/external/grants/{grant}/download',dict(resource='workspace:project',path='large.txt',sha256='0'*64,offset=0,limit=100))[0]==400
    store.revoke(grant,actor='issuer')
    assert call('POST',f'/external/grants/{grant}/download',dict(resource='workspace:project',path='large.txt',sha256=digest,offset=65536,limit=100))[0]==403


def test_manifest_pages_and_mcp_chunk_form_keep_the_exact_grant(external):
    from arvyx_control.external_workspace import snapshot_workspace
    api,store,call,grant,root=external
    names=[]
    for i in range(205):
        name=f'memory-{i:03}.txt';(root/name).write_text(f'Approved {i}\n');names.append(name)
    api.workspaces['project']=snapshot_workspace(root,names)
    assert call('GET',f'/external/grants/{grant}/resources/workspace/project')[0]==403
    status,fresh=call('POST','/external/grants',dict(recipient='cloud',resources=['workspace:project'],operations=['read','lookup','list','search'],provenance='explicit fresh manifest review'),who='issuer-test')
    assert status==201,fresh
    grant=fresh['id']
    seen=[];cursor=None
    while True:
        status,page=call('POST',f'/external/grants/{grant}/manifest',dict(resource='workspace:project',cursor=cursor,limit=17))
        assert status==200,page
        assert all('content_base64' not in f for f in page['files'])
        seen.extend(f['path'] for f in page['files']);cursor=page['next_cursor']
        if cursor is None:break
    assert seen==names
    def mcp(name,args):return call('POST',f'/external/grants/{grant}/mcp',dict(jsonrpc='2.0',id=1,method='tools/call',params=dict(name=name,arguments=args)))
    status,result=mcp('external.lookup',dict(resource='workspace:project',cursor=None,limit=1));assert status==200,result
    first=json.loads(result['result']['content'][0]['text'])['files'][0]
    args=dict(resource='workspace:project',path=first['path'],sha256=first['sha256'],offset=0,limit=4)
    status,result=mcp('external.read',args);assert status==200,result
    assert base64.b64decode(json.loads(result['result']['content'][0]['text'])['content_base64'])==b'Appr'
    store.revoke(grant,actor='issuer')
    assert mcp('external.read',args)[0]==403
