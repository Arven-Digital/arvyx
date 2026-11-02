"""Production issuer presentation with independently supplied export authority.

Browser capability never becomes an external credential. Only issuer config,
reviewed grant issue/readback, scoped audit metadata and revocation are proxied. Recipient/MCP access
stays on the separately authenticated external API. No authorities are minted.
"""
import hashlib,json
from .external_api import Principal

class ExternalPresentation:
    def __init__(self,api,issuer_credential,*,vault,state):
        from pathlib import Path
        if api.vault!=Path(vault).resolve() or api.state!=(None if state is None else Path(state).resolve()):raise PermissionError('external authority binding mismatch')
        principal=api.credentials.get(hashlib.sha256(issuer_credential.encode()).hexdigest())
        if type(principal) is not Principal or principal.role!='issuer':raise PermissionError('independently provisioned issuer required')
        status,config=api.dispatch('GET','/external/config','Bearer '+issuer_credential,{})
        if status!=200 or not config['can_export']:raise PermissionError('independent export authority required')
        self.api=api;self.credential=issuer_credential
    def dispatch(self,method,path,body):
        from urllib.parse import urlsplit
        target=urlsplit(path)
        if target.scheme or target.netloc or target.fragment or '%' in target.path:
            return 403,dict(error='issuer_presentation_only')
        parts=target.path.split('/')
        audit=(len(parts)==5 and parts[1:3]==['external','grants'] and parts[-1]=='audit' and method=='GET')
        if target.query and not audit:return 403,dict(error='issuer_presentation_only')
        allowed=(path=='/external/config' and method=='GET' or path=='/external/grants' and method in ('GET','POST')
            or len(parts)==4 and parts[1:3]==['external','grants'] and method=='GET'
            or audit
            or len(parts)==5 and parts[1:3]==['external','grants'] and parts[-1]=='revoke' and method=='POST')
        if not allowed:return 403,dict(error='issuer_presentation_only')
        if method=='POST' and path=='/external/grants' and 'reviewed_manifests' not in body:return 400,dict(error='reviewed_manifest_required')
        status,result=self.api.dispatch(method,path,'Bearer '+self.credential,body)
        if path=='/external/config' and status==200:result=dict(result,fixture_only=False)
        return status,result


def handle_external(handler):
    server=handler.server
    if not getattr(server,'external',None):return handler.reply(404,dict(error='external_presentation_unconfigured'))
    if not handler.authorized(mutation=handler.command=='POST'):
        return handler.reply(403,dict(error='configured_authenticated_issuer_required'))
    if handler.headers.get_all('Origin',[]) not in ([],[server.origin]):return handler.reply(403,dict(error='same_origin_required'))
    try:
        lengths=handler.headers.get_all('Content-Length',[])
        if handler.headers.get('Transfer-Encoding') or len(lengths)>1:raise ValueError('framing')
        size=int(lengths[0]) if lengths else 0
        if not 0<=size<=32768 or (size and handler.headers.get_all('Content-Type',[])!=['application/json']):raise ValueError('framing')
        raw=handler.rfile.read(size)
        if len(raw)!=size:raise ValueError('short body')
        def unique(pairs):
            obj=dict(pairs)
            if len(obj)!=len(pairs):raise ValueError('duplicate')
            return obj
        body=json.loads(raw,object_pairs_hook=unique) if raw else {}
        if type(body) is not dict:raise ValueError('object')
        status,result=server.external.dispatch(handler.command,handler.path,body)
    except (ValueError,UnicodeError):status,result=400,dict(error='invalid_request')
    return handler.reply(status,result)


def load_presentation(config,*,vault,state):
    """Explicit local configuration; opens existing export authority, never grants it."""
    import os
    from pathlib import Path
    from .external_api import ExternalAPI
    from .external_grants import ExternalGrantStore
    from .external_workspace import snapshot_workspace,_read
    from .replica_authority import authority_context
    p=Path(config)
    if p.is_symlink() or p.stat().st_mode&0o077 or p.stat().st_uid!=os.getuid() or p.stat().st_size>1024*1024:raise ValueError('private bounded export configuration required')
    value=json.loads(p.read_text())
    required={'grants','work','credentials','issuer_credential','workspaces','documents','memory_selections','tasks','recipients'}
    if not required<=set(value) or set(value)-required-{'observers'}:raise ValueError('closed production export configuration required')
    observers=value.get('observers',[])
    if (type(observers) is not list or any(not isinstance(name,str) for name in observers) or len(observers)!=len(set(observers))
            or any(not isinstance(name,str) or not name or not any(p.get('name')==name and p.get('role')=='observer' for p in value['credentials'].values()) for name in observers)):
        raise ValueError('observer membership requires distinct explicitly provisioned observer principals')
    if not Path(value['grants']).is_file():raise PermissionError('independently provisioned existing export authority required')
    def selection(spec):
        if set(spec)!={'root','reviewed_sha256'} or type(spec['reviewed_sha256']) is not dict:raise ValueError('exact reviewed source hashes required')
        snapshot=snapshot_workspace(Path(spec['root']),list(spec['reviewed_sha256']))
        if {f.path:f.sha256 for f in snapshot.files}!=spec['reviewed_sha256']:raise ValueError('export selection changed or excluded')
        return snapshot
    with authority_context(vault,state):
        store=ExternalGrantStore(Path(value['grants']))
        api=None
        try:
            api=ExternalAPI(store,Path(value['work']),credentials={key:Principal(**principal) for key,principal in value['credentials'].items()},
                workspaces={key:selection(spec) for key,spec in value['workspaces'].items()},documents={key:selection(spec) for key,spec in value['documents'].items()},
                memory_selections=value['memory_selections'],tasks=value['tasks'],recipients=value['recipients'],observers=observers,vault=vault,state=state)
            credential,_,_=_read(Path(value['issuer_credential']).parent,(Path(value['issuer_credential']).name,),4096)
            result=ExternalPresentation(api,credential.decode().strip(),vault=vault,state=state)
            result.owns_api=True
            return result
        except BaseException:
            if api:api.close()
            store.close();raise
