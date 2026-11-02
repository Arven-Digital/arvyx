"""Isolated local delegation transport. No shared router or provider integration.

Trusted composition owns credentials, manifests and observer membership. Call
make_server(api).serve_forever() in a local launcher; bind is loopback-only.
"""
import base64
from dataclasses import dataclass
from datetime import timedelta
import hashlib
from http.server import BaseHTTPRequestHandler
import json
from .security import bounded_json_loads
import math
import sqlite3
from urllib.parse import urlsplit, parse_qsl

from .external_gateway import ExternalGateway, ExternalIdentity, Resource, AccessDenied
from .public_onboarding_api import BoundedOnboardingServer, assert_request_active
from .external_work import ExternalWork, WorkAuthorization, validate_submission
from .external_workspace import export_snapshot


MAX_RESPONSE_BYTES = 1024 * 1024
MAX_RESPONSE_FILE_BYTES = 256 * 1024


def _encoded_size(value, *, budget=MAX_RESPONSE_BYTES, depth=0):
    """Count default ensure_ascii JSON bytes before allocating encoded strings.

    Closed DTOs only. Count punctuation, escaping and base64 separately from raw
    workspace bytes; an allowed manifest count is not an HTTP response budget.
    """
    if depth > 64 or budget < 0:
        raise ValueError('response byte/depth budget exceeded')
    if isinstance(value, str):
        size = 2
        for character in value:
            code = ord(character)
            size += (2 if character in '\\"\b\f\n\r\t' else
                     6 if code < 32 or 127 <= code <= 65535 else
                     12 if code > 65535 else 1)
            if size > budget:
                raise ValueError('response byte budget exceeded')
    elif isinstance(value, (list, tuple, dict)):
        if len(value) > 10000:
            raise ValueError('response entry budget exceeded')
        size = 2
        entries = value.items() if isinstance(value, dict) else value
        for index, entry in enumerate(entries):
            size += 2 if index else 0
            if isinstance(value, dict):
                key, child = entry
                if not isinstance(key, str):
                    raise ValueError('response keys must be strings')
                size += _encoded_size(key, budget=budget-size, depth=depth+1) + 2
            else:
                child = entry
            size += _encoded_size(child, budget=budget-size, depth=depth+1)
    elif value is None or type(value) is bool:
        size = 4 if value is None or value is True else 5
    elif type(value) is int and value.bit_length() <= 64:
        size = len(str(value))
    elif type(value) is float and math.isfinite(value):
        size = len(json.dumps(value))
    else:
        raise ValueError('unsupported response value')
    if size > budget:
        raise ValueError('response byte budget exceeded')
    return size


@dataclass(frozen=True)
class Principal:
    name: str
    role: str

    def __post_init__(self):
        ExternalIdentity(self.name)
        if self.role not in {'external', 'issuer', 'observer'}:
            raise ValueError('unknown role')


from .replica_authority import owner_entry, ReplicaAuthorityUnavailable


class ExternalAPI:
    def __init__(self, store, work_path, *, credentials, workspaces, tasks, observers=(), recipients=None, vault=None, state=None,documents=None,memory_selections=None):
        from pathlib import Path
        from .replica_authority import assert_mutation_authority
        self.vault = None if vault is None else Path(vault).resolve()
        self.state = None if state is None else Path(state).resolve()
        if self.vault is not None:
            assert_mutation_authority(self.vault)
        self.store = store
        self.credentials = dict(credentials)
        external_names = {p.name for p in self.credentials.values()
                          if type(p) is Principal and p.role == 'external'}
        metadata = recipients or {}
        if not set(metadata) <= external_names:
            raise ValueError('recipient metadata requires a provisioned external principal')
        self.recipients = []
        for name in sorted(external_names):
            item = metadata.get(name, {})
            if set(item) - {'label', 'location'} or item.get('location', 'local') not in {'cloud', 'local'}:
                raise ValueError('invalid recipient metadata')
            label = item.get('label', name)
            if not isinstance(label, str) or not label.strip():
                raise ValueError('recipient label required')
            self.recipients.append(dict(id=name, label=label, location=item.get('location', 'local')))
        self.workspaces = dict(workspaces)
        # Only trusted, hash-pinned explicit selections become document units.
        # SKILL.md links and parent directories never expand the selection.
        from .external_workspace import WorkspaceSnapshot
        self.documents=dict(documents or {})
        if memory_selections:
            from .external_memory import reviewed_memory_snapshot
            if self.vault is None:raise ValueError('explicit memory vault authority required')
            for key,selection in memory_selections.items():
                if not key.startswith('artifact:') or key in self.documents:raise ValueError('unique exact memory artifact resource required')
                self.documents[key]=reviewed_memory_snapshot(self.vault,selection)
        for key,snapshot in self.documents.items():
            resource=Resource(*key.split(':',1))
            if (resource.kind not in {'prompt','skill','artifact'}
                    or not isinstance(snapshot,WorkspaceSnapshot) or snapshot.coverage!='selection'):
                raise ValueError('explicit selected document manifest required')
            if resource.kind=='skill' and (len(snapshot.files)!=1 or snapshot.files[0].path.split('/')[-1]!='SKILL.md'):
                raise ValueError('skill unit must select exactly SKILL.md')
        self.tasks = frozenset(tasks)
        self.observers = frozenset(observers)
        self.work = ExternalWork(work_path, authorize=self._work_auth,
                                 clock=lambda: store.clock().timestamp())
        self._grant = None  # Only used inside store's serializing authority transaction.

    def close(self):
        self.work.close()

    def _work_auth(self, actor, task, operation):
        grant = self._grant
        if grant is None:
            return None
        # Observer access is an explicit local policy, never an HTTP claim.
        observer = actor in self.observers and operation == 'read'
        decision = (self.store.decide_observer(grant.id, principal=actor, resource='task:' + task)
                    if observer else self.store.decide(grant.id, principal=actor,
                        resource='task:' + task, operation=operation))
        if not decision.allowed:
            return None
        return WorkAuthorization(task, grant.id, grant.recipient, self.observers,
            grant.operations, grant.expires_at.timestamp(), grant.revoked_at is not None,
            grant.provenance, frozenset({'read'}) if observer else frozenset())

    def _registered(self, resource):
        return ((resource.kind == 'workspace' and resource.identifier in self.workspaces)
                or (resource.kind == 'task' and resource.identifier in self.tasks)
                or resource.kind+':'+resource.identifier in self.documents)

    def _snapshot(self,resource, *, granted=False):
        snapshot = (self.workspaces.get(resource.identifier) if resource.kind=='workspace'
                    else self.documents.get(resource.kind+':'+resource.identifier))
        if granted and resource.kind != 'task':
            from .external_workspace import manifest_fingerprint
            key = resource.kind + ':' + resource.identifier
            if (snapshot is None or self._grant is None or
                    self.store.manifest_bindings(self._grant.id).get(key) != manifest_fingerprint(snapshot)):
                raise AccessDenied()
        return snapshot

    def _require_manifest_bindings(self):
        if self._grant is None:
            raise AccessDenied()
        for key in self._grant.resources:
            resource = Resource(*key.split(':', 1))
            if not self._registered(resource):
                raise AccessDenied()
            self._snapshot(resource, granted=True)

    @staticmethod
    def _manifest_record(snapshot):
        if len(snapshot.files) + len(snapshot.excluded) > 1000:
            raise ValueError('response manifest budget exceeded')
        return dict(coverage=snapshot.coverage, complete=snapshot.complete,
            files=[dict(path=f.path, size_bytes=f.size, sha256=f.sha256) for f in snapshot.files],
            excluded=[dict(path=f.path, reason=f.reason) for f in snapshot.excluded])

    def _read_plan(self, resource):
        if not self._registered(resource):
            raise AccessDenied()
        item = dict(kind=resource.kind, id=resource.identifier)
        encoded_content_bytes = 0
        snapshot=self._snapshot(resource, granted=True)
        if snapshot is not None:
            if len(snapshot.files) + len(snapshot.excluded) > 1000:
                raise ValueError('response manifest budget exceeded')
            # Plan the exact JSON size with empty base64 placeholders BEFORE
            # reading file bytes or materializing any encoded file content.
            files = []
            encoded_content_bytes = 0
            for entry in snapshot.files:
                if type(entry.size) is not int or not 0 <= entry.size <= MAX_RESPONSE_FILE_BYTES:
                    raise ValueError('response file byte budget exceeded')
                record = dict(path=entry.path, size=entry.size, sha256=entry.sha256, content_base64='')
                encoded_content_bytes += 4 * ((entry.size + 2) // 3)
                if encoded_content_bytes + _encoded_size(record) > MAX_RESPONSE_BYTES:
                    raise ValueError('response byte budget exceeded')
                files.append(record)
            item.update(coverage=snapshot.coverage, complete=snapshot.complete,
                        excluded_count=len(snapshot.excluded), files=files)
            if _encoded_size(item) + encoded_content_bytes > MAX_RESPONSE_BYTES:
                raise ValueError('response byte budget exceeded')
        return item, _encoded_size(item) + encoded_content_bytes

    def read(self, *, resource, actor):
        item, _ = self._read_plan(resource)
        snapshot=self._snapshot(resource, granted=True)
        if snapshot is not None:
            content = export_snapshot(snapshot)
            # Completeness describes omissions within this explicit coverage.
            item.update(coverage=snapshot.coverage, complete=snapshot.complete, excluded_count=len(snapshot.excluded),
                files=[dict(path=f.path, size=f.size, sha256=f.sha256,
                    content_base64=base64.b64encode(content[f.path]).decode('ascii'))
                    for f in snapshot.files])
        return item

    def lookup(self,*,resource,actor):
        if not self._registered(resource):raise AccessDenied()
        item=dict(kind=resource.kind,id=resource.identifier)
        snapshot=self._snapshot(resource, granted=True)
        if snapshot is not None:
            item.update(coverage=snapshot.coverage,complete=snapshot.complete,excluded_count=len(snapshot.excluded),
                files=[dict(path=f.path,size=f.size,sha256=f.sha256) for f in snapshot.files])
        _encoded_size(item)
        return item

    def _download(self,principal,body):
        if principal.role!='external' or set(body)!={'resource','path','sha256','offset','limit'} or not isinstance(body.get('resource'),str):raise AccessDenied()
        resource=Resource(*body['resource'].split(':',1))
        if not self._registered(resource) or not self.allows(principal=principal.name,resource=resource,operation='read',tool='external.read'):raise AccessDenied()
        snapshot=self._snapshot(resource, granted=True)
        if snapshot is None:raise ValueError('file-backed resource required')
        entry=next((f for f in snapshot.files if f.path==body['path']),None)
        offset,limit=body['offset'],body['limit']
        if (entry is None or body['sha256']!=entry.sha256 or type(offset) is not int or not 0<=offset<=entry.size
                or type(limit) is not int or not 1<=limit<=65536):raise ValueError('exact hash and bounded byte cursor required')
        from .external_workspace import read_snapshot_file
        data=read_snapshot_file(snapshot,entry.path);end=min(entry.size,offset+limit)
        return dict(resource=body['resource'],path=entry.path,sha256=entry.sha256,size=entry.size,
            offset=offset,next_offset=end if end<entry.size else None,content_base64=base64.b64encode(data[offset:end]).decode('ascii'))

    def _manifest_page(self,principal,body):
        if principal.role!='external' or set(body)!={'resource','cursor','limit'} or not isinstance(body.get('resource'),str):raise AccessDenied()
        resource=Resource(*body['resource'].split(':',1))
        if not self._registered(resource) or not any(self.allows(principal=principal.name,resource=resource,operation=op,tool='external.'+op) for op in ('read','lookup')):raise AccessDenied()
        snapshot=self._snapshot(resource, granted=True)
        if snapshot is None or type(body['limit']) is not int or not 1<=body['limit']<=100:raise ValueError('bounded file manifest page required')
        from .external_workspace import _verify_inventory
        _verify_inventory(snapshot)
        fingerprint=hashlib.sha256(json.dumps([self._grant.id,principal.name,body['resource'],[(f.path,f.size,f.sha256) for f in snapshot.files]],separators=(',',':')).encode()).hexdigest()
        offset=0
        if body['cursor'] is not None:
            parts=body['cursor'].split(':') if isinstance(body['cursor'],str) else []
            if len(parts)!=2 or parts[0]!=fingerprint or not parts[1].isascii() or not parts[1].isdecimal() or len(parts[1])>6:raise ValueError('exact manifest cursor required')
            offset=int(parts[1])
        if offset>len(snapshot.files):raise ValueError('manifest cursor out of bounds')
        files=[];used=1024
        for entry in snapshot.files[offset:offset+body['limit']]:
            item=dict(path=entry.path,size=entry.size,sha256=entry.sha256);charge=_encoded_size(item)
            if used+charge>MAX_RESPONSE_BYTES:break
            files.append(item);used+=charge+2
        end=offset+len(files)
        return dict(resource=body['resource'],files=files,total=len(snapshot.files),coverage=snapshot.coverage,complete=snapshot.complete,
            excluded_count=len(snapshot.excluded),next_cursor=fingerprint+':'+str(end) if end<len(snapshot.files) else None)

    def write(self, **kwargs):
        raise AccessDenied()  # Workspace/resource mutation is never supported.

    def allows(self, *, principal, resource, operation, tool):
        if self._grant is None or tool not in {'external.' + op for op in ('lookup','read','list','search')}:
            return False
        try:
            self._snapshot(resource, granted=True)
        except AccessDenied:
            return False
        return self.store.decide(self._grant.id, principal=principal,
            resource=resource.kind + ':' + resource.identifier, operation=operation).allowed

    @owner_entry
    def dispatch(self, method, path, authorization, body):
        try:
            from .replica_authority import assert_bound_authority
            assert_bound_authority()
            if not authorization.startswith('Bearer '):
                raise AccessDenied()
            digest = hashlib.sha256(authorization[7:].encode()).hexdigest()
            principal = self.credentials.get(digest)
            if type(principal) is not Principal:
                raise AccessDenied()
            parts = urlsplit(path)
            if parts.fragment or '%' in parts.path:
                raise ValueError('canonical path required')
            segments = parts.path.strip('/').split('/')
            pagination = None
            if parts.query:
                result_page = (len(segments) == 6 and segments[3] == 'tasks'
                               and segments[5:] == ['results'])
                audit_page = len(segments) == 4 and segments[3] == 'audit'
                if (method != 'GET' or segments[:2] != ['external', 'grants']
                        or not (result_page or audit_page)):
                    raise ValueError('pagination only supported on results or audit')
                pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True, max_num_fields=2)
                if len({key for key, value in pairs}) != len(pairs):
                    raise ValueError('duplicate pagination parameter')
                pagination = dict(pairs)
                if not pagination or set(pagination) - {'limit', 'cursor'}:
                    raise ValueError('closed pagination schema')
                if 'limit' in pagination:
                    value = pagination['limit']
                    if not value.isascii() or not value.isdecimal():
                        raise ValueError('decimal limit required')
                    pagination['limit'] = int(value)
                if 'cursor' in pagination and not pagination['cursor']:
                    raise ValueError('nonempty cursor required')
            if type(body) is not dict:
                raise ValueError('object required')
            if segments == ['external', 'config'] and method == 'GET' and not body:
                return self.store.serialized(lambda: (200, self._config(principal)))
            if segments == ['external','mcp'] and method=='POST':
                return self.store.serialized(lambda:self._mcp(principal,body))
            if (len(segments)==4 and segments[:2]==['external','grants']
                    and segments[3]=='mcp' and method=='POST'):
                return self.store.serialized(lambda:self._mcp(principal,body,grant_id=segments[2]))
            if segments[:2] != ['external', 'grants']:
                raise AccessDenied()
            if (method == 'POST' and len(segments) == 6 and segments[3] == 'tasks'
                    and segments[5] == 'results'):
                return self._submit(segments[2], segments[4], principal, body)
            def action():
                assert_request_active()
                return self._route(method, segments[2:], principal, body, pagination=pagination)
            # BEGIN IMMEDIATE spans decision and verified export or work reads.
            # Other store instances cannot revoke until this operation linearizes.
            return self.store.serialized(action)
        except PermissionError:
            return 403, {'error':'access denied'}
        except (ValueError, TypeError, KeyError, UnicodeError):
            return 400, {'error':'invalid request'}
        except sqlite3.Error:
            return 403, {'error':'access denied'}

    def _submit(self, grant_id, task, principal, body):
        if principal.role != 'external' or task not in self.tasks:
            raise AccessDenied()
        if set(body) not in ({'kind', 'text', 'source'}, {'kind', 'text', 'source', 'submission_id'}):
            raise ValueError('closed submission schema')
        if 'submission_id' in body and not isinstance(body['submission_id'], str):
            raise ValueError('submission identifier must be text')
        validate_submission(body['kind'], body['text'], body['source'])
        # Include every caller-controlled content field; the key is separately
        # scoped to the authenticated principal, grant and task by the store.
        payload = {key: body[key] for key in ('kind', 'text', 'source')}
        fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True,
            ensure_ascii=True, separators=(',', ':')).encode('ascii')).hexdigest()
        assert_request_active()
        attempt = self.store.prepare_submission(grant_id=grant_id, principal=principal.name,
            task_id=task, submission_id=body.get('submission_id'), fingerprint=fingerprint)
        def execute():
            assert_request_active()
            self._grant = self.store.get(grant_id)
            # Recheck all authority after the intent commit. BEGIN IMMEDIATE
            # prevents revocation during the work append and confirmation.
            row = self.work.submit(task, actor=principal.name, record_id=attempt['id'], **payload)
            self.store.confirm_submission(attempt['id'])
            return 201, row
        try:
            return self.store.serialized(execute)
        except Exception:
            # Once a durable intent exists, any ordinary failure in the effect
            # phase is ambiguous, including adapter errors and permission fences.
            # Never let the outer transport convert a post-commit failure to a
            # false denial. BaseException still propagates for process shutdown.
            # Work may already be durable. The precommitted attempt survives
            # rollback and the same identifier retries exactly that work ID.
            return 503, {'error': 'submission outcome uncertain',
                         'submission_id': attempt['submission_id']}

    def _mcp(self,principal,body,*,grant_id=None):
        """Separate read-only MCP namespace over exactly the HTTP grant authority.

        Search covers only authorized exports. It never invokes ambient curated
        recall, shared tools, a provider, a shell or a document's linked resources.
        All checks and export bytes stay under the grant transaction.
        """
        assert_request_active()
        if principal.role!='external':raise AccessDenied()
        if (not {'jsonrpc','method'}<=set(body) or set(body)-{'jsonrpc','id','method','params'} or body['jsonrpc']!='2.0'
                or type(body.get('id',0)) not in (int,str)
                or len(str(body.get('id',0)))>64 or type(body.get('params',{})) is not dict):
            raise ValueError('closed MCP envelope required')
        params=dict(body.get('params',{}))
        if grant_id is None:grant_id=params.pop('grant_id',None)
        if not isinstance(grant_id,str):raise ValueError('explicit grant required')
        grant=self.store.get(grant_id)
        if grant is None or len(grant.resources)>1000:raise AccessDenied()
        self._grant=grant
        self._require_manifest_bindings()
        operations=set(grant.operations)&{'lookup','read','list','search'}
        if not any(self.store.decide(grant.id,principal=principal.name,resource=key,operation=op).allowed
                   for key in sorted(grant.resources) for op in sorted(operations)):
            raise AccessDenied()
        if body['method']=='notifications/initialized':
            if 'id' in body or params:raise ValueError('invalid initialization notification')
            return 202,{}
        if 'id' not in body:raise ValueError('request identifier required')
        if body['method']=='initialize':
            if set(params)!={'protocolVersion','capabilities','clientInfo'} or not isinstance(params['protocolVersion'],str) or type(params['capabilities']) is not dict or type(params['clientInfo']) is not dict:
                raise ValueError('invalid initialization')
            return 200,dict(jsonrpc='2.0',id=body['id'],result=dict(protocolVersion='2024-11-05',capabilities=dict(tools={}),serverInfo=dict(name='arvyx-external',version='0.1.0a0')))
        expected=set() if body['method']=='tools/list' else {'name','arguments'}
        if set(params)!=expected or body['method'] not in {'tools/list','tools/call'}:raise ValueError('unsupported MCP method')
        if body['method']=='tools/list':
            tools=[]
            for operation in sorted(operations):
                properties=({'resource':{'type':'string','maxLength':256}} if operation in {'read','lookup'}
                            else {'query':{'type':'string','maxLength':512}} if operation=='search' else {})
                required=list(properties)
                if operation=='read':properties.update(path={'type':'string'},sha256={'type':'string'},offset={'type':'integer','minimum':0},limit={'type':'integer','minimum':1,'maximum':65536})
                if operation=='lookup':properties.update(cursor={'type':['string','null']},limit={'type':'integer','minimum':1,'maximum':100})
                tools.append(dict(name='external.'+operation,description='Exact granted export '+operation,
                    inputSchema=dict(type='object',properties=properties,required=required,additionalProperties=False)))
            return 200,dict(jsonrpc='2.0',id=body['id'],result=dict(tools=tools))
        name=params['name'];arguments=params['arguments']
        if not isinstance(name,str) or name not in {'external.'+op for op in operations}:raise AccessDenied()
        if type(arguments) is not dict:raise ValueError('closed tool arguments required')
        operation=name.removeprefix('external.')
        if operation in {'lookup','read'}:
            if operation=='read' and set(arguments)=={'resource','path','sha256','offset','limit'}:
                result=self._download(principal,arguments)
                reply=dict(jsonrpc='2.0',id=body['id'],result=dict(content=[dict(type='text',text=json.dumps(result))]));_encoded_size(reply);return 200,reply
            if operation=='lookup' and set(arguments)=={'resource','cursor','limit'}:
                result=self._manifest_page(principal,arguments)
                reply=dict(jsonrpc='2.0',id=body['id'],result=dict(content=[dict(type='text',text=json.dumps(result))]));_encoded_size(reply);return 200,reply
            if set(arguments)!={'resource'} or not isinstance(arguments['resource'],str):raise ValueError('exact resource required')
            resource=Resource(*arguments['resource'].split(':',1))
            if not self._registered(resource) or not self.allows(principal=principal.name,resource=resource,operation=operation,tool=name):raise AccessDenied()
            if operation=='lookup':
                result=ExternalGateway(self,self).access(ExternalIdentity(principal.name),resource,'lookup')
            else:result=ExternalGateway(self,self).access(ExternalIdentity(principal.name),resource,'read')
        else:
            if set(arguments)!=({'query'} if operation=='search' else set()):raise ValueError('closed discovery arguments required')
            query=arguments.get('query','')
            if not isinstance(query,str) or len(query)>512:raise ValueError('bounded metadata query required')
            selected=[];size=2
            for key in sorted(grant.resources):
                resource=Resource(*key.split(':',1))
                if not (self.allows(principal=principal.name,resource=resource,operation=operation,tool=name)
                        and self.allows(principal=principal.name,resource=resource,operation='read',tool=name)):
                    continue
                item,charge=self._read_plan(resource)
                size+=charge+2
                if size>MAX_RESPONSE_BYTES:raise ValueError('response byte budget exceeded')
                selected.append(resource)
            result=[]
            for resource in selected:
                # Planning is not admission: earlier exports may consume the
                # remaining grant lifetime even while revocation is serialized.
                assert_request_active()
                if not (self.allows(principal=principal.name,resource=resource,operation=operation,tool=name)
                        and self.allows(principal=principal.name,resource=resource,operation='read',tool=name)):
                    raise AccessDenied()
                result.append(self.read(resource=resource,actor=principal.name))
            if operation=='search':
                def matches(item):
                    text=json.dumps({k:v for k,v in item.items() if k!='files'})
                    for entry in item.get('files',[]):
                        text+='\n'+entry['path']
                        try:text+='\n'+base64.b64decode(entry['content_base64'],validate=True).decode('utf-8')
                        except UnicodeError:pass
                    return query.casefold() in text.casefold()
                result=[item for item in result if matches(item)]
        response=dict(jsonrpc='2.0',id=body['id'],result=dict(content=[dict(type='text',text=json.dumps(result))]))
        _encoded_size(response)
        return 200,response

    def _config(self, principal):
        if principal.role != 'issuer':
            raise AccessDenied()
        row = self.store.db.execute('SELECT * FROM external_authorities WHERE principal=?',
                                    (principal.name,)).fetchone()
        can_export = bool(row and row['can_issue'] and row['can_export'])
        resources = []
        operations = []
        size = _encoded_size(self.recipients if can_export else []) + 256
        if can_export:
            operations = sorted(set(json.loads(row['operations'])) & {'read','lookup','list','search','submit'})
            for key in sorted(json.loads(row['resources'])):
                if ':' not in key:
                    continue
                kind, identifier = key.split(':', 1)
                if kind not in {'prompt','task','skill','artifact','workspace'}:
                    continue
                if (self._registered(Resource(kind, identifier)) and not self.store.db.execute(
                        'SELECT 1 FROM external_exclusions WHERE resource=?', (key,)).fetchone()):
                    item = dict(key=key, kind=kind, id=identifier)
                    snapshot=self._snapshot(Resource(kind,identifier))
                    if snapshot is not None:
                        item['manifest'] = self._manifest_record(snapshot)
                    size += _encoded_size(item, budget=MAX_RESPONSE_BYTES-size) + 2
                    if size > MAX_RESPONSE_BYTES:
                        raise ValueError('response byte budget exceeded')
                    resources.append(item)
        return dict(issuer=principal.name, can_export=can_export, ttl_hours=24,
                    recipients=self.recipients if can_export else [], resources=resources, operations=operations)

    def _record(self, grant):
        state = ('revoked' if grant.revoked_at is not None else
                 'expired' if self.store.clock() >= grant.expires_at else
                 'active' if self.store._active(grant, self.store.clock()) else 'unavailable')
        return dict(id=grant.id, issuer=grant.issuer, recipient=grant.recipient,
                    resources=sorted(grant.resources), operations=sorted(grant.operations),
                    created_at=grant.created_at.isoformat(), expires_at=grant.expires_at.isoformat(),
                    revoked_at=grant.revoked_at.isoformat() if grant.revoked_at else None,
                    provenance=grant.provenance, parent_id=grant.parent_id, state=state)

    def _route(self, method, parts, principal, body, *, pagination=None):
        if not parts and method == 'GET' and not body:
            if principal.role != 'issuer':
                raise AccessDenied()
            ids = self.store.db.execute('SELECT id FROM external_grants WHERE issuer=? ORDER BY created_at DESC,id',
                                        (principal.name,)).fetchall()
            return 200, [self._record(self.store.get(row['id'])) for row in ids]
        if not parts and method == 'POST':
            if principal.role != 'issuer':
                raise AccessDenied()
            required={'recipient','resources','operations','provenance'}
            if not required<=set(body) or set(body)-required-{'reviewed_manifests','expires_at'}:
                raise ValueError('closed schema')
            body = dict(body)
            reviewed = body.pop('reviewed_manifests', None)
            selected_expiry=body.pop('expires_at',None)
            now=self.store.clock()
            if selected_expiry is None:expires=now+timedelta(hours=24)
            else:
                from datetime import datetime
                if not isinstance(selected_expiry,str):raise ValueError('explicit ISO expiry required')
                try:expires=datetime.fromisoformat(selected_expiry.replace('Z','+00:00'))
                except ValueError:raise ValueError('explicit ISO expiry required') from None
                if expires.tzinfo is None or not now<expires<=now+timedelta(hours=24):raise ValueError('expiry must be future and within 24 hours')
            ExternalIdentity(body['recipient'])
            if body['recipient'] not in {r['id'] for r in self.recipients}:
                raise AccessDenied()
            if not isinstance(body['resources'], list) or not isinstance(body['operations'], list):
                raise ValueError('lists required')
            snapshots = {}
            for key in body['resources']:
                kind, identifier = key.split(':', 1)
                if not self._registered(Resource(kind, identifier)):
                    raise AccessDenied()
                snapshot = self._snapshot(Resource(kind, identifier))
                if snapshot is not None:
                    snapshots[key] = snapshot
            if reviewed is not None and reviewed != {
                    key: self._manifest_record(snapshot) for key, snapshot in snapshots.items()}:
                raise ValueError('workspace manifest changed; review again')
            if not set(body['operations']) <= {'read','lookup','list','search','submit'}:
                raise AccessDenied()
            from .external_grants import validate_resource_operations
            validate_resource_operations(body['resources'], body['operations'])
            assert_request_active()
            from .external_workspace import manifest_fingerprint
            bindings = {key: manifest_fingerprint(snapshot) for key, snapshot in snapshots.items()}
            grant = self.store.issue(issuer=principal.name, **body,
                manifest_bindings=bindings,
                expires_at=expires)
            return 201, {'id':grant.id,'expires_at':grant.expires_at.isoformat()}
        if not parts:
            return 404, {'error':'not found'}
        grant = self.store.get(parts[0])
        if grant is None:
            raise AccessDenied()
        self._grant = grant
        tail = parts[1:]
        if tail == ['audit'] and method == 'GET' and not body:
            return 200, self._audit_page(principal, pagination or {})
        if principal.role == 'external' and tail and tail[0] in {'resources', 'download', 'manifest'}:
            self._require_manifest_bindings()
        if tail==['download'] and method=='POST':return 200,self._download(principal,body)
        if tail==['manifest'] and method=='POST':return 200,self._manifest_page(principal,body)
        if not tail and method == 'GET' and not body:
            if principal.role != 'issuer' or principal.name != grant.issuer:
                raise AccessDenied()
            return 200, self._record(grant)
        if tail == ['revoke'] and method == 'POST' and not body:
            assert_request_active()
            self.store.revoke(grant.id, actor=principal.name)
            return 200, {'revoked':True}
        if tail and tail[0] == 'resources' and method == 'GET' and not body:
            if principal.role != 'external':
                raise AccessDenied()
            gateway = ExternalGateway(self, self)
            identity = ExternalIdentity(principal.name)
            if len(tail) == 1:
                if len(grant.resources) > 1000:
                    raise ValueError('response manifest budget exceeded')
                resources = [Resource(*key.split(':',1)) for key in sorted(grant.resources)]
                # Do not turn revoked/expired discovery into a successful empty list.
                if not self.store.decide(grant.id, principal=principal.name,
                        resource=sorted(grant.resources)[0], operation='read').allowed:
                    raise AccessDenied()
                # Plan the WHOLE discovery response before the first export.
                # Preserve file bodies with one shared encoded response ceiling.
                selected = []
                size = 2
                for resource in resources:
                    if not (self.allows(principal=principal.name, resource=resource,
                            operation='list', tool='external.list')
                            and self.allows(principal=principal.name, resource=resource,
                            operation='read', tool='external.list')):
                        continue
                    _, charge = self._read_plan(resource)
                    size += charge + (2 if selected else 0)
                    if size > MAX_RESPONSE_BYTES:
                        raise ValueError('response byte budget exceeded')
                    selected.append(resource)
                return 200, [gateway.access(identity, resource, 'read') for resource in selected]
            if len(tail) == 3:
                return 200, gateway.access(identity, Resource(tail[1],tail[2]), 'read')
        if len(tail) == 3 and tail[0] == 'tasks' and tail[2] == 'results':
            task = tail[1]
            if task not in self.tasks:
                raise AccessDenied()
            if method == 'GET' and not body:
                if principal.role != 'external' and not (
                        principal.role == 'observer' and principal.name in self.observers):
                    raise AccessDenied()
                if pagination is not None:
                    return 200, self.work.list_page(task, actor=principal.name, **pagination)
                return 200, self.work.list(task, actor=principal.name)
        raise AccessDenied()

    def _audit_page(self, principal, pagination):
        """Grant metadata only; never export the administrative global audit.

        Issuers retain own lifecycle metadata only while current export authority
        and exclusions permit its scope. Observers require a live whole-grant
        decision on EVERY page. A cursor is a position, never authorization.
        """
        grant = self._grant
        if grant is None or len(grant.resources) > 1000:
            raise AccessDenied()
        issuer = principal.role == 'issuer' and principal.name == grant.issuer
        observer = principal.role == 'observer' and principal.name in self.observers
        if not (issuer or observer):
            raise AccessDenied()
        if issuer:
            allowed = (self.store._authority(principal.name, grant.resources, grant.operations)
                    and not any(self.store.db.execute(
                        'SELECT 1 FROM external_exclusions WHERE resource=?', (key,)).fetchone()
                        for key in grant.resources))
            self.store._record('audit_read', self.store.clock(), grant_id=grant.id,
                               actor=principal.name, allowed=allowed)
            if not allowed:
                raise AccessDenied()
        else:
            for key in sorted(grant.resources):
                if not self.store.decide_observer(grant.id, principal=principal.name,
                                                  resource=key).allowed:
                    raise AccessDenied()
        after, through = 0, None
        cursor = pagination.get('cursor')
        if cursor is not None:
            if not isinstance(cursor, str) or len(cursor) > 2048:
                raise ValueError('invalid audit cursor')
            try:
                decoded = bounded_json_loads(base64.b64decode(cursor, altchars=b'-_', validate=True))
            except (ValueError, UnicodeError) as error:
                raise ValueError('invalid audit cursor') from error
            if (type(decoded) is not list or len(decoded) != 5
                    or decoded[:3] != [1, grant.id, principal.name]
                    or type(decoded[3]) is not int or type(decoded[4]) is not int):
                raise ValueError('audit cursor scope mismatch')
            after, through = decoded[3:]
        assert_request_active()
        page = self.store.audit_page(grant.id, after=after, through=through,
                                     limit=pagination.get('limit', 50))
        next_after = page.pop('next_after')
        through = page.pop('through')
        page['next_cursor'] = (base64.urlsafe_b64encode(json.dumps(
            [1, grant.id, principal.name, next_after, through], separators=(',', ':')).encode()).decode()
            if next_after is not None else None)
        page['grant_id'] = grant.id
        _encoded_size(page)
        return page


def make_server(api, *, port=0):
    """Create an authenticated loopback-only listener; no ambient demo fallback."""
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Never log bearer headers or submitted content.

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

        def _handle(self):
            self.connection.settimeout(5)
            try:
                if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) > 1:
                    raise ValueError('ambiguous framing')
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 <= size <= 32768:
                    raise ValueError('body bound')
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError('short request')
                def pairs(values):
                    result = {}
                    for key, value in values:
                        if key in result:
                            raise ValueError('duplicate key')
                        result[key] = value
                    return result
                body = bounded_json_loads(raw, object_pairs_hook=pairs) if raw else {}
                status, result = api.dispatch(self.command, self.path,
                    self.headers.get('Authorization', ''), body)
            except ReplicaAuthorityUnavailable:
                status, result = 503, {'error': 'mutation-authority-unavailable'}
            except (ValueError, UnicodeError):
                status, result = 400, {'error':'invalid request'}
            except Exception:
                status, result = 403, {'error':'access denied'}
            try:
                _encoded_size(result)
            except ValueError:
                status, result = 413, {'error': 'response byte budget exceeded'}
            data = json.dumps(result).encode()
            self.send_response(status)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(data)))
            self.send_header('Cache-Control','no-store')
            self.end_headers()
            self.wfile.write(data)
    return BoundedOnboardingServer(('127.0.0.1', port), Handler)


def main():
    """Run a trusted local composition factory, never request-selected imports."""
    import argparse
    import importlib
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--factory', required=True,
                        help='Trusted local module:function returning a provisioned ExternalAPI')
    parser.add_argument('--port', type=int, default=0)
    args = parser.parse_args()
    module, name = args.factory.split(':', 1)
    api = getattr(importlib.import_module(module), name)()
    if type(api) is not ExternalAPI:
        raise TypeError('factory must return ExternalAPI')
    server = make_server(api, port=args.port)
    print(json.dumps({'listening':'127.0.0.1', 'port':server.server_port}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        api.close()
        api.store.close()


if __name__ == '__main__':
    main()
