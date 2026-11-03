"""Independently authenticated leaf executor for the closed new-local-shell action.

The action creates a real owner PTY and returns its exact immutable session ID.
It does not interpret natural-language goals or shell command text. Each executor
lease binds one target/workspace, mode allowlist, owner incarnation and revocation
snapshot. A new owner requires explicit provisioning of a new leaf lease.
"""
from contextlib import closing
import hashlib,json,re,threading
from . import private_paths
from .organizer_durable import private_database
from .session_workspaces import encoded
from .native_lifecycle import OwnerProducer,SocketOwnerProducer

class LocalExecutorService:
    def __init__(self,database,*,credential,producer,target,session,workspace,environments,identity_store,authority_database=None,remote_fence=None):
        if type(producer) not in (OwnerProducer,SocketOwnerProducer):raise ValueError('closed owner producer required')
        if not isinstance(credential,str) or not 32<=len(credential)<=256:raise ValueError('independently provisioned leaf credential required')
        self.remote_fence=remote_fence
        self.producer=producer;self.target=dict(target);self.session=session
        from pathlib import Path
        from .external_workspace import _open_root
        supplied=Path(workspace)
        with _open_root(supplied) as fd:
            import os
            info=os.fstat(fd)
            self.workspace=str(supplied.resolve(strict=True))
            self.workspace_identity=[info.st_dev,info.st_ino]
        self.identity_store=Path(identity_store)
        self.profile_snapshot=self._verify_target()
        self.vault=producer.owner.vault;self.state=producer.owner.state;self.lock=threading.RLock()
        self.environments=frozenset(environments)
        if not self.environments or self.environments-{'sandbox','host','root'}:raise ValueError('explicit local environment allowlist required')
        self.credential_sha256=hashlib.sha256(credential.encode()).hexdigest();self.binding=producer.inspect()
        from .organizer_durable import authority_fence_identity
        from .replica_authority import authority_context
        self.authority_database=Path(authority_database).resolve() if authority_database is not None else None
        with authority_context(self.vault,self.state):
            self.authority_id=authority_fence_identity(self.authority_database) if self.authority_database is not None else None
        for environment in self.environments:
            plan=producer.plan(dict(harness='shell',environment=environment,root_acknowledged=environment=='root'),self.workspace)
            if plan['workspace_identity']!=self.workspace_identity:raise PermissionError('workspace changed during leaf provisioning')
        self.db=private_database(database)
        from pathlib import Path
        import secrets
        from .cockpit_restart import boot_id
        self.database_path=Path(database).resolve()
        info=self.database_path.stat()
        self.database_identity=(info.st_dev,info.st_ino)
        self.db.execute('CREATE TABLE IF NOT EXISTS executor_incarnation(singleton INTEGER PRIMARY KEY CHECK(singleton=1),identifier TEXT NOT NULL)')
        self.db.execute('INSERT OR IGNORE INTO executor_incarnation VALUES(1,?)',(secrets.token_hex(32),))
        incarnation=self.db.execute('SELECT identifier FROM executor_incarnation WHERE singleton=1').fetchone()[0]
        self.db.execute('CREATE TABLE IF NOT EXISTS executor_identity(singleton INTEGER PRIMARY KEY,document TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS executor_attempts(id TEXT PRIMARY KEY,payload TEXT NOT NULL,status TEXT NOT NULL,result TEXT)')
        identity=encoded(dict(target=self.target,session=session,workspace=self.workspace,workspace_identity=self.workspace_identity,authority_id=self.authority_id,environments=sorted(self.environments),owner=self.binding,profile_snapshot=self.profile_snapshot,remote_fence=None if remote_fence is None else remote_fence.configuration_sha256))
        row=self.db.execute('SELECT document FROM executor_identity WHERE singleton=1').fetchone()
        if row and row[0]!=identity:
            self.db.close();raise PermissionError('executor lease changed; reconcile old attempts and explicitly provision a new leaf')
        self.db.execute('INSERT OR IGNORE INTO executor_identity VALUES(1,?)',(identity,));self.db.commit()
        # Copies, replacement databases and owner reprovisioning are different
        # receiving leases even when the logical endpoint and credential match.
        self.receiving_leaf=hashlib.sha256(encoded([incarnation,boot_id(),str(self.database_path),list(self.database_identity),identity]).encode()).hexdigest()
        from .authority_attempts import migrate_attempts
        import secrets
        migrate_attempts(self.db,secrets.token_hex(16))
    def _verify_target(self):
        import sqlite3
        from .hermes_history import HermesHistory
        from .cockpit_primary import compatible_native_identity
        from .external_workspace import _open_root
        p=self.identity_store
        if not p.is_absolute() or p.is_symlink():raise PermissionError('exact trusted identity store required')
        with _open_root(p.parent):pass
        try:
            with closing(sqlite3.connect(p.as_uri()+'?mode=ro',uri=True)) as db, db:
                row=db.execute('SELECT target,identity FROM onboarding_connections WHERE agent_id=?',(self.target['agent_id'],)).fetchone()
                pin=None if row is None else db.execute(
                    'SELECT snapshot FROM onboarding_connection_pins WHERE agent_id=? AND target=?',
                    (self.target['agent_id'],row[0])).fetchone()
            if not row or json.loads(row[0])!=self.target or pin is None:
                raise PermissionError('exact reviewed onboarding pin required; legacy connections need explicit review')
            snapshot=json.loads(pin[0])
            if not isinstance(snapshot,dict) or not {'profile','identity','home_identity'}<=set(snapshot):
                raise PermissionError('complete reviewed onboarding pin required')
            if hasattr(self,'profile_snapshot') and snapshot!=self.profile_snapshot:
                raise PermissionError('executor reviewed profile lease changed')
            profile=HermesHistory(self.target['workspace_id'],review_snapshot=snapshot)
            profile.validate_review()
            if json.dumps(profile.identity)!=row[1] or not compatible_native_identity(self.producer.owner.vault,self.target['agent_id'],self.target['machine_id'],'hermes'):
                raise PermissionError('profile or registry identity changed')
            return snapshot
        except (OSError,ValueError,TypeError,sqlite3.Error):
            raise PermissionError('reviewed onboarding identity unavailable or changed') from None
    def close(self):self.db.close()
    def _verify_workspace(self):
        from pathlib import Path
        from .external_workspace import _open_root
        import os
        try:
            with _open_root(Path(self.workspace)) as fd:
                info=os.fstat(fd)
                if [info.st_dev,info.st_ino]!=self.workspace_identity:
                    raise PermissionError('provisioned workspace directory changed; reprovision leaf explicitly')
        except (OSError,ValueError):
            raise PermissionError('provisioned workspace unavailable or changed') from None
    def dispatch(self,method,path,authorization,body):
        from .replica_authority import authority_context,assert_mutation_authority
        from .public_onboarding_api import assert_request_active
        if not authorization.startswith('Bearer ') or hashlib.sha256(authorization[7:].encode()).hexdigest()!=self.credential_sha256:return 401,dict(error='executor_authentication_required')
        with self.lock,authority_context(self.vault,self.state):
            try:
                assert_mutation_authority(self.vault)
                self._verify_target()
                self._verify_workspace()
                info=self.database_path.stat()
                if (info.st_dev,info.st_ino)!=self.database_identity:raise PermissionError('receiving leaf database changed')
                if self.producer.inspect()!=self.binding:raise PermissionError('owner lease revoked or changed')
                if path=='/api/public-onboarding/capabilities' and method=='GET' and not body:
                    ready=self._fence_ready()
                    return 200,dict(machine=self.target['machine_id'],agent=self.target['agent_id'],session=self.session,receiving_leaf=self.receiving_leaf,environments=sorted(self.environments) if ready else [],actions=['new-local-shell'] if ready else [],organizer_effect_fence=self.authority_id if ready else None,organizer_effect_fences=([self.authority_id]+([] if self.remote_fence is None else [self.remote_fence.authority_id])) if ready else [])
                if path=='/api/public-onboarding/executor/result' and method=='POST':
                    from .executor_endpoint import validate_result_query
                    validate_result_query(body)
                    if body['receiving_leaf']!=self.receiving_leaf:raise PermissionError('retained leaf incarnation required')
                    row=self.db.execute("SELECT json_extract(record,'$.payload'),status,result FROM authority_attempts WHERE namespace='executor_attempts' AND id=?",(body['request_id'],)).fetchone()
                    if row is None:return 404,dict(error='retained_attempt_unavailable')
                    if hashlib.sha256(encoded(json.loads(row[0])).encode()).hexdigest()!=body['witness_sha256']:
                        raise PermissionError('exact retained witness required')
                    if row[1]!='completed' or row[2] is None:
                        return 409,dict(error='executor_outcome_uncertain',request_id=body['request_id'],reconcile_required=True)
                    result=json.loads(row[2])
                    return 200,dict(request_id=body['request_id'],status='completed',reference='owner-session:'+result['owner_session'])
                if path!='/api/public-onboarding/executor/execute' or method!='POST':return 404,dict(error='unknown_executor_operation')
                expected={'machine','executing_agent','session','operation','environment','goal','request_id','decision','root_acknowledged','delegation_fence','consent_expires_at','receiving_leaf'}
                if type(body) is not dict or set(body)!=expected:raise ValueError('closed executor request required')
                if body['receiving_leaf']!=self.receiving_leaf:raise PermissionError('reviewed receiving leaf changed; review again')
                if (body['machine'],body['executing_agent'],body['session'])!=(self.target['machine_id'],self.target['agent_id'],self.session):raise PermissionError('exact executor identity mismatch')
                if body['environment'] not in self.environments or body['operation']!='invoke_'+body['environment'] or body['goal']!='new-local-shell':raise PermissionError('only explicitly delegated new-local-shell is supported; no arbitrary goal interpreter')
                if type(body['root_acknowledged']) is not bool or body['environment']=='root' and not body['root_acknowledged']:raise PermissionError('root risk acknowledgement required')
                if not self._fence_ready():raise PermissionError('explicit shared owner effect fence required')
                identifier=body['request_id']
                if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9]{32}',identifier):raise ValueError('immutable attempt identifier required')
                ticket=body['delegation_fence']
                if (type(ticket) is not dict or set(ticket)!={'authority_id','token'}
                        or any(not isinstance(value,str) or not re.fullmatch('[a-f0-9]{64}',value) for value in ticket.values())):
                    raise PermissionError('closed authenticated organizer ticket required')
                request=dict(target=self.target,harness='shell',environment=body['environment'],root_acknowledged=body['root_acknowledged'])
                plan=self.producer.plan(request,self.workspace)
                if plan['workspace_identity']!=self.workspace_identity:raise PermissionError('provisioned workspace directory changed')
                plan['workspace_identity']=list(self.workspace_identity)
                self.db.execute('BEGIN IMMEDIATE')
                try:
                    if self.db.execute('SELECT 1 FROM executor_attempts WHERE id=?',(identifier,)).fetchone():raise ValueError('executor attempt exists; no replay')
                    witness=dict(body,delegation_fence=dict(authority_id=ticket['authority_id'],token_sha256=hashlib.sha256(ticket['token'].encode()).hexdigest()))
                    self.db.execute("INSERT INTO executor_attempts VALUES(?,?,'ambiguous',NULL)",(identifier,encoded(witness)));self.db.commit()
                except BaseException:self.db.rollback();raise
                try:
                    assert_request_active()
                    self._verify_target()
                    self._verify_workspace()
                    info=self.database_path.stat()
                    if (info.st_dev,info.st_ino)!=self.database_identity or body['receiving_leaf']!=self.receiving_leaf:raise PermissionError('receiving leaf incarnation changed before effect')
                    if self.producer.inspect()!=self.binding:raise PermissionError('owner lease revoked or changed')
                    from .organizer_durable import validate_delegated_effect
                    unsealed={key:value for key,value in body.items() if key!='delegation_fence'}
                    if self.remote_fence is not None and ticket['authority_id']==self.remote_fence.authority_id:
                        expires=self.remote_fence.validate(ticket,unsealed)['expires']
                    else:
                        expires=validate_delegated_effect(self.authority_database,body['delegation_fence'],unsealed)
                    if type(body['consent_expires_at']) not in (int,float) or body['consent_expires_at']!=expires:
                        raise PermissionError('original organizer consent expiry required')
                    plan['consent_expires_at']=expires
                    plan['delegation_fence']=dict(body['delegation_fence'])
                    result=self.producer.create(identifier,request,self.workspace,plan)
                    self.producer.verify(result,self.target)
                    completion=dict(request_id=identifier,status='completed',reference='owner-session:'+result['owner_session'])
                    with self.db:self.db.execute("UPDATE executor_attempts SET status='completed',result=? WHERE id=?",(encoded(result),identifier))
                    return 200,completion
                except Exception:return 503,dict(error='executor_outcome_uncertain',request_id=identifier,reconcile_required=True)
            except PermissionError:return 403,dict(error='executor_authority_refused')
            except (ValueError,KeyError,TypeError):return 400,dict(error='executor_request_refused')

    def _fence_ready(self):
        if self.remote_fence is not None:
            return (self.binding.get('remote_organizer_authority_id')==self.remote_fence.authority_id
                    and self.binding.get('remote_fence_configuration')==self.remote_fence.configuration_sha256
                    and self.target==self.remote_fence.binding['target']
                    and self.session==self.remote_fence.binding['session']
                    and self.workspace_identity==self.remote_fence.binding['workspace_identity']
                    and self.environments<=set(self.remote_fence.binding['environments']))
        return (self.authority_id is not None and self.binding.get('organizer_effect_fence') is True
                and self.binding.get('organizer_authority_id')==self.authority_id)


def main(argv=None):
    import argparse,os
    from pathlib import Path
    from .public_onboarding_api import make_server
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',type=Path,required=True);parser.add_argument('--port',type=int,default=0)
    args=parser.parse_args(argv);p=args.config
    if p.is_symlink() or not private_paths.owner_private(p.stat(),path=p) or p.stat().st_size>16384:raise ValueError('private bounded leaf configuration required')
    fields=json.loads(p.read_text())
    required={'database','credential','owner','vault','state','target','session','workspace','environments','identity_store','authority_database'}
    if set(fields) not in (required,required|{'remote_fence_config'}):raise ValueError('closed leaf configuration with explicit organizer fence required')
    if 'remote_fence_config' in fields:
        from .remote_effect_fence import load_client
        from .replica_authority import authority_context
        with authority_context(fields['vault'],fields['state']):
            fields['remote_fence']=load_client(fields.pop('remote_fence_config'))
    producer=SocketOwnerProducer(fields.pop('owner'),vault=fields.pop('vault'),state=fields.pop('state'),machine=fields['target']['machine_id'])
    service=LocalExecutorService(producer=producer,**fields)
    server=make_server(service,port=args.port)
    print(json.dumps(dict(origin='http://127.0.0.1:'+str(server.server_port),actions=['new-local-shell'])),flush=True)
    try:server.serve_forever()
    finally:server.server_close();service.close()

if __name__=='__main__':main()
