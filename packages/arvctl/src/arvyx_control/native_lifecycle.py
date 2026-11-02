"""Reviewed native lifecycle over an exact same-UID owner, shared by all clients.

Consent binds target, filesystem identity, effective executor plan, owner boot
incarnation and revocation epoch. Ambiguity is durable before process admission.
Reopen never renews authority and never replays effects.
"""
from dataclasses import asdict
import hashlib,json,secrets,time
from .session_workspaces import encoded
from .reviewed_actions import assert_consent_active, consent_scope, current_consent_expiry

class OwnerProducer:
    def __init__(self,owner,*,policy):
        self.owner=owner;owner.execution_policy=policy
    def inspect(self):return self.owner.native_lifecycle(action='inspect',actor='operator')
    def revoke(self,*,expected=None):return self.owner.native_lifecycle(action='revoke',actor='operator',expected=self.inspect() if expected is None else expected,confirmed=True,consent_expires_at=current_consent_expiry())
    def plan(self,request,workspace):
        data=self.owner.native_lifecycle(action='plan',actor='operator',expected=self.inspect(),confirmed=True,
            target=request.get('target'),harness=request['harness'],provider_start_acknowledged=request.get('provider_start_acknowledged',False),
            environment=request['environment'],workspace=str(workspace),root_acknowledged=request['root_acknowledged'])
        info=__import__('os').stat(workspace)
        return dict(owner=data['owner'],uid=data['uid'],argv=list(data['argv']),launcher_sha256=data['launcher_sha256'],workspace_identity=[info.st_dev,info.st_ino],native=data.get('native'))
    def create(self,attempt,request,workspace,expected):
        expires=expected.get('consent_expires_at')
        inherited=current_consent_expiry()
        if inherited is not None:expires=min(expires,inherited) if expires is not None else inherited
        assert_consent_active(expires)
        return self.owner.native_lifecycle(action='new',actor='operator',expected=expected['owner'],attempt=attempt,
            target=request['target'],workspace=workspace,environment=request['environment'],
            root_acknowledged=request['root_acknowledged'],confirmed=True,workspace_identity=expected['workspace_identity'],reviewed_native=expected.get('native'),harness=request['harness'],provider_start_acknowledged=request.get('provider_start_acknowledged',False),consent_expires_at=expires,delegation_fence=expected.get('delegation_fence'))
    def verify(self,result,target):
        return self.owner.native_lifecycle(action='verify',actor='operator',expected=self.inspect(),result=result,target=target,confirmed=True)
    def attach(self,result,target):
        return self.owner.native_lifecycle(action='attach',actor='operator',expected=self.inspect(),result=result,target=target,confirmed=True,consent_expires_at=current_consent_expiry())
    def resolve(self,target,conversation):
        return self.owner.native_lifecycle(action='resolve',actor='operator',expected=self.inspect(),target=target,conversation=conversation,confirmed=True)
    def io(self,result,target,attachment,operation,fields):
        return self.owner.native_lifecycle(action='io',actor='operator',expected=self.inspect(),result=result,target=target,
            attachment=attachment,io_operation=operation,fields=fields,confirmed=True)
    def record_pane(self,result,target,frontend,presentation):
        return self.owner.native_lifecycle(action='register_pane',actor='operator',expected=self.inspect(),result=result,target=target,
            frontend=frontend,presentation=presentation,confirmed=True,consent_expires_at=current_consent_expiry())

class SocketOwnerProducer(OwnerProducer):
    """Same closed producer through the private owner socket; no live start here."""
    def __init__(self,home,*,vault,state,machine):
        from types import SimpleNamespace
        from pathlib import Path
        self.home=Path(home)
        self.owner=SimpleNamespace(vault=Path(vault).resolve(),state=Path(state).resolve(),host=machine,native_lifecycle=self._call)
    def _call(self,**fields):
        from .cockpit_client import request
        return request(self.home,'native_lifecycle',**fields)

class NativeLifecycle:
    def __init__(self,extension,producer):
        if producer.owner.vault != extension.vault.resolve() or producer.owner.host != extension.machine:
            raise PermissionError('producer authority mismatch')
        extension.state=producer.owner.state
        self.extension=extension;self.db=extension.owner.creation.db;self.producer=producer
        self.frontend=None
        self.db.execute('''CREATE TABLE IF NOT EXISTS native_attempts (
            id TEXT PRIMARY KEY,digest TEXT NOT NULL,payload TEXT NOT NULL,snapshot TEXT NOT NULL,
            expires REAL NOT NULL,status TEXT NOT NULL,result TEXT)''');self.db.commit()
        from .authority_attempts import migrate_attempts
        migrate_attempts(self.db,extension.attempt_incarnation)
    def workspace_request(self,body):
        return dict(target=body['target'],workspace=body['workspace'],environment='metadata')
    def snapshot(self,body):
        from .public_onboarding_api import PublicOnboardingAPI as API
        API._fields(body,('target','workspace','environment','harness','root_acknowledged'),('provider_start_acknowledged','presentation'))
        if body.get('presentation','owner') not in ('owner','native'):raise ValueError('explicit presentation choice required')
        if body.get('presentation')=='native' and self.frontend is None:raise PermissionError('explicit admitted native frontend required')
        if type(body['root_acknowledged']) is not bool:raise ValueError('explicit root acknowledgement required')
        with self.extension.workspaces.selection(self.workspace_request(body)) as (_,__,workspace):pass
        # A new directory is not present yet. Validate the mode against its
        # reviewed parent, then recompute after mkdir before any launch.
        from pathlib import Path
        path=Path(workspace['path'])
        plan=self.producer.plan(body,path if path.exists() else path.parent)
        if not path.exists():
            def destination(argv):return [str(path) if v==str(path.parent) else v for v in argv]
            plan=dict(plan,argv=destination(plan['argv']))
            if plan.get('native') is not None:plan['native']=dict(plan['native'],argv=destination(plan['native']['argv']))
        return dict(workspace=workspace,producer=plan,frontend=self.frontend.identity() if body.get('presentation')=='native' else None)
    def _completed(self,target,*,owner_session=None,before=None,limit=101):
        clauses=["namespace='native_attempts'", "status='completed'", 'result IS NOT NULL']
        values=[]
        for key in ('machine_id','agent_id','workspace_id','connection_id'):
            clauses.append("json_extract(result,'$.target."+key+"')=?");values.append(target[key])
        if owner_session is not None:
            clauses.append("json_extract(result,'$.owner_session')=?");values.append(owner_session)
        if before is not None:clauses.append('ordinal<?');values.append(before)
        values.append(limit)
        return self.db.execute('SELECT ordinal,result FROM authority_attempts WHERE '+' AND '.join(clauses)+' ORDER BY ordinal DESC LIMIT ?',values).fetchall()

    def exact(self,target,owner_session):
        rows=self._completed(target,owner_session=owner_session,limit=2)
        if len(rows)!=1:raise PermissionError('exact native session unavailable or ambiguous')
        result=json.loads(rows[0][1])
        if result.get('target')!=target:raise PermissionError('exact native target changed')
        self.producer.verify(result,target)
        return result

    def route(self,path,method,body,*,review_snapshot=None):
        from .public_onboarding_api import PublicOnboardingAPI as API,assert_request_active
        if path=='native/revoke' and method=='POST':
            API._fields(body,('confirmed',));API._confirm(body)
            if review_snapshot is None:raise PermissionError('durable exact owner review required')
            return 200,self.producer.revoke(expected=review_snapshot)
        if path=='native/present' and method=='POST':
            API._fields(body,('target','session_id','confirmed'));API._confirm(body)
            target=API._target(self.extension.owner,body['target']);self.extension.owner.sessions.recent(target)
            if self.frontend is None:raise PermissionError('explicit admitted native frontend required')
            if review_snapshot is None:raise PermissionError('durable exact native review required')
            proof=review_snapshot['proof']
            if self.frontend.identity()!=review_snapshot['frontend']:raise PermissionError('reviewed frontend changed')
            self.producer.verify(proof,body['target'])
            return 200,dict(self.frontend.present(proof,body['target'],producer=self.producer),target=body['target'])
        if path=='native/io' and method=='POST':
            API._fields(body,('target','proof','attachment','operation','fields'))
            target=API._target(self.extension.owner,body['target']);self.extension.owner.sessions.recent(target)
            return 200,self.producer.io(body['proof'],body['target'],body['attachment'],body['operation'],body['fields'])
        if path=='native/attach' and method=='POST':
            API._fields(body,('target','session_id','confirmed'));API._confirm(body)
            target=API._target(self.extension.owner,body['target']);self.extension.owner.sessions.recent(target)
            if review_snapshot is None:raise PermissionError('durable exact native review required')
            proof=review_snapshot;self.producer.verify(proof,body['target'])
            return 200,dict(proof,target=body['target'],attachment=self.producer.attach(proof,body['target']))
        if path in ('native/sessions','native/open') and method=='POST':
            API._fields(body,('target',) if path=='native/sessions' else ('target','owner_session','confirmed'),
                        ('limit','cursor') if path=='native/sessions' else ())
            target=API._target(self.extension.owner,body['target']);self.extension.owner.sessions.recent(target)
            if path=='native/open':
                API._confirm(body)
                result=self.exact(body['target'],body['owner_session'])
                if review_snapshot is None or result!=review_snapshot:raise PermissionError('native owner review changed')
                return 200,dict(result,attachment=self.producer.attach(result,body['target']))
            limit=body.get('limit',100);cursor=body.get('cursor')
            if type(limit) is not int or not 1<=limit<=100:raise ValueError('bounded native page required')
            if cursor is not None and (not isinstance(cursor,str) or not cursor.isascii() or not cursor.isdecimal() or len(cursor)>19 or not 0<int(cursor)<=2**63-1):
                raise ValueError('invalid native page cursor')
            rows=self._completed(body['target'],before=int(cursor) if cursor is not None else None,limit=limit+1)
            items=[]
            for _,raw in rows[:limit]:
                result=json.loads(raw)
                if result.get('target')!=body['target']:continue
                try:self.producer.verify(result,body['target'])
                except PermissionError:continue
                items.append(result)
            return 200,dict(items=items,next_cursor=str(rows[limit-1][0]) if len(rows)>limit else None)
        if path=='native/prepare' and method=='POST':
            snapshot=self.snapshot(body);identifier=secrets.token_hex(16);expires=time.time()+300
            digest=hashlib.sha256(encoded(dict(request=body,snapshot=snapshot)).encode()).hexdigest()
            with self.db:self.db.execute('INSERT INTO native_attempts VALUES(?,?,?,?,?,?,NULL)',(identifier,digest,encoded(body),encoded(snapshot),expires,'prepared'))
            return 200,dict(consent_id=identifier,sha256=digest,expires_at=expires,request=body,snapshot=snapshot,execution=True)
        if path=='native/commit' and method=='POST':
            API._fields(body,('consent_id','consent_sha256','confirmed'));API._confirm(body)
            attempted=False
            self.db.execute('BEGIN IMMEDIATE')
            try:
                row=self.db.execute('SELECT digest,payload,snapshot,expires,status FROM native_attempts WHERE id=?',(body['consent_id'],)).fetchone()
                if not row or row[0]!=body['consent_sha256'] or row[3]<=time.time() or row[4]!='prepared':raise ValueError('invalid, expired or attempted native consent')
                request=json.loads(row[1]);snapshot=json.loads(row[2])
                if self.snapshot(request)!=snapshot:raise ValueError('workspace, executor or owner changed; review again')
                assert_consent_active(row[3])
                self.db.execute("UPDATE native_attempts SET status='ambiguous' WHERE id=?",(body['consent_id'],))
                assert_consent_active(row[3])
                self.db.commit();attempted=True
                with consent_scope(row[3]):
                    assert_request_active()
                    if request['workspace']['mode']=='create':
                        import os
                        with self.extension.workspaces.selection(self.workspace_request(request)) as (parent,leaf,current):
                            if current!=snapshot['workspace']:raise ValueError('workspace changed')
                            assert_consent_active()
                            os.mkdir(leaf,0o700,dir_fd=parent);os.fsync(parent)
                            fd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                            try:created=[os.fstat(fd).st_dev,os.fstat(fd).st_ino]
                            finally:os.close(fd)
                        check=self.workspace_request(request);check['workspace']=dict(check['workspace'],mode='existing')
                        with self.extension.workspaces.selection(check) as (_,__,observed):
                            if observed['root']!=snapshot['workspace']['root'] or observed['parent']!=snapshot['workspace']['parent'] or observed['existing']!=created:
                                raise ValueError('workspace publication changed')
                    launch_plan=dict(snapshot['producer'],consent_expires_at=row[3],workspace_identity=created if request['workspace']['mode']=='create' else snapshot['workspace']['existing'])
                    assert_consent_active()
                    result=self.producer.create(body['consent_id'],request,snapshot['workspace']['path'],launch_plan)
                    self.producer.verify(result,request['target'])
                    if request.get('presentation')=='native':
                        assert_consent_active()
                        result=self.frontend.present(result,request['target'],producer=self.producer)
                    result=dict(result,target=request['target'])
                    with self.db:self.db.execute("UPDATE native_attempts SET status='completed',result=? WHERE id=?",(encoded(result),body['consent_id']))
                    return 201,result
            except Exception:
                self.db.rollback()
                if attempted:return 503,dict(error='native_outcome_uncertain',reconcile_required=True,consent_id=body['consent_id'])
                raise
            except BaseException:self.db.rollback();raise
        return None
