"""Reviewed workspace preparation for New; never fabricate or launch a session.

Roots are trusted operator configuration. HTTP can choose only paths below those
roots. Descriptor traversal rejects symlinks; attempts persist before effects and
are never replayed after an ambiguous result. No execution mode is inferred.
"""
from contextlib import contextmanager
from dataclasses import asdict
import hashlib,json,os,secrets,time
from pathlib import Path
from .external_workspace import _open_root


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'))
def inode(fd):
    s=os.fstat(fd);return [s.st_dev,s.st_ino]


class SessionWorkspaces:
    def __init__(self,extension):
        self.extension=extension;self.owner=extension.owner;self.db=self.owner.creation.db
        self.db.execute('''CREATE TABLE IF NOT EXISTS session_preparations (
            id TEXT PRIMARY KEY, digest TEXT NOT NULL, payload TEXT NOT NULL,
            snapshot TEXT NOT NULL, expires REAL NOT NULL, status TEXT NOT NULL,
            result TEXT)''');self.db.commit()

    def roots(self):
        roots=self.extension.workspace_roots
        for key,path in roots.items():
            if not isinstance(key,str) or not key or type(path) not in (str,Path) and not isinstance(path,Path):
                raise ValueError('trusted workspace root required')
        return roots

    @contextmanager
    def selection(self,body):
        from .public_onboarding_api import PublicOnboardingAPI as API
        API._fields(body,('target','workspace','environment'))
        target=API._target(self.owner,body['target'])
        self.owner.sessions.recent(target) # exact current adapter/profile identity
        if body['environment']!='metadata':raise ValueError('execution not authorized')
        choice=body['workspace'];API._fields(choice,('mode','root_id'),('path','session_id'))
        roots=self.roots();root=Path(roots[choice['root_id']])
        if not root.is_absolute() or root.is_symlink():raise ValueError('canonical configured root required')
        root=root.absolute()
        if choice['mode']=='current':
            API._fields(choice,('mode','root_id','session_id'))
            adapter=self.owner.sessions._adapter(target)
            row=adapter.exact(choice['session_id'])
            cwd=row.get('cwd')
            if not isinstance(cwd,str) or not Path(cwd).is_absolute():raise ValueError('exact recorded workspace unavailable')
            relative=Path(cwd).relative_to(root).as_posix()
        else:
            API._fields(choice,('mode','root_id','path'))
            if choice['mode'] not in ('existing','create'):raise ValueError('explicit workspace choice required')
            relative=choice['path']
        if not isinstance(relative,str) or not relative or '\\' in relative or any(ord(c)<32 for c in relative):
            raise ValueError('canonical relative workspace required')
        parts=relative.split('/')
        if len(parts)>16 or any(p in ('','..') or (p=='.' and (relative!='.' or choice['mode']=='create')) for p in parts):raise ValueError('bounded relative workspace required')
        with _open_root(root) as original:
            base=os.dup(original)
        try:
            parent=os.dup(base)
            try:
                for part in parts[:-1]:
                    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                    os.close(parent);parent=child
                try:
                    fd=os.open(parts[-1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                except FileNotFoundError:
                    existing=None
                else:
                    try:existing=inode(fd)
                    finally:os.close(fd)
                if (choice['mode']=='create') != (existing is None):raise ValueError('workspace existence changed or conflicts')
                snapshot=dict(root=inode(base),parent=inode(parent),existing=existing,path=str(root.joinpath(*parts)),target=asdict(target))
                yield parent,parts[-1],snapshot
            finally:os.close(parent)
        finally:os.close(base)

    def route(self,path,method,body):
        from .public_onboarding_api import PublicOnboardingAPI as API
        if path=='sessions/workspaces' and method=='POST':
            API._fields(body,('target',));target=API._target(self.owner,body['target']);self.owner.sessions.recent(target)
            native=self.extension.native
            status=native.producer.inspect() if native is not None else {}
            return 200,dict(native_lifecycle=native is not None,native_environments=status.get('environments',[]),native_harnesses=['shell',*status.get('native_protocols',[])] if native is not None else [],roots=[dict(id=k,label=str(p)) for k,p in self.roots().items()],execution=False,environments=[dict(id='metadata',available=True)],native_session_creation=False)
        if path=='sessions/prepare' and method=='POST':
            API._fields(body,('target','workspace','environment'))
            if body['environment']!='metadata':return 501,dict(error='approved_executor_unavailable',queued=False)
            try:
                with self.selection(body) as (_,__,snapshot):pass
            except OSError as exc:raise ValueError('workspace unavailable or unsafe') from exc
            payload=encoded(body);digest=hashlib.sha256(encoded(dict(request=body,snapshot=snapshot)).encode()).hexdigest()
            identifier=secrets.token_hex(16);expires=time.time()+300
            with self.db:self.db.execute('INSERT INTO session_preparations VALUES(?,?,?,?,?,?,NULL)',(identifier,digest,payload,encoded(snapshot),expires,'prepared'))
            return 200,dict(consent_id=identifier,sha256=digest,expires_at=expires,request=body,workspace=snapshot['path'],execution=False,native_session_creation=False)
        if path=='sessions/commit' and method=='POST':
            API._fields(body,('consent_id','consent_sha256','confirmed'));API._confirm(body)
            attempted=False
            self.db.execute('BEGIN IMMEDIATE')
            try:
                row=self.db.execute('SELECT digest,payload,snapshot,expires,status FROM session_preparations WHERE id=?',(body['consent_id'],)).fetchone()
                if not row or row[0]!=body['consent_sha256'] or row[3]<=time.time() or row[4]!='prepared':raise ValueError('invalid, expired or attempted workspace consent')
                request=json.loads(row[1]);expected=json.loads(row[2])
                from .reviewed_actions import consent_scope, assert_consent_active
                with consent_scope(row[3]), self.selection(request) as (parent,leaf,current):
                    if current!=expected:raise ValueError('workspace or connection changed; review again')
                    assert_consent_active()
                    self.db.execute("UPDATE session_preparations SET status='ambiguous' WHERE id=?",(body['consent_id'],));self.db.commit()
                    attempted=True
                    from .public_onboarding_api import assert_request_active
                    assert_request_active()
                    assert_consent_active()
                    if request['workspace']['mode']=='create':
                        os.mkdir(leaf,mode=0o700,dir_fd=parent);os.fsync(parent)
                        # Verify the directory remains at the reviewed root/path.
                        fd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                        try:created=inode(fd);os.fsync(fd)
                        finally:os.close(fd)
                        verification=dict(request);verification['workspace']=dict(request['workspace'],mode='existing')
                        with self.selection(verification) as (_,__,observed):
                            if observed['root']!=current['root'] or observed['parent']!=current['parent'] or observed['existing']!=created:raise OSError('workspace publication needs reconciliation')
                    assert_request_active();assert_consent_active()
                    result=dict(preparation_id=body['consent_id'],target=request['target'],workspace=current['path'],status='workspace_ready',environment='metadata',execution=False,native_session_created=False)
                    with self.db:
                        self.db.execute("UPDATE session_preparations SET status='completed',result=? WHERE id=?",(encoded(result),body['consent_id']))
                        assert_request_active();assert_consent_active()
                return 201,result
            except Exception:
                self.db.rollback()
                if attempted:
                    return 503,dict(error='workspace_outcome_uncertain',consent_id=body['consent_id'],reconcile_required=True)
                raise
            except BaseException:
                self.db.rollback();raise
        return None
