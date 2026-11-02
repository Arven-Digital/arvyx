"""Confirmed exact owner-to-native-pane presentation, never a provider launcher.

The admitted onboarding artifact runs only the fixed AMC attachment bridge. The
owner created/resumed the conversation under separate consent. Pane attempts are
fenced before API effects; a lost acknowledgement cannot create another tab.
"""
import hashlib,json,shlex,subprocess,sys
from pathlib import Path
from .native_artifact_policy import VerifiedNative
from .cockpit_arvyx import frontend_environment,_focus_pane
from .external_workspace import _read
from .session_workspaces import encoded
from .reviewed_actions import assert_consent_active, current_consent_expiry

class NativePresentation:
    def __init__(self,owner_home,frontend,binary,db):
        self.owner_home=Path(owner_home).resolve();self.frontend=Path(frontend).absolute();self.binary=Path(binary).absolute();self.db=db
        self.db.execute('''CREATE TABLE IF NOT EXISTS native_presentations(
            owner_session TEXT PRIMARY KEY,owner_incarnation TEXT NOT NULL,epoch INTEGER NOT NULL,
            target TEXT NOT NULL,status TEXT NOT NULL,pane TEXT,workspace TEXT,tab TEXT)''');self.db.commit()
    def identity(self):
        raw,_,_=_read(self.frontend,('bindings.json',),256*1024);binding=json.loads(raw)
        if Path(binding['authority_home']).resolve()!=self.owner_home:raise PermissionError('native frontend owner mismatch')
        with VerifiedNative(self.binary,binding,required_capability='onboarding-v1') as native:
            return dict(bindings_sha256=hashlib.sha256(raw).hexdigest(),binary_sha256=native.digest)
    def present(self,proof,target,*,producer):
        expires=current_consent_expiry()
        if expires is None:raise ValueError('native presentation requires original reviewed consent expiry')
        producer.verify(proof,target);expected=self.identity()
        raw,_,_=_read(self.frontend,('bindings.json',),256*1024);binding=json.loads(raw)
        if hashlib.sha256(raw).hexdigest()!=expected['bindings_sha256']:raise PermissionError('frontend binding changed')
        sid=proof['owner_session'];saved_target=encoded(target)
        row=self.db.execute('SELECT owner_incarnation,epoch,target,status,pane,workspace,tab FROM native_presentations WHERE owner_session=?',(sid,)).fetchone()
        if row and (tuple(row[:3])!=(proof['owner_incarnation'],proof['epoch'],saved_target) or row[3]!='completed'):
            raise PermissionError('native presentation uncertain or stale; reconcile exact tab without recreation')
        env=frontend_environment(self.frontend);env['PYTHONPATH']=str(Path(__file__).resolve().parents[1])
        with VerifiedNative(self.binary,binding,required_capability='onboarding-v1') as native:
            def command(*args):
                from .public_onboarding_api import assert_request_active
                assert_request_active()
                assert_consent_active()
                value=json.loads(native.invoke(subprocess.check_output,['--session','amc',*args],env=env,timeout=2))
                if type(value) is not dict or 'error' in value:raise OSError('native API outcome uncertain')
                return value['result']
            snapshot=command('api','snapshot')['snapshot']['panes']
            if row:
                pane,workspace,tab=row[4:]
                exact=[p for p in snapshot if p['pane_id']==pane and p['workspace_id']==workspace and p['tab_id']==tab]
                if len(exact)!=1:raise PermissionError('exact native pane gone; no recreation')
            else:
                existing=[b for b in binding.get('bindings',[]) if b.get('sid')==sid]
                if len(existing)>1:raise PermissionError('ambiguous exact pane binding')
                pane=existing[0]['pane'] if existing else None
                exact=[p for p in snapshot if p['pane_id']==pane] if pane else []
                if existing and len(exact)!=1:raise PermissionError('bound native pane unavailable; no fallback')
                assert_consent_active()
                with self.db:
                    self.db.execute("INSERT INTO native_presentations VALUES(?,?,?,?,'ambiguous',NULL,NULL,NULL)",(sid,proof['owner_incarnation'],proof['epoch'],saved_target))
                    assert_consent_active()
                if exact:
                    workspace,tab=exact[0]['workspace_id'],exact[0]['tab_id']
                else:
                    result=command('workspace','create','--cwd',str(self.owner_home),'--label','Arvyx / exact native session','--no-focus')
                    pane=result['root_pane']['pane_id'];workspace=result['workspace']['workspace_id'];tab=result['tab']['tab_id']
                    argv=[sys.executable,'-m','arvyx_control.cockpit_arvyx','--home',str(self.owner_home),'--sid',sid,'--native-proof',encoded(proof),'--native-target',encoded(target),'--native-consent-expires',str(expires)]
                    command('pane','run',pane,shlex.join(argv))
            command('workspace','focus',workspace);command('tab','focus',tab)
            assert_consent_active();_focus_pane(self.frontend,pane)
            observed=command('api','snapshot')['snapshot']['panes']
            exact=[p for p in observed if p.get('pane_id')==pane and p.get('workspace_id')==workspace and p.get('tab_id')==tab and p.get('focused') is True]
            if len(exact)!=1 or [p['pane_id'] for p in observed if p.get('focused') is True]!=[pane]:raise OSError('exact native focus not observed; do not retry creation')
            producer.verify(proof,target)
            if self.identity()!=expected:raise OSError('native artifact/binding changed during presentation')
            with self.db:self.db.execute("UPDATE native_presentations SET status='completed',pane=?,workspace=?,tab=? WHERE owner_session=?",(pane,workspace,tab,sid))
            producer.record_pane(proof,target,expected['bindings_sha256'],dict(pane=pane,workspace=workspace,tab=tab))
            return dict(proof,pane_id=pane,workspace_id=workspace,tab_id=tab,native_focus_observed=True)
