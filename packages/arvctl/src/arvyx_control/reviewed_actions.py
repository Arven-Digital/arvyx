"""Shared durable review for human metadata access and enrollment decisions.

A capability authenticates the local owner, not a biological user gesture. The
client must display the prepared operation and obtain explicit confirmation.
Records bind that authenticated owner, exact inputs and current destination.
Ambiguous attempts never replay; no confirmation flag bypass is accepted.
"""
from dataclasses import asdict
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import math
from pathlib import Path
import secrets
import time

ACTIONS=frozenset(('native/revoke','native/present','native/attach','native/open','manual/connect','profiles/connect','profiles/register','connect','sessions/select','instructions/preview','pairing/issue','pairing/decide'))
_consent_expiry = ContextVar('reviewed_consent_expiry', default=None)
_current_attempt = ContextVar('reviewed_attempt', default=None)


def record_attempt_plan(plan):
    """Persist what a reviewed effect is about to publish, before it publishes.

    An effect that mints identifiers calls this before its first durable write,
    so an uncertain outcome (REV-0568) still names what may now exist. Outside
    a reviewed commit there is no attempt row; the call is a no-op.
    """
    attempt = _current_attempt.get()
    if attempt is None:
        return False
    actions, consent_id = attempt
    actions.record_plan(consent_id, plan)
    return True


def current_consent_expiry():
    return _consent_expiry.get()


def assert_consent_active(expires=None):
    """Original wall-clock consent, independent of request transport budgets."""
    for value in (current_consent_expiry(), expires):
        if value is not None and (type(value) not in (int, float) or not math.isfinite(value) or time.time() >= value):
            raise ValueError('consent expired before effect admission')


@contextmanager
def consent_scope(expires):
    assert_consent_active(expires)
    inherited = current_consent_expiry()
    token = _consent_expiry.set(min(expires, inherited) if inherited is not None else expires)
    try:
        yield
    finally:
        _consent_expiry.reset(token)


def call_with_publication_guard(effect, *args):
    """Trusted injected effects must gate after their own blocking preparation."""
    from .public_onboarding_api import assert_request_active
    assert_request_active()
    if current_consent_expiry() is None:
        return effect(*args)
    import inspect
    expires = current_consent_expiry()
    def publication_guard():
        assert_request_active()
        assert_consent_active(expires)
    try:
        inspect.signature(effect).bind(*args, publication_guard=publication_guard)
    except TypeError:
        raise PermissionError('reviewed adapter requires publication_guard at its final publication boundary') from None
    return effect(*args, publication_guard=publication_guard)


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'))


class ReviewedActions:
    def __init__(self,extension):
        self.extension=extension;self.owner=extension.owner;self.db=self.owner.creation.db
        self.db.execute('''CREATE TABLE IF NOT EXISTS reviewed_actions (
            id TEXT PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,
            digest TEXT NOT NULL,payload TEXT NOT NULL,snapshot TEXT NOT NULL,
            expires REAL NOT NULL,status TEXT NOT NULL,result TEXT)''');self.db.commit()

    def snapshot(self,api,key,action,body):
        API=type(api);owner=self.owner
        if action not in ACTIONS:raise ValueError('unsupported reviewed action')
        API._confirm(body)
        if action=='native/revoke':
            API._fields(body,('confirmed',))
            if self.extension.native is None:raise PermissionError('native producer unavailable')
            return self.extension.native.producer.inspect()
        if action in ('native/present','native/attach'):
            API._fields(body,('target','session_id','confirmed'))
            target=API._target(owner,body['target']);owner.sessions.recent(target)
            if self.extension.native is None:raise PermissionError('exact native producer unavailable')
            proof=self.extension.native.producer.resolve(body['target'],body['session_id'])
            if action=='native/present':
                if self.extension.native.frontend is None:raise PermissionError('admitted native frontend unavailable')
                return dict(proof=proof,frontend=self.extension.native.frontend.identity())
            return proof
        if action=='native/open':
            API._fields(body,('target','owner_session','confirmed'))
            target=API._target(owner,body['target']);owner.sessions.recent(target)
            native=self.extension.native
            if native is None:raise ValueError('native producer unavailable')
            return native.exact(body['target'],body['owner_session'])
        if action=='profiles/connect':
            request=api._profile_request(key,body)
            candidate=api._candidates[key][body['candidate_id']]
            return dict(candidate=candidate,profile=self.snapshot(api,key,'manual/connect',request))
        if action=='profiles/register':
            API._fields(body,('candidate_id','display_name','confirmed'))
            candidate=api._candidates.get(key,{}).get(body['candidate_id'])
            from .metadata_adapters import METADATA_HARNESSES
            if candidate is None or candidate.get('family') not in METADATA_HARNESSES:raise ValueError('compatible discovered profile unavailable')
            from .registry_enrollment import preflight
            return dict(candidate=candidate,registration=preflight(self.extension.vault,self.extension.machine,body['display_name'],candidate['family']))
        if action=='manual/connect':
            API._fields(body,('family','path','agent_id','confirmed'))
            from .metadata_adapters import METADATA_HARNESSES, open_history
            if body['family'] not in METADATA_HARNESSES:raise ValueError('local adapter unavailable')
            from .cockpit_primary import compatible_native_identity
            if not compatible_native_identity(self.extension.vault,body['agent_id'],self.extension.machine,body['family']):raise PermissionError
            path=Path(body['path'])
            if not path.is_absolute() or '..' in path.parts:raise ValueError('absolute exact profile required')
            history=open_history(body['family'],path)
            if history.identity is None:raise ValueError('existing native metadata required')
            # One profile binds one identity. Refuse at review time; a commit-time
            # constraint failure would otherwise be reported as an ambiguous outcome.
            holder=self.db.execute('SELECT agent_id FROM onboarding_profiles WHERE profile=?',(str(history.home),)).fetchone()
            if holder is not None and holder[0]!=body['agent_id']:raise ValueError('profile already connected to another identity')
            # Bind registry bytes as well as the profile/database incarnation.
            records=[]
            from .external_workspace import _read
            from .auth import AGENT_ID_RE
            for kind in ('agents','machines','runtimes'):
                identifier=(body['agent_id'] if kind=='agents' else self.extension.machine if kind=='machines' else None)
                if identifier is None:
                    agent=json.loads(_read(self.extension.vault,('registry','agents',body['agent_id']+'.json'),256*1024)[0])
                    identifier=agent['runtime_id']
                if not isinstance(identifier,str) or not AGENT_ID_RE.fullmatch(identifier):raise PermissionError('invalid exact registry identity')
                data=_read(self.extension.vault,('registry',kind,identifier+'.json'),256*1024)[0]
                records.append(hashlib.sha256(data).hexdigest())
            return dict(profile=str(history.home),identity=history.identity,home_identity=list(history.profile.home_identity),registry=records,harness=body['family'])
        if action=='connect':
            API._fields(body,('candidate_id','confirmed'))
            candidate=api._candidates.get(key,{}).get(body['candidate_id'])
            if candidate is None or not callable(owner.connectors.get(body['candidate_id'])):raise ValueError('candidate unavailable')
            return dict(candidate=candidate,connector_incarnation=api._connector_incarnation(owner.connectors[body['candidate_id']]))
        if action=='sessions/select':
            from .agent_sessions import SessionRoute
            API._fields(body,('route','confirmed'));route=body['route'];API._fields(route,('target','session_id'))
            target=API._target(owner,route['target']);exact=SessionRoute(target,route['session_id'])
            if not any(item.route==exact for item in owner.sessions._metadata(target)):raise ValueError('session unavailable')
            adapter=owner.sessions._adapter(target)
            return dict(route=asdict(exact),metadata=adapter.exact(exact.session_id) if hasattr(adapter,'exact') else None)
        if action=='instructions/preview':
            API._fields(body,('source_id','paths','confirmed'),('offset',))
            from .agent_creation import _IDENTITY
            from .external_workspace import _read
            source,target=self.extension.sources[body['source_id']]
            if target not in owner.targets:raise PermissionError
            paths=body['paths']
            if not isinstance(paths,list) or not paths or len(paths)>len(_IDENTITY) or len(set(paths))!=len(paths):raise ValueError('distinct allowlisted instructions required')
            files={}
            for path in paths:
                if path not in _IDENTITY:raise ValueError('instruction not allowlisted')
                data,_,_=_read(source,(path,),256*1024);files[path]=hashlib.sha256(data).hexdigest()
            return dict(target=asdict(target),files=files)
        if self.extension.pairing is None:raise ValueError('pairing unavailable')
        if action=='pairing/issue':
            API._fields(body,('confirmed',));return dict(machine=self.extension.machine)
        API._fields(body,('fingerprint','claim_id','approved','confirmed'))
        if type(body['approved']) is not bool:raise ValueError('approval or denial required')
        if not isinstance(body['claim_id'],str) or not body['claim_id'] or len(body['claim_id'])>128:
            raise ValueError('bounded exact pairing claim required')
        store=self.extension.pairing.store
        return dict(claim=store.claim_snapshot(body['fingerprint'],body['claim_id']))

    def record_plan(self,consent_id,plan):
        """Durably record the identifiers an in-flight ambiguous attempt will publish.

        reviewed_actions is a migrated view with INSTEAD OF triggers, so rowcount is
        not evidence; the write is checked by reading the row back before commit.
        """
        saved=encoded(dict(planned=plan))
        with self.db:
            row=self.db.execute('SELECT status,result FROM reviewed_actions WHERE id=?',(consent_id,)).fetchone()
            if row is None or row[0]!='ambiguous' or row[1] is not None:
                raise ValueError('attempt plan can be recorded once, only for the ambiguous attempt in flight')
            self.db.execute('UPDATE reviewed_actions SET result=? WHERE id=?',(saved,consent_id))
            if self.db.execute('SELECT result FROM reviewed_actions WHERE id=?',(consent_id,)).fetchone()[0]!=saved:
                raise OSError('attempt plan was not durably recorded')

    def _registry_present(self,planned):
        """Whether the identifiers an uncertain registration planned exist in the vault now."""
        from .cockpit_primary import read_native_registry
        present={}
        for kind,field in (('agents','agent_id'),('runtimes','runtime_id')):
            identifier=planned.get(field)
            try:
                record=read_native_registry(self.extension.vault,kind,identifier)
                present[kind[:-1]]=isinstance(record,dict) and record.get('id')==identifier
            except (OSError,ValueError,TypeError):
                present[kind[:-1]]=False
        return present

    def route(self,api,key,path,method,body):
        API=type(api)
        if path.startswith('actions/attempts/') and method=='GET':
            API._fields(body)
            row=self.db.execute('SELECT action,status,expires,result FROM reviewed_actions WHERE id=? AND actor=?',(path.removeprefix('actions/attempts/'),key)).fetchone()
            if row is None:return 404,dict(error='attempt_not_found')
            result=json.loads(row[3]) if row[3] else None
            response=dict(action=row[0],status=row[1],expires_at=row[2],result=result,replay_allowed=False)
            if row[1]=='ambiguous':
                # The effect may or may not have published. Report what it planned and
                # what exists now, so the operator reconciles instead of guessing.
                response['reconcile_required']=True
                planned=result.get('planned') if isinstance(result,dict) else None
                if row[0]=='profiles/register' and isinstance(planned,dict):
                    response['registry_present']=self._registry_present(planned)
            return 200,response
        if path=='actions/prepare' and method=='POST':
            API._fields(body,('action','request'))
            snapshot=self.snapshot(api,key,body['action'],body['request'])
            payload=encoded(body['request']);saved=encoded(snapshot)
            if len(payload.encode())+len(saved.encode())>65536:raise ValueError('review budget exceeded')
            digest=hashlib.sha256(encoded(dict(actor=key,action=body['action'],request=body['request'],snapshot=snapshot)).encode()).hexdigest()
            identifier=secrets.token_hex(16);expires=time.time()+300
            with self.db:self.db.execute('INSERT INTO reviewed_actions VALUES(?,?,?,?,?,?,?,?,NULL)',(identifier,key,body['action'],digest,payload,saved,expires,'prepared'))
            return 200,dict(consent_id=identifier,sha256=digest,expires_at=expires,action=body['action'],request=body['request'],snapshot=snapshot)
        if path=='actions/commit' and method=='POST':
            API._fields(body,('consent_id','consent_sha256','confirmed'));API._confirm(body)
            self.db.execute('BEGIN IMMEDIATE')
            try:
                row=self.db.execute('SELECT action,digest,payload,snapshot,expires,status FROM reviewed_actions WHERE id=? AND actor=?',(body['consent_id'],key)).fetchone()
                if row is None or row[1]!=body['consent_sha256'] or row[4]<=time.time() or row[5]!='prepared':raise ValueError('invalid, expired or attempted consent')
                action,payload=row[0],json.loads(row[2])
                if encoded(self.snapshot(api,key,action,payload))!=row[3]:raise ValueError('destination changed; review again')
                assert_consent_active(row[4])
                self.db.execute("UPDATE reviewed_actions SET status='ambiguous' WHERE id=?",(body['consent_id'],))
                assert_consent_active(row[4])
                self.db.commit()
            except BaseException:self.db.rollback();raise
            try:
                from .public_onboarding_api import assert_request_active
                attempt=_current_attempt.set((self,body['consent_id']))
                try:
                    with consent_scope(row[4]):
                        assert_request_active()
                        status,result=api._route(key,self.owner,'POST',action,payload,reviewed=True,review_snapshot=json.loads(row[3]))
                finally:
                    _current_attempt.reset(attempt)
                if status>=500:raise OSError('action result uncertain')
                # A pairing code is a transient credential, never durable result data.
                saved_result=({k:v for k,v in result.items() if k!='code'}
                              if action=='pairing/issue' else result)
                if action in ('native/open','native/attach'):saved_result={k:v for k,v in result.items() if k!='attachment'}
                if action=='instructions/preview':
                    saved_result=dict(source_id=result.get('source_id'),files=[
                        {k:v for k,v in f.items() if k!='content'} for f in result.get('files',[])])
                with self.db:self.db.execute('UPDATE reviewed_actions SET status=?,result=? WHERE id=?',('completed' if status<300 else 'denied',encoded(saved_result),body['consent_id']))
                return status,result
            except Exception:
                return 503,dict(error='action_outcome_uncertain',consent_id=body['consent_id'],reconcile_required=True)
        return None
