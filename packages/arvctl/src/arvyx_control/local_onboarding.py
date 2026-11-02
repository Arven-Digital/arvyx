"""Explicit local composition over public onboarding authority."""
import hashlib
import json
from pathlib import Path
import sqlite3
from .agent_creation import AgentCreation
from .agent_sessions import AgentSessions
from .harness_discovery import discover_harnesses
from .public_onboarding_api import OwnerAdapters, PublicOnboardingAPI


def local_composition(directory, *, vault, machine_id, capability, discovery_home=None, authorize=None, pairing=None, workspace_roots=None, delegation_config=None):
    from .replica_authority import assert_mutation_authority
    assert_mutation_authority(Path(vault))
    directory=Path(directory)
    profiles=directory/'profiles';profiles.mkdir(mode=0o700,exist_ok=True)
    creation=AgentCreation(sqlite3.connect(directory/'agents.sqlite',check_same_thread=False),profiles,
        workspace_id='local',local_host=machine_id,isolated_harnesses={'hermes'})
    discovery=(lambda: discover_harnesses(discovery_home)) if discovery_home else (lambda: dict(candidates=[],truncated=False,incomplete=True,incomplete_reasons=['discovery_root_not_configured']))
    owner=OwnerAdapters(discovery,creation,AgentSessions({}),mode='real-local')
    owner.extension=LocalOnboarding(owner,vault,machine_id,authorize=authorize,pairing=pairing,workspace_roots=workspace_roots)
    if delegation_config is not None:
        from .replica_authority import authority_context
        from .delegation_runtime import load_delegations
        with authority_context(owner.extension.vault,getattr(owner.extension,'state',None)):
            owner.extension.delegations=load_delegations(delegation_config)
    return PublicOnboardingAPI(credentials={hashlib.sha256(capability.encode()).hexdigest():'local-owner'},owners={'local-owner':owner})


class LocalOnboarding:
    """Human-only service extension; metadata consent never authorizes execution.

    This reuses AgentCreation's digest-approved allowlist and HermesHistory's
    exact read-only routing. Attempt state follows the explicit-consent pattern
    in cockpit_consent: persist ambiguity before an operation, never replay it.
    """
    def __init__(self, owner, vault, machine_id, *, authorize=None, pairing=None, workspace_roots=None):
        self.owner, self.vault, self.machine = owner, Path(vault), machine_id
        self.authorize = authorize
        self.pairing = pairing
        self.sources = {}
        self.delegations = None
        self.native = None
        self.workspace_roots = dict(workspace_roots or {})
        from .session_workspaces import SessionWorkspaces
        self.workspaces = SessionWorkspaces(self)
        db = owner.creation.db
        db.executescript('''CREATE TABLE IF NOT EXISTS onboarding_consents (
            id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, payload TEXT NOT NULL,
            expires REAL NOT NULL, status TEXT NOT NULL, result TEXT);
            CREATE TABLE IF NOT EXISTS onboarding_profiles (
                agent_id TEXT PRIMARY KEY, profile TEXT UNIQUE NOT NULL);
        ''')
        from .reviewed_actions import ReviewedActions
        self.reviewed_actions=ReviewedActions(self)
        import secrets
        self.attempt_incarnation=secrets.token_hex(16)
        from .authority_attempts import migrate_attempts
        migrate_attempts(db,self.attempt_incarnation)
        db.execute('''CREATE TABLE IF NOT EXISTS onboarding_connections (
            agent_id TEXT PRIMARY KEY,target TEXT NOT NULL,identity TEXT NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS onboarding_connection_pins (
            agent_id TEXT PRIMARY KEY,target TEXT NOT NULL,snapshot TEXT NOT NULL)''');db.commit()
        self._restore_profiles()

    def _restore_profiles(self):
        from .hermes_history import HermesHistory
        from .agent_sessions import SessionTarget
        from .cockpit_primary import compatible_native_identity
        from .metadata_adapters import METADATA_HARNESSES, open_history
        db=self.owner.creation.db
        for agent,saved,identity in db.execute('SELECT agent_id,target,identity FROM onboarding_connections'):
            target=SessionTarget(**json.loads(saved))
            try:
                pin=db.execute('SELECT snapshot FROM onboarding_connection_pins WHERE agent_id=? AND target=?',
                               (agent,saved)).fetchone()
                # Legacy rows did not retain directory consent. Reconnect them
                # explicitly rather than deriving approval from today's path.
                if pin is None:continue
                snapshot=json.loads(pin[0])
                # Pins written before the adapter registry were Hermes-only.
                harness=snapshot.get('harness','hermes')
                if harness not in METADATA_HARNESSES or not compatible_native_identity(self.vault,agent,self.machine,harness):
                    continue
                adapter=open_history(harness,target.workspace_id,review_snapshot=snapshot)
                if json.dumps(adapter.identity)!=identity:continue
                adapter.target=target;adapter.metadata(target)
            except (OSError,ValueError,sqlite3.Error):continue
            self.owner.targets=frozenset(set(self.owner.targets)|{target})
            self.owner.sessions._adapters[target]=adapter
            if isinstance(adapter,HermesHistory):
                source_id=hashlib.sha256((agent+'\0'+str(adapter.home)).encode()).hexdigest()
                self.sources[source_id]=(adapter.home,target)

    def capabilities(self):
        from .metadata_adapters import catalog as metadata_adapter_catalog
        return dict(delegation_targets=self.delegations.catalog() if self.delegations else [],
            metadata_adapters=metadata_adapter_catalog(),
            native_lifecycle=self.native is not None,
            reviewed_actions=True,session_preparation=bool(self.workspace_roots), manual_connection=True, pairing=self.pairing is not None,
            instruction_copy=True, creation_preview=True,
            environments=[dict(id='metadata',available=True),
                *[dict(id=mode,available=False,reason='No approved executor is configured.')
                  for mode in ('sandbox','host','root')]],
            instruction_sources=[dict(id=key,label=target.agent_id)
                for key, (_,target) in self.sources.items()])

    def _source(self, source_id):
        source, target = self.sources[source_id]
        if target not in self.owner.targets:
            raise ValueError('instruction connection changed; review again')
        adapter = self.owner.sessions._adapters.get(target)
        from .hermes_history import HermesHistory
        if not isinstance(adapter, HermesHistory) or adapter.home != source:
            raise ValueError('exact reviewed instruction adapter required')
        adapter.validate_review()
        return source, target

    def _request(self, body):
        from .agent_creation import CreationRequest, IdentityFile
        if body['environment'] != 'metadata':
            raise UnsupportedEnvironment
        mode = body['identity_mode']
        if mode not in ('clean','copy'):
            raise ValueError('explicit instruction choice required')
        files = body.get('identity_files', [])
        if mode == 'clean':
            if files or body.get('source_id'):
                raise ValueError('clean creation cannot copy files')
            source = None
        else:
            if not isinstance(files,list) or not files:
                raise ValueError('individually reviewed instruction selection required')
            source, target = self._source(body['source_id'])
        request = CreationRequest(body['name'],body['harness'],self.machine,
            source_root=source,identity_files=tuple(IdentityFile(**f) for f in files))
        self.owner.creation._validate(request)
        if mode == 'copy':
            self._source(body['source_id'])
        return request

    def route(self, path, method, body,*,review_snapshot=None):
        from .public_onboarding_api import assert_request_active
        from .replica_authority import assert_mutation_authority
        assert_mutation_authority(self.vault)
        import secrets
        import time
        from dataclasses import asdict
        from .agent_creation import _IDENTITY
        from .external_workspace import _read
        from .security import contains_literal_secret
        api = PublicOnboardingAPI
        if path.startswith('native/'):
            if self.native is None:
                return 501, dict(error='explicit_native_producer_unavailable', queued=False,
                    execution=False, native_session_created=False)
            return self.native.route(path, method, body,review_snapshot=review_snapshot)
        if path == 'delegations' or path.startswith('delegations/'):
            if self.delegations is None:
                return 501, dict(error='approved_organizer_executor_unavailable', queued=False)
            return self.delegations.route(path, method, body)
        response = self.workspaces.route(path, method, body)
        if response is not None:
            return response
        if path == 'targets' and method == 'GET':
            api._fields(body)
            return 200, dict(items=[asdict(t) for t in sorted(self.owner.targets,key=repr)])
        if path == 'manual/connect' and method == 'POST':
            api._fields(body,('family','path','agent_id','confirmed'))
            api._confirm(body)
            from .metadata_adapters import ADAPTERS
            family=body['family']
            if family not in ADAPTERS:
                return 501, dict(error='compatible_local_adapter_unavailable')
            kind=ADAPTERS[family]
            from .cockpit_primary import compatible_native_identity
            if not compatible_native_identity(self.vault,body['agent_id'],self.machine,family):
                raise PermissionError
            value=body['path']
            if not isinstance(value,str) or not Path(value).is_absolute() or '..' in Path(value).parts:
                raise ValueError('explicit absolute profile directory required')
            path = Path(value)
            kind.refuse_links(path)
            from .hermes_history import HermesHistory
            from .agent_sessions import SessionTarget
            if not isinstance(review_snapshot, dict):
                raise ValueError('reviewed exact profile identity required')
            adapter = kind.open(path, review_snapshot=review_snapshot)
            if adapter.identity is None:
                raise ValueError(f'existing {kind.label} metadata required')
            adapter.target = SessionTarget(self.machine,body['agent_id'],str(adapter.home),
                hashlib.sha256((repr(adapter.identity)+secrets.token_hex(16)).encode()).hexdigest())
            adapter.metadata(adapter.target)  # Validate schema before publishing connection.
            db=self.owner.creation.db
            saved_target=json.dumps(asdict(adapter.target))
            saved_pin=json.dumps(dict(profile=str(adapter.home),identity=list(adapter.identity),
                                     home_identity=list(adapter.profile.home_identity),harness=family))
            committed=False
            try:
                with db:
                    db.execute('BEGIN IMMEDIATE')
                    prior=db.execute('SELECT profile FROM onboarding_profiles WHERE agent_id=?',(body['agent_id'],)).fetchone()
                    if prior and prior[0] != str(adapter.home):
                        raise ValueError('agent profile is immutable; explicit administrative reconciliation required')
                    previous_connection=db.execute('SELECT agent_id,target,identity FROM onboarding_connections WHERE agent_id=?',
                                                   (body['agent_id'],)).fetchone()
                    previous_pin=db.execute('SELECT agent_id,target,snapshot FROM onboarding_connection_pins WHERE agent_id=?',
                                            (body['agent_id'],)).fetchone()
                    adapter.validate_review()
                    assert_request_active()
                    db.execute('INSERT OR IGNORE INTO onboarding_profiles VALUES(?,?)',(body['agent_id'],str(adapter.home)))
                    mapped=db.execute('SELECT agent_id FROM onboarding_profiles WHERE profile=?',(str(adapter.home),)).fetchone()
                    if mapped[0] != body['agent_id']:
                        raise ValueError('profile belongs to a different exact agent')
                    db.execute('INSERT OR REPLACE INTO onboarding_connections VALUES(?,?,?)',
                        (body['agent_id'],saved_target,json.dumps(adapter.identity)))
                    db.execute('INSERT OR REPLACE INTO onboarding_connection_pins VALUES(?,?,?)',
                        (body['agent_id'],saved_target,saved_pin))
                    adapter.validate_review()
                    assert_request_active()
                committed=True
                adapter.validate_review()
                assert_request_active()
            except BaseException:
                if committed:
                    with db:
                        db.execute('BEGIN IMMEDIATE')
                        current=db.execute('SELECT target FROM onboarding_connections WHERE agent_id=?',
                                           (body['agent_id'],)).fetchone()
                        if current and current[0]==saved_target:
                            db.execute('DELETE FROM onboarding_connections WHERE agent_id=?',(body['agent_id'],))
                            db.execute('DELETE FROM onboarding_connection_pins WHERE agent_id=?',(body['agent_id'],))
                            if previous_connection is not None:
                                db.execute('INSERT INTO onboarding_connections VALUES(?,?,?)',tuple(previous_connection))
                            if previous_pin is not None:
                                db.execute('INSERT INTO onboarding_connection_pins VALUES(?,?,?)',tuple(previous_pin))
                            if prior is None:
                                db.execute('DELETE FROM onboarding_profiles WHERE agent_id=? AND profile=?',
                                           (body['agent_id'],str(adapter.home)))
                raise
            old=[t for t in self.owner.targets if t.agent_id==body['agent_id']]
            for target in old:
                self.owner.sessions._adapters.pop(target,None)
            self.owner.targets=frozenset((set(self.owner.targets)-set(old))|{adapter.target})
            self.owner.sessions._adapters[adapter.target]=adapter
            source_id=None
            if isinstance(adapter,HermesHistory):
                # Instruction copy reads the Hermes identity allowlist; file stores expose none.
                source_id=hashlib.sha256((body['agent_id']+'\0'+str(adapter.home)).encode()).hexdigest()
                self.sources[source_id]=(adapter.home,adapter.target)
            return 200, dict(target=asdict(adapter.target),connected=True,live_runtime=False,
                metadata_only=True,harness=family,instruction_source_id=source_id,mode=self.owner.mode)
        if path == 'instructions/preview' and method == 'POST':
            api._fields(body,('source_id','paths','confirmed'),('offset',));api._confirm(body)
            source,target=self._source(body['source_id'])
            paths=body['paths']
            if not isinstance(paths,list) or not paths or len(paths)>len(_IDENTITY) or len(set(paths))!=len(paths):
                raise ValueError('explicit distinct instruction selection required')
            files=[]
            for path in paths:
                if path not in _IDENTITY:
                    raise ValueError('instruction file not allowlisted')
                data,_,_=_read(source,(path,),256*1024)
                text=data.decode('utf-8')
                if '\0' in text or contains_literal_secret(text):
                    raise ValueError('unsafe instruction material')
                item=dict(path=path,approved_sha256=hashlib.sha256(data).hexdigest(),content=text)
                if 'offset' in body:
                    offset=body['offset']
                    if len(paths)!=1 or type(offset) is not int or not 0<=offset<=len(text):
                        raise ValueError('single-file character offset required')
                    # At most 12 JSON bytes per Unicode character (surrogate pair).
                    # 32K characters leaves ample envelope room below the 1 MiB client cap.
                    end=min(offset+32768,len(text))
                    item.update(content=text[offset:end],next_offset=end if end<len(text) else None)
                files.append(item)
            self._source(body['source_id'])
            assert_request_active()
            return 200, dict(source_id=body['source_id'],files=files)
        if path.startswith('agents/attempts/') and method == 'GET':
            api._fields(body)
            identifier=path.removeprefix('agents/attempts/')
            row=self.owner.creation.db.execute('SELECT status,expires,result FROM onboarding_consents WHERE id=?',(identifier,)).fetchone()
            if row is None:
                return 404,dict(error='creation_attempt_not_found')
            return 200,dict(id=identifier,status=row[0],expires_at=row[1],
                result=json.loads(row[2]) if row[2] else None,replay_allowed=False)
        if path == 'agents/prepare' and method == 'POST':
            api._fields(body,('name','harness','environment','identity_mode'),('source_id','identity_files'))
            try: self._request(body)
            except UnsupportedEnvironment:
                return 501, dict(error='execution_environment_unavailable',queued=False)
            payload=json.dumps(body,sort_keys=True,separators=(',',':'))
            digest=hashlib.sha256(payload.encode()).hexdigest()
            identifier=secrets.token_hex(16);expires=time.time()+300
            with self.owner.creation.db as db:
                db.execute('INSERT INTO onboarding_consents VALUES(?,?,?,?,?,NULL)',(identifier,digest,payload,expires,'prepared'))
            return 200, dict(consent_id=identifier,sha256=digest,expires_at=expires,
                environment='metadata',request=body,execution=False)
        if path == 'agents/commit' and method == 'POST':
            api._fields(body,('consent_id','consent_sha256','confirmed'));api._confirm(body)
            db=self.owner.creation.db
            db.execute('BEGIN IMMEDIATE')
            try:
                row=db.execute('SELECT sha256,payload,expires,status FROM onboarding_consents WHERE id=?',(body['consent_id'],)).fetchone()
                if not row or row[0]!=body['consent_sha256'] or row[2]<=time.time() or row[3]!='prepared':
                    raise ValueError('invalid, expired or attempted consent')
                request=self._request(json.loads(row[1]))
                from .reviewed_actions import assert_consent_active
                assert_consent_active(row[2])
                # Persist BEFORE creation. A crash cannot replay an uncertain operation.
                db.execute("UPDATE onboarding_consents SET status='ambiguous' WHERE id=?",(body['consent_id'],))
                db.commit()
            except BaseException:
                db.rollback();raise
            from .public_onboarding_api import assert_request_active
            try:
                assert_request_active()
                from .reviewed_actions import consent_scope
                with consent_scope(row[2]):
                    created=self.owner.creation.create(request)
                result=dict(asdict(created),environment='metadata',metadata_only=True,
                            execution=False,native_session_created=False)
                with db:
                    db.execute("UPDATE onboarding_consents SET status='completed',result=? WHERE id=?",(json.dumps(result),body['consent_id']))
            except Exception:
                # The durable marker predates the effect. Do not let dispatch
                # relabel a partial creation as an ordinary validation refusal.
                return 503, dict(error='creation_outcome_uncertain',consent_id=body['consent_id'],reconcile_required=True)
            return 201,result
        if path.startswith('pairing/'):
            if self.pairing is None:
                return 501,dict(error='pairing_transport_not_configured')
            store=self.pairing.store
            if path=='pairing/pending' and method=='GET':
                api._fields(body)
                with store.lock:
                    items=[dict(row) for row in store.db.execute("SELECT claim_id,fingerprint,name,expires FROM machine_pairing_codes WHERE state='claimed' AND expires>? ORDER BY expires,claim_id",(store._now(),))]
                return 200,dict(claims=items)
            if path=='pairing/issue' and method=='POST':
                api._fields(body,('confirmed',));api._confirm(body)
                from .reviewed_actions import current_consent_expiry
                ticket=store.issue(actor='local-human',consent_expires_at=current_consent_expiry())
                return 201,dict(code=ticket.code,expires_at=ticket.expires_at,enrolled=False)
            if path=='pairing/decide' and method=='POST':
                api._fields(body,('fingerprint','claim_id','approved','confirmed'));api._confirm(body)
                if type(body['approved']) is not bool:
                    raise ValueError('explicit approval or denial required')
                claim=review_snapshot.get('claim') if isinstance(review_snapshot,dict) else None
                if (not isinstance(body['claim_id'],str) or not body['claim_id']
                        or not isinstance(claim,dict) or claim.get('claim_id') != body['claim_id']
                        or claim.get('fingerprint') != body['fingerprint']):
                    raise PermissionError('stable reviewed pairing claim required')
                from .reviewed_actions import current_consent_expiry
                decision=store.decide(body['fingerprint'],actor='local-human',approved=body['approved'],deny=not body['approved'],
                    claim_id=claim['claim_id'],review_snapshot=claim,consent_expires_at=current_consent_expiry())
                return (200 if decision.allowed else 409),asdict(decision)
        return None


class UnsupportedEnvironment(ValueError):
    pass
