"""Durable, reviewed dispatch through explicitly configured exact endpoints.

Uses OrganizerAuthority's create/manage and explicitly attested executor decisions. Pairing,
main-agent election, browser fields and an available OS root never grant roles.
No command, native/provider process or remote transport is installed by this code.
Trusted integrators supply bounded executor endpoints under existing transport
trust. Fixtures supply only a disposable file effect; no real execution accepted.
"""
from dataclasses import asdict
import hashlib,json,secrets,time,threading
from .organizer_durable import private_database
from .security import contains_literal_secret


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'))


class DelegationService:
    def __init__(self,database,authority,actor,endpoints,*,remote_fence=None):
        if authority._backend is None:raise ValueError('durable policy required')
        self.remote_fence=remote_fence
        self.db=private_database(database);self.authority=authority;self.actor=actor;self.endpoints=dict(endpoints);self.lock=threading.RLock();self.endpoint_incarnations={}
        self.db.execute('''CREATE TABLE IF NOT EXISTS organizer_requests (
            id TEXT PRIMARY KEY,digest TEXT NOT NULL,payload TEXT NOT NULL,
            expires REAL NOT NULL,status TEXT NOT NULL,decision TEXT,result TEXT,endpoint TEXT NOT NULL DEFAULT '')''')
        if 'endpoint' not in {row[1] for row in self.db.execute('PRAGMA table_info(organizer_requests)')}:
            self.db.execute("ALTER TABLE organizer_requests ADD COLUMN endpoint TEXT NOT NULL DEFAULT ''")
        if 'consent' not in {row[1] for row in self.db.execute('PRAGMA table_info(organizer_requests)')}:
            # Empty legacy consent stays unknown, never fabricated as a gesture.
            self.db.execute("ALTER TABLE organizer_requests ADD COLUMN consent TEXT NOT NULL DEFAULT ''")
        self.db.commit()
        from .authority_attempts import migrate_attempts
        import secrets
        migrate_attempts(self.db,secrets.token_hex(16))
        # Separate immutable readback identity: no bearer ticket is retained and
        # no existing attempt/view schema or legacy authority is rewritten.
        self.db.execute('CREATE TABLE IF NOT EXISTS organizer_result_queries(id TEXT PRIMARY KEY,query TEXT NOT NULL)')
        self.db.commit()

    def close(self):
        self.db.close()
        resources=getattr(self,'_runtime_resources',None)
        if resources is not None:
            policy,fence,endpoints=resources
            for endpoint in endpoints:
                if hasattr(endpoint,'close'):endpoint.close()
            if fence is not None:fence.close()
            policy.close();self._runtime_resources=None

    def catalog(self):
        from .executor_endpoint import ExecutorEndpoint
        from .remote_delegation import RemoteDelegationEndpoint
        with self.lock:
            return [dict(machine=machine,executing_agent=agent,session=session,
                         environments=sorted(endpoint.environments))
                    for (machine,agent,session),endpoint in self.endpoints.items()
                    if type(endpoint) in (ExecutorEndpoint,RemoteDelegationEndpoint)]

    @staticmethod
    def _execution_binding(endpoint,plan):
        from .remote_delegation import RemoteDelegationEndpoint
        if type(endpoint) is RemoteDelegationEndpoint:
            return endpoint.execution_binding(plan)
        return endpoint.execution_binding()

    def _binding_preflight(self,plan):
        # Discovery is untrusted I/O, never part of the authority transaction.
        from .executor_endpoint import ExecutorEndpoint
        from .remote_delegation import RemoteDelegationEndpoint
        endpoint=self.endpoints.get((plan['machine'],plan['executing_agent'],plan['session']))
        if type(endpoint) not in (ExecutorEndpoint,RemoteDelegationEndpoint):
            raise PermissionError('closed bounded executor transport required')
        if self.authority._backend.depth:
            raise RuntimeError('binding discovery requires released policy guard')
        return endpoint,self._execution_binding(endpoint,plan)

    def _decision(self,plan,*,preflight=None):
        executor=None
        if plan['executing_agent'] is not None:
            try:executor=self.authority.identity_handle(plan['executing_agent'])
            except PermissionError:
                from .organizer_authority import Identity
                executor=Identity(plan['executing_agent'],'internal') # deliberately unauthenticated; policy denies
        decision=self.authority.authorize(self.actor,operation=plan['operation'],machine=plan['machine'],executing_agent=executor)
        if self.authority._backend.depth:
            self.authority._backend.checkpoint()
        if not decision.allowed:raise PermissionError(decision.reason)
        key=(plan['machine'],plan['executing_agent'],plan['session'])
        if key not in self.endpoints:raise PermissionError('approved exact executor unavailable')
        endpoint=self.endpoints[key]
        from .executor_endpoint import ExecutorEndpoint
        from .remote_delegation import RemoteDelegationEndpoint
        if type(endpoint) not in (ExecutorEndpoint, RemoteDelegationEndpoint):
            raise PermissionError('closed bounded executor transport required')
        if type(endpoint) is RemoteDelegationEndpoint and (plan['environment'] not in endpoint.environments or plan['operation']=='invoke_root' and endpoint.receiver_binding is None):
            raise PermissionError('authenticated local approval transfer and cross-host final-admission protocol unavailable')
        previous=self.endpoint_incarnations.get(key)
        observed,binding=self._binding_preflight(plan) if preflight is None else preflight
        if observed is not endpoint:raise PermissionError('executor changed during binding discovery')
        if previous is None or previous[0] is not endpoint or previous[2]!=binding:
            previous=(endpoint,secrets.token_hex(32),binding);self.endpoint_incarnations[key]=previous
        generation=previous[1]
        return decision,endpoint,generation

    def _retain_query(self,effect):
        from .executor_endpoint import result_query
        self.db.execute('INSERT INTO organizer_result_queries VALUES(?,?)',
                        (effect['request_id'],canonical(result_query(effect))))

    def _recover_result(self,identifier,query):
        from .executor_endpoint import ExecutorEndpoint
        from .remote_delegation import RemoteDelegationEndpoint
        row=self.db.execute("SELECT json_extract(record,'$.payload'),status,result FROM authority_attempts WHERE namespace='organizer_requests' AND id=?",(identifier,)).fetchone()
        retained=self.db.execute('SELECT query FROM organizer_result_queries WHERE id=?',(identifier,)).fetchone()
        if row is None or retained is None or canonical(query)!=retained[0]:
            raise PermissionError('exact retained delegation required; no replay')
        if row[1]=='completed':return json.loads(row[2])
        if row[1]!='ambiguous':raise PermissionError('only attempted delegation can be reconciled')
        plan=json.loads(row[0])
        endpoint=self.endpoints.get((plan['machine'],plan['executing_agent'],plan['session']))
        if endpoint is None or type(endpoint) not in (ExecutorEndpoint,RemoteDelegationEndpoint):
            raise PermissionError('original closed result transport unavailable')
        result=endpoint.recover(query)
        # Only exact authenticated durable completion changes the local ledger.
        # Neither a missing record nor a failed read authorizes another effect.
        with self.db:self.db.execute("UPDATE authority_attempts SET status='completed',result=?,record=json_set(record,'$.status','completed','$.result',?) WHERE namespace='organizer_requests' AND id=? AND status='ambiguous'",(canonical(result),canonical(result),identifier))
        return result

    def route(self,path,method,body):
        from .public_onboarding_api import PublicOnboardingAPI as API
        with self.lock:
            if path in ('delegations/result','delegations/reconcile') and method=='POST':
                from .executor_endpoint import validate_result_query
                if path=='delegations/reconcile':
                    API._fields(body,('consent_id','consent_sha256'))
                    identifier=body['consent_id']
                    if (not isinstance(identifier,str) or len(identifier)!=32
                            or not isinstance(body['consent_sha256'],str) or len(body['consent_sha256'])!=64):
                        raise ValueError('exact original consent identity required')
                    row=self.db.execute("SELECT json_extract(record,'$.digest') FROM authority_attempts WHERE namespace='organizer_requests' AND id=?",(identifier,)).fetchone()
                    retained=self.db.execute('SELECT query FROM organizer_result_queries WHERE id=?',(identifier,)).fetchone()
                    if row is None or row[0]!=body['consent_sha256'] or retained is None:
                        raise PermissionError('original exact consent and retained attempt required')
                    query=json.loads(retained[0])
                else:
                    query=body;validate_result_query(query);identifier=query['request_id']
                try:result=self._recover_result(identifier,query)
                except (OSError,ValueError,TimeoutError):
                    return 503,dict(error='delegation_outcome_uncertain',id=identifier,status='ambiguous',reconcile_required=True)
                if path=='delegations/result':
                    return 200,dict(request_id=identifier,status='completed',reference=result['reference'])
                return 200,dict(id=identifier,status='completed',result=result,queued=False)
            if path=='delegations/fence' and method=='GET':
                API._fields(body)
                with self.authority._lock:
                    identifier=self.authority._backend.fence_identity()
                value=dict(organizer_effect_fence=identifier)
                if self.remote_fence is not None:value.update(remote_coordinator_id=self.remote_fence.authority_id,receiver_binding=self.remote_fence.binding)
                return 200,value
            if path=='delegations/leaf-binding' and method=='POST':
                API._fields(body,('machine','executing_agent','session'))
                from .executor_endpoint import ExecutorEndpoint
                endpoint=self.endpoints.get((body['machine'],body['executing_agent'],body['session']))
                if type(endpoint) is not ExecutorEndpoint:raise PermissionError('exact final leaf transport required')
                return 200,endpoint.execution_binding()
            if path=='delegations/fenced-execute' and method=='POST':
                # Authenticated forwarding under an explicitly shared policy
                # store. Preserve the initiating ticket, ID and original expiry;
                # never substitute a freshly reviewed remote attempt.
                API._fields(body,('machine','executing_agent','session','operation','environment','goal','request_id','decision','root_acknowledged','consent_expires_at','delegation_fence','receiving_leaf'))
                # Local human approval is authoritative; no second human review.
                # This shared-host ticket does not provide cross-host approval
                # transfer bound to the remote workspace/owner lease or enforce
                # independent-host final admission/revocation. Root remains an
                # unimplemented required capability, not a product-policy denial.
                if (body['environment']=='root' or body['operation']=='invoke_root') and self.remote_fence is None:
                    raise PermissionError('authenticated local approval transfer and cross-host final-admission protocol unavailable')
                from .organizer_durable import validate_delegated_effect
                unsealed={key:value for key,value in body.items() if key!='delegation_fence'}
                if self.remote_fence is not None:
                    expires=self.remote_fence.validate(body['delegation_fence'],unsealed)['expires']
                else:
                    expires=validate_delegated_effect(self.authority._backend.path,body['delegation_fence'],unsealed)
                if (expires!=body['consent_expires_at'] or body['decision']['initiating_organizer']!=(self.actor.principal if self.remote_fence is None else self.remote_fence.organizer)):
                    raise PermissionError('exact original organizer and consent required')
                preflight=self._binding_preflight(body)
                with self.authority._lock:
                    # Preflight may block. Never dispatch an already-expired
                    # original consent, even though final owner admission also
                    # remains mandatory and independently authoritative.
                    if expires <= time.time():
                        raise PermissionError('original delegated consent expired during binding discovery')
                    from .public_onboarding_api import assert_request_active
                    assert_request_active()
                    _,endpoint,generation=self._decision(body,preflight=preflight)
                    from .executor_endpoint import ExecutorEndpoint
                    if type(endpoint) is not ExecutorEndpoint:raise PermissionError('forwarding requires exact final leaf transport')
                    if preflight[1]['receiving_leaf']!=body['receiving_leaf']:raise PermissionError('original receiving leaf changed')
                    payload={key:body[key] for key in ('machine','executing_agent','session','operation','environment','goal')}
                    confirmed=dict(principal=self.actor.principal,confirmed=True,root_acknowledged=body['root_acknowledged'],forwarded=True)
                    with self.db:
                        self.db.execute("INSERT INTO organizer_requests(id,digest,payload,expires,status,decision,endpoint,consent) VALUES(?,?,?,?,'ambiguous',?,?,?)",
                            (body['request_id'],hashlib.sha256(canonical(body).encode()).hexdigest(),canonical(payload),expires,canonical(body['decision']),generation,canonical(confirmed)))
                        self._retain_query(body)
                try:
                    result=endpoint.execute(body)
                    with self.db:self.db.execute("UPDATE organizer_requests SET status='completed',result=? WHERE id=?",(canonical(result),body['request_id']))
                except Exception:
                    return 503,dict(error='delegation_outcome_uncertain',id=body['request_id'],status='ambiguous',reconcile_required=True)
                return 200,dict(id=body['request_id'],status='completed',result=result,queued=False)
            if path=='delegations' and method=='GET':
                API._fields(body)
                rows=self.db.execute("SELECT id,status,json_extract(record,'$.decision'),result,json_extract(record,'$.payload'),json_extract(record,'$.consent') FROM authority_attempts WHERE namespace='organizer_requests' ORDER BY ordinal DESC LIMIT 100").fetchall()
                from .remote_delegation import RemoteDelegationEndpoint
                items=[]
                for row in rows:
                    plan=json.loads(row[4]);endpoint=self.endpoints.get((plan['machine'],plan['executing_agent'],plan['session']))
                    link=endpoint.links(row[0]) if isinstance(endpoint,RemoteDelegationEndpoint) else None
                    items.append(dict(id=row[0],status=row[1],decision=json.loads(row[2]) if row[2] else None,result=json.loads(row[3]) if row[3] else None,remote=link,consent=json.loads(row[5]) if row[5] else None))
                return 200,dict(items=items)
            if path=='delegations/prepare' and method=='POST':
                API._fields(body,('machine','executing_agent','session','operation','environment','goal'))
                if (not isinstance(body['session'],str) or not body['session'] or len(body['session'])>256 or not isinstance(body['goal'],str) or not body['goal'].strip() or len(body['goal'].encode())>4096 or contains_literal_secret(body['goal'])):raise ValueError('bounded exact reviewed delegation required')
                required={'invoke_root':'root','invoke_host':'host','invoke_sandbox':'sandbox',
                          'create_agent':'metadata','manage_agent':'metadata'}.get(body['operation'])
                if required is None:raise ValueError('supported explicit operation required')
                if body['environment']!=required:raise ValueError('explicit matching execution boundary required')
                decision,endpoint,generation=self._decision(body)
                binding=self.endpoint_incarnations[(body['machine'],body['executing_agent'],body['session'])][2]
                payload=canonical(body);digest=hashlib.sha256(canonical(dict(request=body,executor_connection_id=generation,execution_binding=binding)).encode()).hexdigest();identifier=secrets.token_hex(16);expires=time.time()+300
                with self.db:self.db.execute('INSERT INTO organizer_requests(id,digest,payload,expires,status,endpoint) VALUES(?,?,?,?,?,?)',(identifier,digest,payload,expires,'prepared',generation))
                return 200,dict(consent_id=identifier,sha256=digest,request=body,execution_binding=binding,decision=asdict(decision),executor_connection_id=generation,expires_at=expires,root_acknowledgement_required=required=='root')
            if path=='delegations/commit' and method=='POST':
                API._fields(body,('consent_id','consent_sha256','confirmed','root_acknowledged'));API._confirm(body)
                # Bind exact authority durably, then release the sender lock.
                # Only the owner's final effect guard may serialize the actual
                # effect with revocation; a transport timeout cannot do so.
                # Read-only preflight before the policy guard. Repeat all consent
                # checks inside the transaction after the potentially blocking I/O.
                candidate=self.db.execute('SELECT digest,payload,expires,status FROM organizer_requests WHERE id=?',(body['consent_id'],)).fetchone()
                if not candidate or candidate[0]!=body['consent_sha256'] or candidate[2]<=time.time() or candidate[3]!='prepared':
                    raise ValueError('invalid, expired or attempted delegation')
                preflight=self._binding_preflight(json.loads(candidate[1]))
                with self.authority._lock:
                    self.db.execute('BEGIN IMMEDIATE')
                    try:
                        row=self.db.execute('SELECT digest,payload,expires,status,endpoint FROM organizer_requests WHERE id=?',(body['consent_id'],)).fetchone()
                        if not row or row[0]!=body['consent_sha256'] or row[2]<=time.time() or row[3]!='prepared':raise ValueError('invalid, expired or attempted delegation')
                        plan=json.loads(row[1])
                        if type(body['root_acknowledged']) is not bool or (plan['environment']=='root' and body['root_acknowledged'] is not True):raise ValueError('explicit root risk acknowledgement required')
                        key=(plan['machine'],plan['executing_agent'],plan['session'])
                        previous=self.endpoint_incarnations.get(key)
                        if previous is not None and previous[0] is not self.endpoints.get(key):raise ValueError('executor connection changed; review again')
                        decision,endpoint,generation=self._decision(plan,preflight=preflight)
                        if generation!=row[4]:raise ValueError('executor connection changed; review again')
                        record=json.loads(canonical(asdict(decision)))
                        confirmed=dict(principal=decision.initiating_principal,confirmed=True,root_acknowledged=body['root_acknowledged'])
                        self.db.execute("UPDATE organizer_requests SET status='ambiguous',decision=?,consent=? WHERE id=?",(canonical(record),canonical(confirmed),body['consent_id']));self.db.commit()
                    except BaseException:self.db.rollback();raise
                    try:
                        from .public_onboarding_api import assert_request_active
                        assert_request_active()
                        effect=dict(plan,request_id=body['consent_id'],decision=record,
                                    root_acknowledged=body['root_acknowledged'],consent_expires_at=row[2],
                                    receiving_leaf=self.endpoint_incarnations[(plan['machine'],plan['executing_agent'],plan['session'])][2]['receiving_leaf'])
                        effect['delegation_fence']=self.authority._backend.issue_effect_ticket(effect,row[2],receiver=getattr(endpoint,'receiver_binding',None))
                        # Persist query before any transport can cross the effect
                        # boundary. A crash before this point stays uncertain.
                        with self.db:self._retain_query(effect)
                    except Exception:
                        return 503,dict(error='delegation_outcome_uncertain',id=body['consent_id'],status='ambiguous',reconcile_required=True)
                try:
                    result=endpoint.execute(effect)
                    if (type(result) is not dict or set(result)-{'status','reference'} or not isinstance(result.get('status'),str) or any(not isinstance(v,str) or len(v)>256 or contains_literal_secret(v) for v in result.values())):raise ValueError('endpoint returned unsafe or unbounded result; reconcile attempt')
                    with self.db:self.db.execute("UPDATE organizer_requests SET status='completed',result=? WHERE id=?",(canonical(result),body['consent_id']))
                except Exception:
                    return 503,dict(error='delegation_outcome_uncertain',id=body['consent_id'],status='ambiguous',reconcile_required=True)
                return 200,dict(id=body['consent_id'],status='completed',result=result,queued=False)
        return None
