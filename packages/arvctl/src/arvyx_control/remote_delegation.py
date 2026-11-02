"""Explicit remote endpoint over the existing loopback/approved-tunnel API.

No SSH process, discovery, pairing-to-execution promotion, token minting or retry.
Both sides independently use their trusted organizer/executor provisioning. A
private durable link records the remote attempt before commit for reconciliation
when acknowledgement is lost. Credentials remain in memory, never in the ledger.
"""
import json,re,threading,time
from .organizer_durable import private_database


class RemoteDelegationEndpoint:
    # Local explicit human approval is authoritative for the remote target.
    # The missing capability is authenticated exact approval transfer plus remote
    # final admission/revocation, not a second remote-human gesture. A forwarding
    # credential or local Boolean alone cannot supply this protocol.
    environments=frozenset(('sandbox','host'))

    def __init__(self,database,origin,credential,*,machine,timeout=2,receiver_binding=None,coordinator_id=None,environments=None):
        from .shared_onboarding_cli import client
        if not isinstance(machine,str) or not machine:raise ValueError('exact expected machine required')
        import math
        if not math.isfinite(timeout) or not 0 < timeout <= 2:raise ValueError('bounded total delegation deadline required')
        self.receiver_binding=None;self.coordinator_id=coordinator_id
        if receiver_binding is not None:
            from .remote_effect_fence import validate_binding
            self.receiver_binding=validate_binding(receiver_binding)
            if not isinstance(coordinator_id,str) or not re.fullmatch("[a-f0-9]{64}",coordinator_id):raise ValueError("explicit trusted coordinator identity required")
            if self.receiver_binding["target"]["machine_id"]!=machine:raise ValueError("receiver target machine mismatch")
            self.environments=frozenset(environments or self.receiver_binding["environments"])
            if not self.environments or self.environments-set(self.receiver_binding["environments"]):raise ValueError("exact independently provisioned receiver modes required")
        elif coordinator_id is not None or environments is not None:raise ValueError("complete trusted remote receiver provisioning required")
        self.timeout=timeout
        self.call=client(origin,credential,timeout=timeout);self.expected_machine=machine
        self.db=private_database(database);self.lock=threading.RLock()
        self.db.execute('PRAGMA busy_timeout=100')
        self.db.execute('''CREATE TABLE IF NOT EXISTS remote_delegation_links (
            local_id TEXT PRIMARY KEY,remote_id TEXT,status TEXT NOT NULL)''');self.db.commit()
        from .authority_attempts import migrate_attempts
        import secrets
        migrate_attempts(self.db,secrets.token_hex(16))

    def close(self):self.db.close()

    def execution_binding(self,request):
        if request['machine']!=self.expected_machine:raise PermissionError('remote exact machine mismatch')
        machine,agent,session=request['machine'],request['executing_agent'],request['session']
        if self.receiver_binding is not None:
            target=self.receiver_binding['target']
            if (machine,agent,session)!=(target['machine_id'],target['agent_id'],self.receiver_binding['session']):raise PermissionError('remote receiver target changed')
        # Shared-authority non-root discovery grants no effect authority. Both
        # paths still require the original sealed ticket and final owner fence.
        leaf=self.call('delegations/leaf-binding',dict(machine=machine,executing_agent=agent,session=session),deadline=time.monotonic()+self.timeout)
        if (leaf.get('machine'),leaf.get('agent'),leaf.get('session'))!=(machine,agent,session):raise PermissionError('remote receiving identity changed')
        identifier=leaf.get('receiving_leaf')
        if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9]{64}',identifier):raise PermissionError('remote receiving leaf unavailable')
        return json.loads(json.dumps(dict(coordinator_id=self.coordinator_id,receiver=self.receiver_binding,machine=machine,agent=agent,session=session,environments=sorted(self.environments),receiving_leaf=identifier)))

    def links(self,identifier):
        with self.lock:
            row=self.db.execute('SELECT remote_id,status FROM remote_delegation_links WHERE local_id=?',(identifier,)).fetchone()
            return dict(remote_id=row[0],status=row[1]) if row else None

    def recover(self,query):
        from .executor_endpoint import validate_result_query,completed_result
        validate_result_query(query)
        deadline=time.monotonic()+self.timeout
        if not self.lock.acquire(timeout=self.timeout):raise TimeoutError('remote recovery admission expired')
        try:
            row=self.db.execute("SELECT json_extract(record,'$.remote_id') FROM authority_attempts WHERE namespace='remote_delegation_links' AND id=?",(query['request_id'],)).fetchone()
            if row is None or row[0]!=query['request_id']:raise PermissionError('exact recorded remote attempt required')
            result=self.call('delegations/result',query,deadline=deadline)
            completed_result(result,query['request_id'])
            with self.db:self.db.execute("UPDATE authority_attempts SET status='completed',record=json_set(record,'$.status','completed') WHERE namespace='remote_delegation_links' AND id=?",(query['request_id'],))
            return dict(status='remote_completed',reference=query['request_id'])
        finally:self.lock.release()

    def execute(self,plan):
        # Preserve the initiating human's exact attestation. Never derive it
        # from environment or replace it with a remote-human approval gate.
        if type(plan.get('root_acknowledged')) is not bool or ((plan['environment']=='root' or plan['operation']=='invoke_root') and plan['root_acknowledged'] is not True):
            raise PermissionError('explicit original root risk acknowledgement required')
        if plan['environment'] not in self.environments or plan['operation']=='invoke_root' and self.receiver_binding is None:
            raise PermissionError('authenticated local approval transfer and cross-host final-admission protocol unavailable')
        deadline=time.monotonic()+self.timeout
        if not self.lock.acquire(timeout=self.timeout):raise TimeoutError('remote endpoint admission expired')
        try:
            def call(path,data=None):
                if time.monotonic()>=deadline:raise TimeoutError('remote delegation deadline expired')
                return self.call(path,data,deadline=deadline)
            identifier=plan['request_id']
            with self.db:
                if self.db.execute('SELECT 1 FROM remote_delegation_links WHERE local_id=?',(identifier,)).fetchone():raise ValueError('remote attempt already recorded; reconcile instead of replay')
                self.db.execute("INSERT INTO remote_delegation_links VALUES(?,NULL,'ambiguous')",(identifier,))
            if call('capabilities').get('owner_host')!=self.expected_machine or plan['machine']!=self.expected_machine:raise PermissionError('remote exact machine mismatch')
            ticket=plan.get('delegation_fence')
            if (type(ticket) is not dict or set(ticket)!={'authority_id','token'}
                    or any(not isinstance(value,str) or not re.fullmatch('[a-f0-9]{64}',value) for value in ticket.values())):
                raise PermissionError('closed authenticated original organizer ticket required')
            advertised=call('delegations/fence')
            if self.receiver_binding is None:
                if advertised.get('organizer_effect_fence')!=ticket['authority_id']:
                    raise PermissionError('independent receiver requires trusted coordinator/receiver binding provisioning')
            elif (ticket['authority_id']!=self.coordinator_id
                    or advertised.get('remote_coordinator_id')!=self.coordinator_id
                    or advertised.get('receiver_binding')!=self.receiver_binding):
                raise PermissionError('exact provisioned remote authority and receiver incarnation required')
            # Original review/attempt/expiry travels unchanged. The final owner
            # independently authenticates and acquires the durable source permit.
            remote_id=identifier
            with self.db:self.db.execute('UPDATE remote_delegation_links SET remote_id=? WHERE local_id=?',(remote_id,identifier))
            # The host capability is checked again immediately before commit.
            if call('capabilities').get('owner_host')!=self.expected_machine:raise PermissionError('remote machine changed before commit')
            # Forward the exact sealed attempt, never synthesize remote consent.
            result=call('delegations/fenced-execute',plan)
            if result.get('id')!=remote_id or result.get('status')!='completed':raise OSError('remote outcome uncertain; reconcile, never retry')
            with self.db:self.db.execute("UPDATE remote_delegation_links SET status='completed' WHERE local_id=?",(identifier,))
            return dict(status='remote_completed',reference=remote_id)
        finally:self.lock.release()
