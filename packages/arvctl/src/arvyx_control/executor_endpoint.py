"""Closed transport to an independently provisioned exact harness executor.

No arbitrary callbacks run under the organizer policy guard. The leaf executor
must authenticate this connection, durably fence request_id before effects, check
its own local authority and return completion only for that exact attempt. AMC
never supplies a shell command, credential, privilege escalation or fallback.
Unconfigured endpoints remain unavailable. A timeout is an uncertain effect,
never permission to replay. Transport endpoints are trusted composition only.
"""
import hashlib,json,math,re
import time
from .security import contains_literal_secret


def result_query(plan):
    """Exact retained-attempt lookup; never persist the bearer effect ticket."""
    ticket=plan['delegation_fence']
    witness=dict(plan,delegation_fence=dict(authority_id=ticket['authority_id'],
                 token_sha256=hashlib.sha256(ticket['token'].encode()).hexdigest()))
    return dict(request_id=plan['request_id'],receiving_leaf=plan['receiving_leaf'],
                witness_sha256=hashlib.sha256(json.dumps(witness,sort_keys=True,separators=(',',':')).encode()).hexdigest())


def validate_result_query(query):
    if (type(query) is not dict or set(query)!={'request_id','receiving_leaf','witness_sha256'}
            or any(not isinstance(query[key],str) or not re.fullmatch(pattern,query[key])
                   for key,pattern in (('request_id','[a-f0-9]{32}'),('receiving_leaf','[a-f0-9]{64}'),('witness_sha256','[a-f0-9]{64}')))):
        raise ValueError('exact retained result query required')


def completed_result(result,identifier):
    if (type(result) is not dict or set(result)!={'request_id','status','reference'}
            or result.get('request_id')!=identifier or result.get('status')!='completed'
            or not isinstance(result.get('reference'),str) or not result['reference']
            or len(result['reference'])>256 or contains_literal_secret(result['reference'])):
        raise OSError('executor completion uncertain; reconcile exact attempt')
    return dict(status='completed',reference=result['reference'])


class ExecutorEndpoint:
    def __init__(self, origin, credential, *, machine, agent, session,
                 environments, timeout=2):
        from .shared_onboarding_cli import client
        if any(not isinstance(v,str) or not v.strip() or len(v)>256
               for v in ((machine,session) if agent is None else (machine,agent,session))):
            raise ValueError('exact executor identity required')
        if (not environments or set(environments)-{'metadata','sandbox','host','root'}
                or (agent is None and set(environments)!={'metadata'})
                or not math.isfinite(timeout) or not 0 < timeout <= 2):
            raise ValueError('explicit modes and bounded deadline required')
        self.machine,self.agent,self.session=machine,agent,session
        self.environments=frozenset(environments);self.timeout=timeout
        self._call=client(origin,credential,timeout=timeout)

    def execution_binding(self):
        caps=self._call('capabilities',deadline=time.monotonic()+self.timeout)
        if (caps.get('machine'),caps.get('agent'),caps.get('session'))!=(self.machine,self.agent,self.session):
            raise PermissionError('executor identity changed')
        leaf=caps.get('receiving_leaf')
        if not isinstance(leaf,str) or not re.fullmatch('[a-f0-9]{64}',leaf):
            raise PermissionError('receiving leaf incarnation unavailable')
        if not self.environments<=set(caps.get('environments',[])):
            raise PermissionError('executor modes unavailable')
        return dict(machine=self.machine,agent=self.agent,session=self.session,environments=sorted(self.environments),receiving_leaf=leaf)

    def execute(self, plan):
        if (plan['machine'],plan['executing_agent'],plan['session']) != (self.machine,self.agent,self.session):
            raise PermissionError('exact executor mismatch')
        if plan['environment'] not in self.environments:
            raise PermissionError('executor environment unavailable')
        if plan['environment']=='root' and plan.get('root_acknowledged') is not True:
            raise PermissionError('explicit root acknowledgement required')
        deadline=time.monotonic()+self.timeout
        caps=self._call('capabilities',deadline=deadline)
        if (caps.get('machine'),caps.get('agent'),caps.get('session')) != (self.machine,self.agent,self.session):
            raise PermissionError('executor identity changed')
        if plan['environment'] not in caps.get('environments',[]):
            raise PermissionError('executor mode no longer available')
        if (not isinstance(plan.get('receiving_leaf'),str)
                or not re.fullmatch('[a-f0-9]{64}',plan['receiving_leaf'])
                or caps.get('receiving_leaf')!=plan['receiving_leaf']):
            raise PermissionError('reviewed receiving leaf changed')
        ticket=plan.get('delegation_fence')
        if (type(ticket) is not dict or set(ticket)!={'authority_id','token'}
                or any(not isinstance(value,str) or not re.fullmatch('[a-f0-9]{64}',value) for value in ticket.values())
                or ticket['authority_id'] not in ([caps.get('organizer_effect_fence')]+caps.get('organizer_effect_fences',[]))):
            raise PermissionError('exact shared organizer effect fence unavailable')
        result=self._call('executor/execute',plan,deadline=deadline)
        return completed_result(result,plan['request_id'])

    def recover(self,query):
        validate_result_query(query)
        # A result read cannot issue/consume a ticket or execute an effect. The
        # authenticated leaf checks its exact incarnation and retained witness.
        result=self._call('executor/result',query,deadline=time.monotonic()+self.timeout)
        return completed_result(result,query['request_id'])
