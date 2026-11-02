"""Synthetic durable authority recorders; no native/provider/fork execution."""
from contextlib import contextmanager
from dataclasses import asdict
import time
from arvyx_control.organizer_durable import authority_fence_identity,delegated_effect_guard


def capabilities(policy,**fields):
    fields.setdefault('receiving_leaf','a'*64)
    return dict(fields,organizer_effect_fence=authority_fence_identity(policy._backend.path))


def issue(policy,actor,worker,request,*,attempt='a'*32,expires=None,receiving_leaf='a'*64):
    with policy._lock:
        decision=policy.authorize(actor,operation=request['operation'],machine=request['machine'],executing_agent=worker)
        effect=dict(request,request_id=attempt,decision=asdict(decision),root_acknowledged=request['environment']=='root',consent_expires_at=expires or time.time()+60,receiving_leaf=receiving_leaf)
        effect['delegation_fence']=policy._backend.issue_effect_ticket(effect,effect['consent_expires_at'])
    return effect


@contextmanager
def admitted(policy,plan):
    with delegated_effect_guard(policy._backend.path,plan['delegation_fence'],attempt=plan['request_id'],machine=plan['machine'],agent=plan['executing_agent'],environment=plan['environment'],root_acknowledged=plan['root_acknowledged']) as check:
        check();yield
