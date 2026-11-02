"""Closed endpoint admission; real HTTP tests use disposable loopback only."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
import pytest
from arvyx_control.organizer_authority import OrganizerAuthority
from arvyx_control.organizer_delegation import DelegationService
from arvyx_control.replica_authority import authority_context
from test_durable_organizer_journey import seed,body,consent
from delegation_fixture_helpers import capabilities,issue,admitted


def test_unbounded_callback_is_refused_before_consent(tmp_path):
    class Arbitrary:
        def execute(self,plan):raise AssertionError('must never dispatch')
    with authority_context(tmp_path/'vault'):
        policy=OrganizerAuthority(database=tmp_path/'policy.sqlite');actor,_=seed(policy)
        service=DelegationService(tmp_path/'requests.sqlite',policy,actor,{('machine-a','worker','session-exact'):Arbitrary()})
        try:
            with pytest.raises(PermissionError,match='bounded'):
                service.route('delegations/prepare','POST',body())
            assert service.db.execute('SELECT count(*) FROM organizer_requests').fetchone()[0]==0
        finally:service.close();policy.close()


def test_leaf_requires_exact_machine_executor_and_durable_ack(tmp_path):
    from arvyx_control.executor_endpoint import ExecutorEndpoint
    calls=[]
    def call(path,data=None,*,deadline=None):
        calls.append((path,data,deadline))
        if path=='capabilities':return dict(machine='machine-a',agent='worker',session='session-exact',environments=['root'])
        return dict(request_id=data['request_id'],status='completed',reference='fixture-effect')
    with patch('arvyx_control.shared_onboarding_cli.client',return_value=call):
        endpoint=ExecutorEndpoint('http://127.0.0.1:12345','fixture-token',machine='machine-a',agent='worker',session='session-exact',environments=('root',))
    with authority_context(tmp_path/'vault'):
        policy=OrganizerAuthority(database=tmp_path/'policy.sqlite');actor,worker=seed(policy)
        plan=issue(policy,actor,worker,body())
        original=endpoint._call
        def fenced(path,data=None,**kw):
            if path=='capabilities':return capabilities(policy,**original(path,data,**kw))
            with admitted(policy,data):return original(path,data,**kw)
        endpoint._call=fenced
        result=endpoint.execute(plan)
        assert result==dict(status='completed',reference='fixture-effect')
        assert len({c[2] for c in calls})==1 and calls[0][2]>time.monotonic()
        with pytest.raises(PermissionError):endpoint.execute(dict(plan,session='other'))
        with pytest.raises(PermissionError):endpoint.execute({k:v for k,v in plan.items() if k!='delegation_fence'})
        with pytest.raises(PermissionError):endpoint.execute(dict(plan,delegation_fence=dict(plan['delegation_fence'],authority_id='b'*64)))
        def lost(path,data=None,*,deadline=None):
            if path=='capabilities':return capabilities(policy,**call(path,data,deadline=deadline))
            return dict(request_id='different',status='completed',reference='wrong')
        endpoint._call=lost
        with pytest.raises(OSError):endpoint.execute(plan)
        policy.close()


def test_socket_trickle_cannot_hold_policy_revocation(tmp_path):
    from arvyx_control.executor_endpoint import ExecutorEndpoint
    received=threading.Event();policy_holder=[]
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            
            with authority_context(tmp_path/'vault'):data=json.dumps(capabilities(policy_holder[0],machine='machine-a',agent='worker',session='session-exact',environments=['root'])).encode()
            self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def do_POST(self):
            plan=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            with authority_context(tmp_path/'vault'),admitted(policy_holder[0],plan):pass
            received.set()
            self.send_response(200);self.send_header('Content-Length','1000');self.end_headers()
            for _ in range(100):
                try:self.wfile.write(b' ');self.wfile.flush()
                except OSError:break
                time.sleep(.03)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with authority_context(tmp_path/'vault'):
            policy=OrganizerAuthority(database=tmp_path/'policy.sqlite');actor,_=seed(policy);policy_holder.append(policy)
            other=OrganizerAuthority(database=tmp_path/'policy.sqlite');other_actor=other.identity_handle('organizer')
            endpoint=ExecutorEndpoint(f'http://127.0.0.1:{server.server_port}','fixture-token',machine='machine-a',agent='worker',session='session-exact',environments=('root',),timeout=.25)
            service=DelegationService(tmp_path/'requests.sqlite',policy,actor,{('machine-a','worker','session-exact'):endpoint})
            prepared=service.route('delegations/prepare','POST',body())[1];result=[]
            def dispatch():
                with authority_context(tmp_path/'vault'):result.append(service.route('delegations/commit','POST',consent(prepared)))
            worker=threading.Thread(target=dispatch);worker.start();assert received.wait(2)
            start=time.monotonic();other.set_organizer(other_actor,False);elapsed=time.monotonic()-start
            worker.join(2)
            assert not worker.is_alive() and elapsed<1.5
            assert result[0][0]==503
            with pytest.raises(ValueError):service.route('delegations/commit','POST',consent(prepared))
            with pytest.raises(PermissionError):service.route('delegations/prepare','POST',body())
            service.close();other.close();policy.close()
    finally:server.shutdown();server.server_close();thread.join(2)


def test_root_acknowledgement_is_durable_before_executor_effect(tmp_path):
    from arvyx_control.executor_endpoint import ExecutorEndpoint
    with authority_context(tmp_path/'vault'):
        policy=OrganizerAuthority(database=tmp_path/'policy.sqlite');actor,_=seed(policy)
        endpoint=ExecutorEndpoint('http://127.0.0.1:12345','fixture',machine='machine-a',agent='worker',session='session-exact',environments=('root',))
        service=DelegationService(tmp_path/'requests.sqlite',policy,actor,{('machine-a','worker','session-exact'):endpoint})
        def execute(path,data=None,*,deadline=None):
            if path=='capabilities':return capabilities(policy,machine='machine-a',agent='worker',session='session-exact',environments=['root'])
            row=service.db.execute('SELECT status,consent FROM organizer_requests WHERE id=?',(data['request_id'],)).fetchone()
            assert row[0]=='ambiguous'
            assert json.loads(row[1])==dict(principal='organizer',confirmed=True,root_acknowledged=True)
            with admitted(policy,data):pass
            return dict(request_id=data['request_id'],status='completed',reference='fixture-effect')
        endpoint._call=execute
        try:
            review=service.route('delegations/prepare','POST',body())[1]
            assert service.route('delegations/commit','POST',consent(review))[0]==200
        finally:service.close();policy.close()
