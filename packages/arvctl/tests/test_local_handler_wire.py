"""Actual HTTP handlers over byte streams; no listener/network proof is claimed."""
import io
import json
from types import SimpleNamespace
from test_consolidated_election import binding
from arvyx_control.cockpit_local import LocalHandler
from arvyx_control.public_onboarding_api import handler_for

class Wire:
    def __init__(self,raw): self.raw=io.BytesIO(raw);self.output=bytearray()
    def makefile(self,*args,**kwargs): return self.raw
    def sendall(self,data): self.output.extend(data)


def request(handler,server,path,body=None,*,auth=True,origin=True,raw=None):
    payload=json.dumps(body).encode() if raw is None and body is not None else raw or b''
    headers=[('Host','127.0.0.1:12345')]
    if auth: headers.append(('Authorization','Bearer browser-test'))
    if body is not None or raw is not None:
        headers.extend([('Content-Type','application/json'),('Content-Length',str(len(payload)))])
        if origin: headers.append(('Origin',server.origin))
    method='POST' if body is not None or raw is not None else 'GET'
    wire=Wire((f'{method} {path} HTTP/1.0\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers)+'\r\n').encode()+payload)
    handler(wire,('127.0.0.1',1),server)
    head,result=bytes(wire.output).split(b'\r\n\r\n',1)
    return int(head.split()[1]),json.loads(result)


def test_actual_local_binding_handler_disconnect_before_first_primary_read(binding):
    bindings,sessions,registry,primary=binding
    primary.source=bindings.connected
    server=SimpleNamespace(bindings=bindings,primary=primary,origin='http://127.0.0.1:12345',capability='browser-test')
    body=dict(sessions[0],agent_id='alpha',revision=0)
    assert request(LocalHandler,server,'/api/local-bindings',body,origin=False)[0]==403
    assert request(LocalHandler,server,'/api/local-bindings',body)[0]==200
    sessions.clear()
    status,state=request(LocalHandler,server,'/api/primary-agent')
    assert status==200 and state['primary_agent_id']=='alpha' and state['primary_connected'] is False
    primary.source=lambda:['beta']
    assert request(LocalHandler,server,'/api/primary-agent')[1]['primary_agent_id']=='alpha'


def test_public_handler_returns_400_for_nonobject_route_and_duplicate_json(tmp_path):
    from arvyx_control.public_onboarding_api import fixture_composition
    api,token,adapter=fixture_composition(tmp_path)
    try:
        # Handler must authenticate the exact token. No live endpoint is involved.
        import hashlib
        api.credentials={hashlib.sha256(b'browser-test').hexdigest():'fixture-owner'}
        server=SimpleNamespace(server_address=('127.0.0.1',12345),server_port=12345,origin='http://127.0.0.1:12345')
        handler=handler_for(api)
        assert request(handler,server,'/api/public-onboarding/sessions/select',dict(route='x',confirmed=True))[0]==400
        assert request(handler,server,'/api/public-onboarding/discover',{},origin=False)[0]==403
        assert request(handler,server,'/api/public-onboarding/discover',raw=b'{"x":1,"x":2}')[0]==400
    finally: api.close()
