"""Worker handshake recorder and opt-in parent-host disposable TLS transport."""
import os, ssl, threading, time
from types import SimpleNamespace
from unittest.mock import patch
import pytest


def test_coordinator_handshake_is_deferred_until_bounded_worker_deadline():
    from arvyx_control.remote_effect_fence import make_server
    from arvyx_control.public_onboarding_api import BoundedOnboardingServer
    closed=threading.Event();calls=[]
    class Socket:
        def shutdown(self,*args):closed.set()
        def do_handshake(self):
            calls.append('handshake')
            assert closed.wait(.5), 'absolute worker deadline must terminate an idle handshake'
            raise TimeoutError('synthetic idle TLS')
    sock=Socket()
    def initialize(server,*args,**kwargs):
        server.socket=sock;server._workers=threading.BoundedSemaphore(1);server._workers.acquire()
    context=SimpleNamespace(load_cert_chain=lambda *a:None,wrap_socket=lambda request,**kw:calls.append(('wrap',kw)) or request)
    with patch.object(BoundedOnboardingServer,'__init__',initialize),patch('ssl.SSLContext',return_value=context):
        server=make_server(SimpleNamespace(),origin='https://coordinator.invalid',certificate='synthetic.crt',private_key='synthetic.key')
    assert calls==[('wrap',dict(server_side=True,do_handshake_on_connect=False))]
    server.request_lifetime_seconds=.03;server.shutdown_request=lambda request:closed.set();server.handle_error=lambda *a:None
    server.process_request_thread(sock,('synthetic',1))
    assert closed.is_set() and calls[-1]=='handshake'
    assert server._workers.acquire(blocking=False)


@pytest.mark.skipif(os.environ.get('AMC_FIX5_PARENT_TLS')!='1',reason='parent-host actual TLS only; no sandbox socket claim')
def test_parent_tls_idle_client_does_not_block_authenticated_peer(tmp_path):
    import http.client, socket, subprocess, json
    from arvyx_control.remote_effect_fence import make_server
    # Ephemeral synthetic certificate only. No real identity/provider credential.
    key=tmp_path/'synthetic.key';certificate=tmp_path/'synthetic.crt'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(certificate)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
    key.chmod(0o600)
    # Exercise real HMAC service authentication over verified TLS, no effect API.
    from arvyx_control.organizer_authority import OrganizerAuthority
    from arvyx_control.remote_effect_fence import RemoteFenceService,PROTOCOL,_mac
    import secrets
    from arvyx_control.replica_authority import authority_context
    vault=tmp_path/'vault';vault.mkdir();state=tmp_path/'events'
    with authority_context(vault,state):authority=OrganizerAuthority(database=tmp_path/'authority.db')
    binding=dict(receiver_id='synthetic-receiver',incarnation='a'*32,epoch=1,
        target=dict(machine_id='synthetic-machine',agent_id='synthetic-agent',workspace_id='synthetic-workspace',connection_id='synthetic-connection'),
        session='synthetic-session',workspace_identity=[1,1],environments=['host'],policy_id='b'*64)
    peer_key=secrets.token_hex(32)
    with authority_context(vault,state):service=RemoteFenceService(authority,{'synthetic-receiver':dict(key=peer_key,binding=binding,organizer='synthetic-organizer')})
    original=service.handle
    def handle(envelope):
        with authority_context(vault,state):return original(envelope)
    service.handle=handle
    server=make_server(service,origin='https://127.0.0.1:0',certificate=certificate,private_key=key)
    server.request_lifetime_seconds=.2
    thread=threading.Thread(target=server.serve_forever,kwargs=dict(poll_interval=.02),daemon=True);thread.start()
    idle=socket.create_connection(server.server_address,timeout=1)
    try:
        context=ssl.create_default_context(cafile=str(certificate))
        connection=http.client.HTTPSConnection('localhost',server.server_port,context=context,timeout=1)
        try:
            connection.request('POST','/api/authority-fence',json.dumps({'wrong':'auth'}),{'Content-Type':'application/json'})
            response=connection.getresponse();assert response.status in (400,401,403)
            assert json.loads(response.read())
        finally:connection.close()
        message=dict(protocol=PROTOCOL,authority_id=service.authority_id,receiver_id='synthetic-receiver',nonce=secrets.token_hex(16),operation='status',payload=dict(permit_id='c'*32,sha256='d'*64))
        connection=http.client.HTTPSConnection('localhost',server.server_port,context=context,timeout=1)
        try:
            connection.request('POST','/api/authority-fence',json.dumps(dict(message=message,mac=_mac(peer_key,message))),{'Content-Type':'application/json'})
            response=connection.getresponse();assert response.status==200
            result=json.loads(response.read());assert result['mac']==_mac(peer_key,result['message'])
            assert result['message']['payload']['status']=='not-observed-uncertain'
        finally:connection.close()
        time.sleep(.3);idle.settimeout(.5);assert idle.recv(1)==b''
    finally:
        idle.close();server.shutdown();server.server_close();thread.join(2);authority.close()
