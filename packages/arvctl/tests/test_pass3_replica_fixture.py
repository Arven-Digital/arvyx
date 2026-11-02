"""Execute the original deletion/hash fixture using a byte-stream HTTP bridge.

This is handler/producer evidence only; the real host socket command remains
mandatory and unchanged. Production transport and assertions are not weakened.
"""
import io
from urllib.parse import urlsplit
from types import SimpleNamespace
from test_local_handler_wire import Wire

def test_original_state_deletion_fixture_parses_bound_transport_query(monkeypatch):
    import test_replication as original
    import arvyx_control.replica as replica
    servers=[]
    class Server:
        def __init__(self,address,handler):
            self.handler=handler;self.server_port=23456;self.server_address=('127.0.0.1',23456);servers.append(self)
        def serve_forever(self):pass
        def shutdown(self):pass
        def server_close(self):pass
    class Response(io.BytesIO):
        status=200
    def transport(request,**kwargs):
        parts=urlsplit(request.full_url);route=parts.path+('?' + parts.query if parts.query else '')
        wire=Wire(('GET '+route+' HTTP/1.0\r\nHost: 127.0.0.1:23456\r\n\r\n').encode())
        servers[-1].handler(wire,('127.0.0.1',1),servers[-1])
        header,payload=bytes(wire.output).split(b'\r\n\r\n',1)
        assert header.split()[1]==b'200'
        return Response(payload)
    monkeypatch.setattr(original,'ThreadingHTTPServer',Server)
    monkeypatch.setattr(replica,'urlopen',transport)
    original.ReplicationTests('test_state_file_deletions_are_propagated').test_state_file_deletions_are_propagated()
