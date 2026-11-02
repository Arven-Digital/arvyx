"""Candidate-21 findings 1 and 3: synthetic captured-wire regressions."""
import http.client
import io
import json
from urllib.request import Request

import pytest
from arvyx_control import http_bounds
from safe_mcp_bridge import http_bounds as bridge_bounds
from safe_mcp_bridge import cli as bridge


class WireSocket:
    def __init__(self, wire):
        self.wire = wire
    def makefile(self, *args, **kwargs):
        return io.BytesIO(self.wire)


def captured_connection(monkeypatch, wire):
    responses = []
    class Connection:
        sock = None
        def __init__(self, *args, **kwargs): pass
        def connect(self): pass
        def request(self, *args, **kwargs): pass
        def getresponse(self):
            response = http.client.HTTPResponse(WireSocket(wire))
            response.begin()
            responses.append(response)
            return response
        def close(self): pass
    monkeypatch.setattr(http.client, 'HTTPConnection', Connection)
    return responses


@pytest.mark.parametrize('module', [http_bounds, bridge_bounds])
@pytest.mark.parametrize('headers', [
    b'Content-Length: 2\r\nContent-Length: 50',
    b'Content-Length: 2, 2',
    b'Content-Length: invalid', b'Content-Length: -2', b'Content-Length: +2',
    b'Content-Length: 2\r\nTransfer-Encoding: chunked',
    b'Transfer-Encoding: gzip', b'Transfer-Encoding: gzip, chunked',
    b'Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked',
])
@pytest.mark.parametrize('status', [200, 400])
def test_reject_invalid_framing_before_yield(monkeypatch, module, headers, status):
    responses = captured_connection(monkeypatch, b'HTTP/1.1 ' + str(status).encode() + b' Test\r\n' + headers + b'\r\n\r\n{}')
    with pytest.raises(ValueError, match='framing'):
        with module.BoundedOpener().open(Request('http://example.invalid/')):
            pytest.fail('invalid response yielded')
    assert responses[0].isclosed()


@pytest.mark.parametrize('module', [http_bounds, bridge_bounds])
@pytest.mark.parametrize('headers, body', [
    (b'Content-Length: 2', b'{}'),
    (b'Content-Length: 2\r\nContent-Length: 2', b'{}'),
    (b'Transfer-Encoding: chunked', b'2\r\n{}\r\n0\r\n\r\n'),
    (b'Connection: close', b'{}'),
])
def test_valid_framing(monkeypatch, module, headers, body):
    captured_connection(monkeypatch, b'HTTP/1.1 200 OK\r\n' + headers + b'\r\n\r\n' + body)
    with module.BoundedOpener().open(Request('http://example.invalid/')) as response:
        assert response.read() == b'{}'


@pytest.mark.parametrize('prefix', ['', 'Bearer'])
def test_doctor_redacts_configured_credential(monkeypatch, tmp_path, capsys, prefix):
    credential = 'opaque-synthetic-sol22-value'
    monkeypatch.setenv('SOL22_TEST_AUTH', credential)
    config = {'target': {'url': 'http://example.invalid/'},
              'auth': {'env': 'SOL22_TEST_AUTH', 'header': 'X-Custom-Auth', 'prefix': prefix},
              'policy': {'allow_tools': []}, 'redaction': {'fail_on_secret_output': True}}
    path = tmp_path / 'bridge.json'
    path.write_text(json.dumps(config))
    body = ('echo ' + credential + ' shape ghp_' + 'a' * 36).encode()
    captured_connection(monkeypatch, b'HTTP/1.1 403 Denied\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
    assert bridge.main(['doctor', str(path), '--json']) == 1
    output = capsys.readouterr()
    assert credential not in output.err
    assert 'ghp_' not in output.err
    assert 'upstream HTTP 403' in output.err
