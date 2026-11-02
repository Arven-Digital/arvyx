"""Actual MCP provider inspection against synthetic loopback wire responses."""
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
import uuid
from unittest import mock

from arvyx_control.brokers import InspectionGuard
from arvyx_control.mcp import handle_request
from arvyx_control.vault import init_vault

BODY = b'{"status":"ok","version":"1.2.3"}'


class ProviderFramingTests(unittest.TestCase):
    def inspect(self, wire, *, healthy):
        with tempfile.TemporaryDirectory() as tmp, socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(3)
            errors = []

            def serve():
                try:
                    with listener.accept()[0] as conn:
                        conn.settimeout(3)
                        conn.recv(4096)
                        conn.sendall(wire)
                except Exception as exc:
                    errors.append(type(exc).__name__)

            thread = threading.Thread(target=serve)
            thread.start()
            vault = Path(tmp) / 'vault'
            init_vault(vault)
            config = {'probe': {'provider': 'http-broker', 'health_url':
                      f'http://127.0.0.1:{listener.getsockname()[1]}/health'}}
            guard = InspectionGuard(circuit_failure_threshold=1)
            try:
                with mock.patch('arvyx_control.brokers.load_broker_config', return_value=config):
                    result = handle_request(
                        {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                         'params': {'name': 'secret.providers', 'arguments': {
                             # Every MCP inspection call requires a fresh durable
                             # admission key (docs/rowan-v2-secret-provider.md).
                             'idempotency_key': f'framing-{uuid.uuid4().hex}'}}},
                        vault=vault, state=Path(tmp) / 'control-events.jsonl',
                        allowed_tools={'secret.providers'},
                        actor='probe', inspection_guard=guard)
            finally:
                thread.join(4)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertNotIn('error', result)
            encoded = json.dumps(result)
            if healthy:
                self.assertIn('"status": "ok"', encoded)
                self.assertIn('"version": "1.2.3"', encoded)
            else:
                self.assertIn('"status": "unavailable"', encoded)
                self.assertNotIn('1.2.3', encoded)
                self.assertFalse(guard.circuit_allows('probe:http-broker'))

    def test_malformed_framing_fails_closed(self):
        cases = {
            'truncated': f'Content-Length: {len(BODY) + 5}\r\n'.encode(),
            'short-declared': b'Content-Length: 1\r\n',
            'conflicting': f'Content-Length: {len(BODY)}\r\nContent-Length: 1\r\n'.encode(),
            'invalid-transfer': b'Transfer-Encoding: nonsense\r\n',
            'mixed': f'Transfer-Encoding: chunked\r\nContent-Length: {len(BODY)}\r\n'.encode(),
            'invalid-length': b'Content-Length: +33\r\n',
        }
        for name, headers in cases.items():
            with self.subTest(case=name):
                self.inspect(b'HTTP/1.1 200 OK\r\n' + headers + b'\r\n' + BODY, healthy=False)

    def test_valid_framing_remains_healthy(self):
        for headers in (b'', f'Content-Length: {len(BODY)}\r\n'.encode(),
                        f'Content-Length: {len(BODY)}\r\nContent-Length: {len(BODY)}\r\n'.encode()):
            with self.subTest(headers=headers):
                self.inspect(b'HTTP/1.0 200 OK\r\n' + headers + b'\r\n' + BODY, healthy=True)

    def test_chunked_complete_and_truncated(self):
        prefix = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
        chunk = f'{len(BODY):x}\r\n'.encode() + BODY + b'\r\n'
        self.inspect(prefix + chunk + b'0\r\n\r\n', healthy=True)
        self.inspect(prefix + chunk, healthy=False)


if __name__ == '__main__':
    unittest.main()
