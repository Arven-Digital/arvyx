"""Review regressions, synthetic material only; no live enrollment."""
import dataclasses
import http.client
import json
import socket
import sqlite3
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import test_secret_delivery as fixture
from arvyx_control.secret_delivery_protocol import MAX_BODY, Receipts, Rejected


class ReviewRegressions(fixture.SecretDeliveryE2E):
    def test_browser_style_unicode_boundary(self):
        for value in ('雪' * 20000, '雪' * 21845 + 'a'):
            prepared = self.prepare()
            payload = dict(target=self.target.id, key='anthtropic_auth', value=value,
                           delivery_id=__import__('secrets').token_hex(16),
                           confirmation=prepared['confirmation'], overwrite=prepared['exists'])
            raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            status, result, _ = self.request('send', payload, raw=raw)
            self.assertEqual(status, 200)
            self.assertEqual(result['receipt']['status'], 'saved')
            self.assertIn(value.encode(), (self.destdir/'.env').read_bytes())

    def test_stalled_tls_handshake_does_not_block_legitimate_request(self):
        stalled = socket.create_connection(('127.0.0.1', self.servers[0][0].server_port))
        try:
            time.sleep(.1)
            start = time.monotonic()
            self.prepare()
            self.assertLess(time.monotonic() - start, 2)
        finally:
            stalled.close()

    def test_dashboard_anti_frame(self):
        c = http.client.HTTPSConnection('localhost', self.ingress.server_port, context=self.context('operator'))
        c.request('GET', '/dashboard', headers={'Authorization': 'Bearer '+self.bearer})
        r = c.getresponse(); r.read()
        self.assertIn("frame-ancestors 'none'", r.getheader('Content-Security-Policy', ''))
        self.assertEqual(r.getheader('X-Frame-Options'), 'DENY')
        c.close()

    def test_receipt_actor_scope_and_legacy_quarantine(self):
        store = Receipts(self.root/'actors.sqlite')
        store.reserve('same-id', 'target', 'KEY', 'human-a')
        self.assertEqual(store.get('same-id', 'human-a')['actor'], 'human-a')
        for actor in ('human-b', 'operator'):
            with self.assertRaises(Rejected): store.get('same-id', actor)
            with self.assertRaises(Rejected): store.reserve('same-id', 'target', 'KEY', actor)
        path = self.root/'legacy.sqlite'
        db = sqlite3.connect(path)
        db.execute('CREATE TABLE receipts (id TEXT PRIMARY KEY, target TEXT, key TEXT, status TEXT, actor TEXT, created INTEGER)')
        db.execute("INSERT INTO receipts VALUES ('legacy','target','KEY','saved','operator',1)")
        db.commit(); db.close(); path.chmod(0o600)
        migrated = Receipts(path)
        with self.assertRaises(Rejected): migrated.get('legacy', 'operator')

    def test_response_size_and_field_allowlist(self):
        from http.server import BaseHTTPRequestHandler
        from arvyx_control import secret_delivery_protocol as protocol
        valid = b'{"exists":false,"version":"x"}'
        cases = (
            ('at-limit', 'prepare', valid + b' ' * (MAX_BODY - len(valid)), False),
            ('over-limit', 'prepare', valid + b' ' * (MAX_BODY + 1 - len(valid)), True),
            ('prepare-extra-field', 'prepare', b'{"exists":false,"version":"x","value":"must-not-return"}', True),
            ('send-extra-field', 'send', b'{"status":"saved","value":"must-not-return"}', True),
        )
        for name, action, response, rejected in cases:
            class BadResponse(BaseHTTPRequestHandler):
                def log_message(self, *args): pass
                def do_POST(self):
                    # Drain the request before closing TLS: otherwise unread input
                    # can reset the connection and truncate the response on the wire.
                    self.rfile.read(int(self.headers['Content-Length']))
                    self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
                    self.wfile.write(response)
            server = self.start(BadResponse)
            target = dataclasses.replace(self.target, url=f'https://localhost:{server.server_port}/v1/deliver')
            reads = []
            original_read = http.client.HTTPResponse.read

            def observe_read(http_response, amount=None):
                data = original_read(http_response, amount)
                reads.append((amount, len(data)))
                return data

            payload = dict(action=action, target=target.id, agent=target.agent,
                           runtime=target.runtime, key='OTHER', actor='human-a')
            with self.subTest(case=name), patch.object(http.client.HTTPResponse, 'read', observe_read), patch.object(
                    protocol, 'validate_response', wraps=protocol.validate_response) as validate:
                if rejected:
                    with self.assertRaises(Rejected):
                        target.exchange(payload)
                else:
                    self.assertEqual(target.exchange(payload), {'exists': False, 'version': 'x'})
                # A transport failure must not masquerade as a validator rejection.
                expected_reads = [(MAX_BODY + 1, len(response))]
                if name != 'over-limit':
                    # Close-delimited responses require a bounded EOF proof.
                    expected_reads.append((1, 0))
                self.assertEqual(reads, expected_reads)
                if name == 'over-limit':
                    validate.assert_not_called()
                else:
                    validate.assert_called_once_with(action, json.loads(response))


def load_tests(loader, tests, pattern):
    # Inherit fixture helpers, not duplicate the base suite's test receipts.
    return unittest.TestSuite(ReviewRegressions(name) for name in ReviewRegressions.__dict__ if name.startswith('test_'))


if __name__ == '__main__': unittest.main()
