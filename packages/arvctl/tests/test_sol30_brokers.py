"""Regression evidence."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from arvyx_control.api import handle_api_request
from arvyx_control.auth import issue_token
from arvyx_control.brokers import BrokerError, find_secret_refs, parse_ref
from arvyx_control.mcp import handle_json_line
from arvyx_control.vault import init_vault


def credential():
    return ''.join(('gh', 'p', '_', 'z' * 24))


class BrokerBoundaryTests(unittest.TestCase):
    def test_broker_and_path_reject_canonical_material(self):
        for uri in (f'secret://{credential()}/DB', f'secret://env/{credential()}'):
            with self.subTest(location=uri.split('/')[2][:2]):
                with self.assertRaises(BrokerError):
                    parse_ref(uri)
                self.assertEqual(find_secret_refs(uri), [])
        self.assertEqual(parse_ref('secret://env/DB').uri, 'secret://env/DB')

    def test_actual_rest_and_mcp_dispatch_sanitize_durable_events(self):
        for surface in ('rest', 'http-mcp', 'stdio'):
            for location in ('broker', 'path'):
                with self.subTest(surface=surface, location=location), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    vault = root / 'vault'
                    init_vault(vault)
                    audit = root / 'audit.jsonl'
                    ref = f'secret://{credential()}/DB' if location == 'broker' else f'secret://env/{credential()}'
                    args = {'ref': ref, 'idempotency_key': 'sol30-resolution-0001'}
                    request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'secret.resolve', 'arguments': args}}
                    if surface == 'stdio':
                        response = handle_json_line(json.dumps(request), vault=vault, allowed_tools={'secret.resolve'}, secret_audit_log=audit, require_secret_audit=True)
                        self.assertIn('error', json.loads(response))
                    else:
                        auth = issue_token(vault, 'demobot', scopes=['secret.resolve']).token
                        response = handle_api_request('POST', '/secret/resolve' if surface == 'rest' else '/mcp', args if surface == 'rest' else request, vault=vault, state=root / 'events.jsonl', audit_log=audit, authorization=f'Bearer {auth}', mcp_profile='operator', idempotency_key='sol30-resolution-0001')
                        self.assertTrue(response.status == 400 or 'error' in response.body)
                    text = audit.read_text()
                    # Avoid unittest printing credential-shaped failure payloads.
                    self.assertFalse(credential() in text, 'credential persisted in audit')
                    events = [json.loads(line) for line in text.splitlines()]
                    relevant = [e for e in events if 'secret_ref' in e]
                    self.assertTrue(relevant)
                    self.assertEqual({e.get('phase') for e in relevant}, {'intent', 'outcome'})
                    self.assertTrue(all(e['secret_ref'].startswith('invalid-') for e in relevant))

    def test_operator_cli_bounded_pointer_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / 'vault'
            init_vault(vault)
            request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'secret.pointer_check', 'arguments': {'ref': 'secret://env/' + 'a.b.' * 8000}}}
            cmd = [sys.executable, '-m', 'arvyx_control.cli', 'mcp', '--vault', str(vault), '--profile', 'operator']
            try:
                result = subprocess.run(cmd, input=json.dumps(request) + '\n', text=True, capture_output=True, timeout=1, env=os.environ.copy())
            except subprocess.TimeoutExpired:
                self.fail('operator pointer_check exceeded one-second process deadline')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"id": 1', result.stdout)


if __name__ == '__main__':
    unittest.main()
