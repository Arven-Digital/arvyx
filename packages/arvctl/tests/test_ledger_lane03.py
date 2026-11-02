"""Lane03 regression source; NOT EXECUTED under remediation contract."""
import json
import unittest
from unittest import mock
from arvyx_control import api
from arvyx_control.mcp_client_evidence import _external_client_provenance
from safe_mcp_bridge import cli as bridge


class Lane03Tests(unittest.TestCase):
    def test_completed_mcp_is_raw_json_not_rest_and_notification_is_silent(self):
        response = api._completed_mutation_response('/mcp', {'id': 'current'},
                                                    'operation_completed_no_replay', 'operation')
        self.assertIsInstance(response.body, str)
        body = json.loads(response.body)
        self.assertEqual(body['jsonrpc'], '2.0')
        self.assertEqual(body['id'], 'current')
        self.assertEqual(body['error']['data']['operation_id'], 'operation')
        self.assertNotIn('body', body)
        notification = api._completed_mutation_response('/mcp', {}, 'operation_completed_no_replay', 'operation')
        self.assertEqual((notification.status, notification.body), (202, ''))

    def test_invalid_bridge_envelopes_never_forward_or_disappear(self):
        config = {'policy': {'allow_tools': []}}
        invalid = [({'method': 'ping'}, None),
                   ({'jsonrpc': '1.0', 'method': 'ping'}, None),
                   ({'jsonrpc': '2.0', 'method': 'ping', 'params': []}, None),
                   ({'jsonrpc': '2.0', 'method': 'ping', 'id': True}, None),
                   ({'jsonrpc': '2.0', 'method': 'ping', 'id': {}}, None),
                   ({'jsonrpc': '2.0', 'method': 'ping', 'id': float('inf')}, None),
                   ({'jsonrpc': '1.0', 'method': 'ping', 'id': 'valid'}, 'valid')]
        with mock.patch.object(bridge, '_post_json') as post:
            for payload, expected_id in invalid:
                with self.subTest(payload=payload):
                    response = bridge._handle_line(config, json.dumps(payload))
                    self.assertEqual(response['error']['code'], -32600)
                    self.assertEqual(response['id'], expected_id)
            post.assert_not_called()
        with mock.patch.object(bridge, '_post_json', return_value={}) as post:
            self.assertIsNone(bridge._handle_line(config, '{"jsonrpc":"2.0","method":"ping"}'))
            post.assert_called_once()

    def test_labels_never_promote_self_or_legacy_evidence(self):
        for name in ('python-mcp-sdk', 'Claude Desktop', 'anything'):
            for provenance in (None, {'kind': 'product-self-client'}):
                payload = {'client': name}
                if provenance is not None:
                    payload['client_provenance'] = provenance
                self.assertFalse(_external_client_provenance(payload))

    def test_measured_provenance_is_closed_and_capture_bound(self):
        payload = {'client': 'display only', 'client_version': 'synthetic-unit',
                   'capture_sha256': 'a' * 64, 'capture_bytes': 1,
                   'scan_scope': ['initialize', 'tools/list', 'memory.recall'],
                   'client_provenance': {'kind': 'third-party-sdk', 'distribution': 'mcp',
                       'version': 'synthetic-unit', 'implementation_sha256': 'b' * 64}}
        self.assertTrue(_external_client_provenance(payload))
        payload['client_provenance']['unknown'] = 'forbidden'
        self.assertFalse(_external_client_provenance(payload))
