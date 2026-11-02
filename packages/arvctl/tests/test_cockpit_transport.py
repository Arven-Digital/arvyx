"""Endpoint identity and offline-draft boundaries."""
import unittest
from unittest.mock import patch
from pathlib import Path


class TransportTests(unittest.TestCase):
    def test_endpoint_pins_host_and_authority_before_mutation(self):
        from arvyx_control.cockpit_transport import Endpoint
        endpoint = Endpoint(Path('/unused'), host='rowan', state='/authority/events.jsonl')
        with patch('arvyx_control.cockpit_transport.request', return_value={'host': 'uma', 'state': '/authority/events.jsonl'}) as rpc:
            with self.assertRaisesRegex(ValueError, 'identity'):
                endpoint.call('end', sid='same-name', actor='operator')
            self.assertEqual(rpc.call_count, 1)
        with patch('arvyx_control.cockpit_transport.request', side_effect=[{'host': 'rowan', 'state': '/authority/events.jsonl'}, {'status': 'ended'}]) as rpc:
            self.assertEqual(endpoint.call('end', sid='stable-id', actor='operator')['status'], 'ended')
            self.assertEqual(rpc.call_args.kwargs['sid'], 'stable-id')

    def test_ssh_forwarding_uses_existing_trust_and_no_remote_commands(self):
        from arvyx_control.cockpit_transport import ssh_forward_plan
        argv = ssh_forward_plan('operator@rowan', Path('/home/operator/socket'), '/home/operator/runtime/cockpit.sock')
        self.assertIn('StrictHostKeyChecking=yes', argv)
        self.assertIn('BatchMode=yes', argv)
        self.assertIn('-N', argv)
        self.assertNotIn('sh', argv)
        for target in ['-oProxyCommand=bad', 'user:password@host', 'rowan;bad', 'rowan\n']:
            with self.assertRaises(ValueError):
                ssh_forward_plan(target, Path('/safe'), '/remote/socket')

    def test_no_request_retry_on_lost_ack(self):
        from arvyx_control.cockpit_transport import Endpoint
        endpoint = Endpoint(Path('/unused'), host='rowan', state='/events')
        with patch('arvyx_control.cockpit_transport.request', side_effect=[{'host': 'rowan', 'state': '/events'}, OSError('lost ACK')]) as rpc:
            with self.assertRaises(OSError):
                endpoint.call('write', sid='a', text='once', actor='operator')
            self.assertEqual(rpc.call_count, 2)
