"""synthetic real-flock regression; no external delivery or guard mocks."""
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHILD = r'''
import os, sys, time
from pathlib import Path
from arvyx_control.secret_delivery_writer import Destination, DeliveryError
from arvyx_control.secret_delivery_receiver import Receiver
from arvyx_control.secret_delivery_protocol import Receipts
root = Path(sys.argv[1])
mode = sys.argv[2]
d = Destination(str(root), '.env', os.getuid(), allowed_keys={'KEY'})
r = Receiver('target', 'agent', 'runtime', {'a' * 64}, d, Receipts(root / 'receipts.jsonl'))
payload = dict(action='prepare', target='target', agent='agent', runtime='runtime', key='KEY', actor='operator')
if mode == 'send':
    from arvyx_control.secret_delivery_writer import Prepared
    r.preparations['token'] = (Prepared('KEY', False, 'synthetic-version'), time.time() + 120, 'operator')
    payload.update(action='send', value='synthetic', delivery_id='a' * 32, version='token', overwrite=False)
start = time.monotonic()
try:
    if mode == 'writer':
        d.write('KEY', 'synthetic')
    else:
        result = r.operate(payload)
        assert result == {'status': 'ambiguous'}, result
        assert r.operate(payload) == result  # durable result, no unsafe retry
        print('ambiguous')
except DeliveryError as exc:
    assert str(exc) == 'lock-timeout', str(exc)
    print(str(exc))
assert time.monotonic() - start < 2
assert not (root / '.env').exists()
assert not list(root.glob('*.tmp'))
'''


class WriterLockTests(unittest.TestCase):
    def test_expired_tls_request_releases_worker_while_destination_stays_locked(self):
        import http.client
        import json
        import ssl
        import threading
        import time
        from test_secret_delivery import certificates, pin
        from arvyx_control.secret_delivery_protocol import Receipts
        from arvyx_control.secret_delivery_receiver import Receiver
        from arvyx_control.secret_delivery_server import SecretTLSServer
        from arvyx_control.secret_delivery_writer import Destination
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            certificates(root)
            dest = Destination(directory, '.env', os.getuid(), allowed_keys={'KEY'})
            receiver = Receiver('target', 'agent', 'runtime', {pin(root / 'sender.pem')}, dest, Receipts(root / 'receipts.sqlite'))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / 'server.pem', root / 'server.key')
            context.load_verify_locations(root / 'ca.pem')
            context.verify_mode = ssl.CERT_REQUIRED
            server = SecretTLSServer(('127.0.0.1', 0), receiver.handler(), context)
            server.request_lifetime_seconds = 0.2
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
            lock = os.open(root / dest.lockname, os.O_CREAT | os.O_RDWR, 0o600)
            connection = None
            slots = 0
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                thread.start()
                client = ssl.create_default_context(cafile=str(root / 'ca.pem'))
                client.load_cert_chain(root / 'sender.pem', root / 'sender.key')
                connection = http.client.HTTPSConnection('localhost', server.server_port, context=client, timeout=2)
                payload = dict(action='prepare', target='target', agent='agent', runtime='runtime', key='KEY', actor='operator')
                server.request_lifetime_seconds = 2
                connection.request('POST', '/v1/deliver', json.dumps(payload), {'Content-Type': 'application/json'})
                response = connection.getresponse()
                self.assertEqual(response.status, 400)
                self.assertEqual(json.loads(response.read()), {'error': 'secret-delivery-rejected'})
                connection.close()
                connection = http.client.HTTPSConnection('localhost', server.server_port, context=client, timeout=2)
                server.request_lifetime_seconds = 0.2
                connection.request('POST', '/v1/deliver', json.dumps(payload), {'Content-Type': 'application/json'})
                with self.assertRaises((http.client.RemoteDisconnected, ConnectionError)):
                    connection.getresponse()
                limit = time.monotonic() + 2
                while slots < 8 and time.monotonic() < limit:
                    if server._worker_slots.acquire(blocking=False):
                        slots += 1
                    else:
                        time.sleep(0.01)
                self.assertEqual(slots, 8, 'expired request retained a worker slot')
                self.assertFalse((root / '.env').exists())
            finally:
                for _ in range(slots):
                    server._worker_slots.release()
                os.close(lock)
                if connection:
                    connection.close()
                server.shutdown()
                server.server_close()
                thread.join(2)

    def test_contended_receiver_prepare_send_and_direct_writer_are_bounded(self):
        for mode in ('prepare', 'send', 'writer'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                lock = os.open(root / '..env.secret-delivery.lock', os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    child = subprocess.Popen([sys.executable, '-c', CHILD, directory, mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        out, err = child.communicate(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        out, err = child.communicate()
                        self.fail('destination flock retained receiver/writer beyond 3 seconds: ' + err)
                    self.assertEqual(child.returncode, 0, err)
                    self.assertEqual(out.strip(), 'ambiguous' if mode == 'send' else 'lock-timeout')
                    self.assertFalse((root / '.env').exists())
                finally:
                    os.close(lock)


if __name__ == '__main__':
    unittest.main()
