"""Offline real RS256 verification across a controlled JWKS lock wait."""
from email.message import Message
import json
import threading
import time
import unittest
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from arvyx_control.secret_delivery_access import AccessVerifier, CACHE_SECONDS
from arvyx_control.secret_delivery_protocol import Rejected


class WaitingLock:
    def __init__(self):
        self.lock = threading.Lock()
        self.lock.acquire()
        self.waiting = threading.Event()

    def __enter__(self):
        self.waiting.set()
        if not self.lock.acquire(timeout=2):
            raise AssertionError('controlled lock wait timed out')

    def __exit__(self, *args):
        self.lock.release()


class AccessClockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.signer.public_key()))
        cls.jwk.update(kid='synthetic-clock-key')

    def verify_after_wait(self, fetch_result=None, last_attempt=0, expires=105):
        verifier = AccessVerifier('https://synthetic.cloudflareaccess.com', 'synthetic-app', ['human-a'])
        verifier.keys = {'synthetic-clock-key': self.signer.public_key()}
        verifier.expires = expires
        verifier.last_attempt = last_attempt
        verifier.lock = WaitingLock()
        wall = int(time.time())
        token = jwt.encode(dict(iss=verifier.issuer, aud=verifier.audience, sub='human-a',
                                exp=wall+60, iat=wall-1, nbf=wall-1, type='app'),
                           self.signer, algorithm='RS256', headers={'kid': 'synthetic-clock-key'})
        headers = Message()
        headers['Cf-Access-Jwt-Assertion'] = token
        clock = [100.0]
        outcome = []

        def run():
            try:
                outcome.append(verifier.verify(headers))
            except Exception as exc:
                outcome.append(exc)

        kwargs = ({'side_effect': fetch_result} if isinstance(fetch_result, Exception)
                  else {'return_value': fetch_result})
        with patch('arvyx_control.secret_delivery_access.time.monotonic', side_effect=lambda: clock[0]), \
                patch.object(verifier, '_fetch_jwks', **kwargs) as fetch:
            worker = threading.Thread(target=run)
            worker.start()
            try:
                self.assertTrue(verifier.lock.waiting.wait(2), 'worker did not reach lock')
                clock[0] = 110.0
            finally:
                verifier.lock.lock.release()
                worker.join(3)
            self.assertFalse(worker.is_alive(), 'verification remained blocked')
        self.assertEqual(len(outcome), 1)
        return verifier, outcome[0], fetch.call_count

    def test_expired_cache_after_wait_refuses_failed_refresh(self):
        verifier, result, calls = self.verify_after_wait(TimeoutError('synthetic offline failure'))
        self.assertIsInstance(result, Rejected)
        self.assertEqual(calls, 1)
        self.assertEqual(verifier.last_attempt, 110)
        self.assertEqual(verifier.expires, 105)

    def test_expired_cache_after_wait_refreshes_and_verifies_rs256(self):
        verifier, result, calls = self.verify_after_wait({'keys': [self.jwk]}, last_attempt=95)
        self.assertNotIsInstance(result, Exception)
        self.assertEqual(result.sub, 'human-a')
        self.assertEqual(calls, 1)
        self.assertEqual(verifier.last_attempt, 110)
        self.assertEqual(verifier.expires, 110 + CACHE_SECONDS)

    def test_expired_cache_with_recent_failed_attempt_obeys_minimum_gap(self):
        verifier, result, calls = self.verify_after_wait({'keys': [self.jwk]}, last_attempt=106)
        self.assertIsInstance(result, Rejected)
        self.assertEqual(calls, 0)
        self.assertEqual(verifier.last_attempt, 106)

    def test_unexpired_cache_after_wait_still_verifies_without_refresh(self):
        _, result, calls = self.verify_after_wait(TimeoutError(), expires=115)
        self.assertNotIsInstance(result, Exception)
        self.assertEqual(result.sub, 'human-a')
        self.assertEqual(calls, 0)


if __name__ == '__main__':
    unittest.main()
