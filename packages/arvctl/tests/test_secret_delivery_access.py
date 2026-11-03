"""Real edge denial matrix, signed synthetic JWTs and local key source only."""
import builtins
import dataclasses
from email.message import Message
import http.client
import json
from pathlib import Path
import secrets
import socket
import time
import os
import unittest
from unittest.mock import patch

import test_secret_delivery as fixture
from arvyx_control.secret_delivery_access import AccessVerifier, SecretEdge, MAX_JWKS
from arvyx_control.secret_delivery_protocol import MAX_BODY, Receipts, Rejected, envelope


class EdgeAccessTests(fixture.SecretDeliveryE2E):
    def test_signed_jwt_denial_matrix_before_body_every_operation(self):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        forged_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged = jwt.encode(dict(sub='human-a', iss=self.verifier.issuer, aud=['synthetic-app'],
                                 exp=int(time.time())+30, iat=int(time.time())-1, nbf=int(time.time())-1, type='app'),
                            forged_key, algorithm='RS256', headers={'kid':'synthetic-key'})
        invalid = [None, '', forged, self.token(aud=['wrong-app']), self.token(exp=int(time.time())-1),
                   self.token(iss='https://unknown.cloudflareaccess.com'), self.token(sub='unapproved'),
                   self.token(type='service'), self.token(common_name='human-a'),
                   self.token(service_token_id='synthetic-service'), self.token(nbf=int(time.time())+30),
                   self.token(iat=int(time.time())+30), self.token(exp=None), self.token(sub=''),
                   self.token(iat='1'), self.token(exp=True), self.token(type=None)]
        for action in ('bootstrap', 'prepare', 'send', 'status'):
            for assertion in invalid:
                with self.subTest(action=action, variant=invalid.index(assertion)):
                    # No bytes sent for declared body. Reading it would time out.
                    status, data, _ = self.request(action, {}, raw=b'', headers={
                        'Cf-Access-Jwt-Assertion':assertion, 'Content-Length':'90000',
                        'Cf-Access-Authenticated-User-Email':'operator@example.invalid',
                        'Authorization':'Bearer '+self.bearer})
                    self.assertEqual((status, data), (403, {'error':'secret-delivery-denied'}))
        self.assertFalse((self.root/'events.jsonl').exists())

    def test_duplicate_and_comma_assertions_before_body(self):
        for values in ([self.assertion, self.assertion], [self.assertion+','+self.assertion]):
            connection = http.client.HTTPSConnection('localhost', self.ingress.server_port, context=self.context(), timeout=2)
            connection.putrequest('POST', '/secret-delivery/send')
            for value in values: connection.putheader('Cf-Access-Jwt-Assertion', value)
            connection.putheader('Content-Length', '90000'); connection.endheaders()
            response = connection.getresponse(); response.read()
            self.assertEqual(response.status, 403)
            connection.close()

    def test_cross_actor_receipts_sessions_preparations_and_receiver_dedupe(self):
        _, result, sent = self.send()
        self.assertEqual(result['receipt']['actor'], 'human-a')
        self.assertEqual(self.receiver.receipts.get(sent['delivery_id'], 'human-a')['actor'], 'human-a')
        prepared = self.prepare()
        old_cookie, old_csrf = self.cookie, self.csrf
        self.assertion = self.token(sub='human-b')
        self.assertEqual(self.request('status', {'delivery_id':sent['delivery_id']})[0], 400)
        self.bootstrap()
        self.assertEqual(self.request('status', {'delivery_id':sent['delivery_id']})[0], 400)
        self.assertEqual(self.request('send', sent)[0], 400)
        self.assertEqual(self.send(prepared=prepared)[0], 400)
        self.assertEqual(self.request('prepare', {'target':self.target.id, 'key':'OTHER'},
                                     headers={'Cookie':old_cookie, 'X-Secret-CSRF':old_csrf})[0], 400)
        direct = dict(action='prepare', target=self.target.id, agent=self.target.agent,
                      runtime=self.target.runtime, key='OTHER', actor='human-a')
        prep = self.target.exchange(direct)
        direct.update(action='send', value='synthetic', delivery_id=secrets.token_hex(16),
                      version=prep['version'], overwrite=False, actor='human-b')
        with self.assertRaises(Rejected): self.target.exchange(direct)
        direct.update(key=sent['key'], delivery_id=sent['delivery_id'])
        with self.assertRaises(Rejected): self.target.exchange(direct)
        self.assertEqual(self.send('actor-b')[1]['receipt']['actor'], 'human-b')

    def test_expired_jwt_cannot_reuse_live_session(self):
        self.assertion = self.token(exp=int(time.time())-1)
        self.assertEqual(self.request('status', {'delivery_id':'unknown'})[0], 403)
        self.assertion = self.token()
        for session in self.service.sessions.values(): session.expires = time.time()-1
        self.assertEqual(self.request('prepare', {'target':self.target.id,'key':'OTHER'})[0], 400)

    def test_complete_outbound_envelope_rejected_before_reservation(self):
        # Tune browser JSON to fit while trusted receiver metadata pushes it over.
        prepared = self.prepare()
        payload = dict(target=self.target.id, key='anthtropic_auth', value='', delivery_id=secrets.token_hex(16),
                       confirmation=prepared['confirmation'], overwrite=False)
        overhead = len(envelope(payload))
        payload['value'] = '\t' * ((MAX_BODY-overhead)//2)
        self.assertLessEqual(len(envelope(payload)), MAX_BODY)
        with patch.object(self.service.receipts, 'reserve', side_effect=AssertionError('reserved oversized envelope')) as reserve:
            self.assertEqual(self.request('send', payload, raw=envelope(payload))[0], 400)
            reserve.assert_not_called()
        self.assertIsNone(self.service.receipts.get(payload['delivery_id'], 'human-a'))
        self.assertFalse((self.destdir/'.env').exists())

    def test_body_limits_duplicate_headers_and_utf8_overlimit(self):
        prepared = self.prepare()
        payload = dict(target=prepared['target'], key=prepared['key'], value='雪'*21846,
                       delivery_id=secrets.token_hex(16), confirmation=prepared['confirmation'],
                       overwrite=prepared['exists'])
        # ASCII escaping exceeded MAX_BODY and raced the server's early close,
        # never exercising the distinct decoded UTF-8 value limit.
        raw = envelope(payload)
        self.assertLessEqual(len(raw), MAX_BODY)
        self.assertGreater(len(payload['value'].encode('utf-8')), 65536)
        self.assertEqual(self.request('send', payload, raw=raw)[0], 400)
        self.assertIsNone(self.service.receipts.get(payload['delivery_id'], 'human-a'))
        self.assertFalse((self.destdir/'.env').exists())
        # An oversized declared body must be rejected without reading its bytes.
        self.assertEqual(self.request('send', {}, raw=b'',
                                      headers={'Content-Length':str(MAX_BODY+1)})[0], 400)
        for raw_len in ('+2', '-1', '02x'):
            self.assertEqual(self.request('bootstrap', {}, headers={'Content-Length':raw_len})[0], 400)
        for name, values in [('Origin', [self.service.origin]*2), ('Content-Length', ['2','2']),
                             ('Content-Type', ['application/json']*2)]:
            c = http.client.HTTPSConnection('localhost', self.ingress.server_port, context=self.context(), timeout=2)
            c.putrequest('POST', '/secret-delivery/bootstrap')
            headers = {'Cf-Access-Jwt-Assertion':self.assertion,'Origin':self.service.origin,
                       'Content-Length':'2','Content-Type':'application/json','X-Secret-Delivery':'1'}
            headers.pop(name)
            for k,v in headers.items(): c.putheader(k,v)
            for v in values: c.putheader(name,v)
            c.endheaders(b'{}'); r=c.getresponse(); r.read(); self.assertEqual(r.status,400); c.close()

    def test_opt_in_config_and_missing_dependency_fail_closed(self):
        manifest = self.root/'destinations.json'
        manifest.write_text(json.dumps(dict(enabled=True, origin='https://control.party',
                                           targets=[dataclasses.asdict(self.target)], receipts=str(self.root/'config-receipts.sqlite'))))
        manifest.chmod(0o600)
        config = dict(enabled=True, origin='https://control.party', access_issuer=self.verifier.issuer,
                      access_audience='synthetic-app', operator_subjects=['human-a'], manifest=str(manifest), vault=str(self.vault))
        path = self.root/'edge.json'
        def write(): path.write_text(json.dumps(config)); path.chmod(0o600)
        write(); self.assertIsInstance(SecretEdge.from_config(path), SecretEdge)
        for key,value in [('origin','https://evil.invalid'),('enabled',False),('access_issuer','http://synthetic.cloudflareaccess.com'),
                          ('access_issuer','https://synthetic.cloudflareaccess.com/evil'),('access_audience',''),('operator_subjects',[])]:
            previous=config[key]; config[key]=value; write()
            with self.assertRaises(Rejected): SecretEdge.from_config(path)
            config[key]=previous
        write()
        real_import=builtins.__import__
        def no_jwt(name,*args,**kwargs):
            if name=='jwt' or name.startswith('jwt.'): raise ImportError('synthetic missing optional dependency')
            return real_import(name,*args,**kwargs)
        with patch('builtins.__import__',side_effect=no_jwt):
            with self.assertRaises(ImportError): SecretEdge.from_config(path)
        original = self.ingress.secret_edge; self.ingress.secret_edge=None
        try:
            self.assertEqual(self.request('send', {}, raw=b'',headers={'Content-Length':'90000'})[0],503)
        finally: self.ingress.secret_edge=original

    def test_jwks_fixed_source_rotation_expiry_and_no_token_urls(self):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        verifier = self.verifier_class(self.verifier.issuer,'synthetic-app',['human-a'])
        def headers(token):
            h=Message(); h['Cf-Access-Jwt-Assertion']=token; return h
        with patch.object(verifier,'_fetch_jwks',wraps=verifier._fetch_jwks) as fetch:
            verifier.verify(headers(self.assertion)); verifier.verify(headers(self.assertion)); self.assertEqual(fetch.call_count,1)
            key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
            jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())); jwk.update(kid='rotated')
            claims=jwt.decode(self.assertion, self.jwt_key.public_key(), algorithms=['RS256'], audience='synthetic-app')
            rotated=jwt.encode(claims,key,algorithm='RS256',headers={'kid':'rotated'})
            with self.assertRaises(Rejected): verifier.verify(headers(rotated))
            verifier.last_attempt=float('-inf')
            with patch.object(verifier,'_fetch_jwks',return_value={'keys':[jwk]}):
                self.assertEqual(verifier.verify(headers(rotated)).sub,'human-a')
            with self.assertRaises(Rejected): verifier.verify(headers(self.assertion))
            verifier.expires=0; verifier.last_attempt=float('-inf')
            with patch.object(verifier,'_fetch_jwks',side_effect=TimeoutError):
                with self.assertRaises(Rejected): verifier.verify(headers(rotated))
        malicious=jwt.encode(claims,self.jwt_key,algorithm='RS256',headers={'kid':'synthetic-key','jku':'https://evil.invalid/keys'})
        with patch.object(verifier,'_fetch_jwks',side_effect=AssertionError('token URL fetch')) as fetch:
            with self.assertRaises(Rejected): verifier.verify(headers(malicious))
            fetch.assert_not_called()
        # Exercise production fetcher with a fake connection; no external network.
        verifier=AccessVerifier(self.verifier.issuer,'synthetic-app',['human-a'])
        from unittest.mock import MagicMock
        for status,raw in [(302,b'{}'),(200,b' '* (MAX_JWKS+1))]:
            conn=MagicMock(); resp=conn.getresponse.return_value; resp.status=status
            resp.isclosed.return_value=False; resp.length=None
            chunks=[raw[i:i+8192] for i in range(0,len(raw),8192)]+[b'']
            resp.read1.side_effect=chunks
            with patch('arvyx_control.secret_delivery_access.http.client.HTTPSConnection',return_value=conn) as factory:
                with self.assertRaises(Rejected): verifier._fetch_jwks()
                self.assertEqual(factory.call_args.args,('synthetic.cloudflareaccess.com',443))
                self.assertEqual(conn.request.call_args.args,('GET','/cdn-cgi/access/certs'))

    def test_tls_worker_gate_and_recovery(self):
        server=self.servers[0][0]
        server.handshake_timeout=.4
        stalled=[]
        try:
            for _ in range(8): stalled.append(socket.create_connection(('127.0.0.1',server.server_port)))
            time.sleep(.1)
            extra=socket.create_connection(('127.0.0.1',server.server_port)); extra.settimeout(1)
            self.assertEqual(extra.recv(1),b''); extra.close()
            time.sleep(.5)
            self.prepare()
        finally:
            for c in stalled:c.close()


def load_tests(loader, tests, pattern):
    # Inherit fixture helpers, not duplicate the base suite's test receipts.
    return unittest.TestSuite(EdgeAccessTests(name) for name in EdgeAccessTests.__dict__ if name.startswith('test_'))


if __name__ == '__main__': unittest.main()
