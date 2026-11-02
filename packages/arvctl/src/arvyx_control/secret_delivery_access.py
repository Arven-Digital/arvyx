"""Private edge-only Cloudflare Access verification. Never imported by core auth.

The only key source is the operator-configured Access team issuer. No JWT URL,
email header, client certificate, shared bearer, or loopback identity is trusted.
"""
from __future__ import annotations

import http.client
import json
from .security import bounded_json_loads
from pathlib import Path
import re
import socket
import ssl
import threading
import time

from .http_bounds import bounded_connection, _validate_response_framing, _validate_response_complete
from .secret_delivery import SecretDelivery
from .secret_delivery_protocol import Principal, Rejected, private_json, reply

ORIGIN = 'https://control.party'
ISSUER = re.compile(r'https://[a-z0-9][a-z0-9-]{0,62}\.cloudflareaccess\.com\Z')
MAX_JWKS = 65536
CACHE_SECONDS = 300
REFRESH_SECONDS = 10


class AccessVerifier:
    def __init__(self, issuer: str, audience: str, subjects: list[str]):
        if (not isinstance(issuer, str) or not ISSUER.fullmatch(issuer)
                or not isinstance(audience, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,256}', audience)
                or not isinstance(subjects, list) or not subjects or len(subjects) > 128
                or len(set(subjects)) != len(subjects)):
            raise Rejected()
        for subject in subjects:
            Principal(subject, time.time() + 1).check()
        # Optional dependency: absence prevents enablement, never a fallback.
        import jwt
        from jwt.algorithms import RSAAlgorithm
        if 'RS256' not in jwt.algorithms.get_default_algorithms():
            raise Rejected()
        self.jwt, self.rsa = jwt, RSAAlgorithm
        self.issuer, self.audience = issuer, audience
        self.subjects = frozenset(subjects)
        self.keys = {}
        self.expires = 0.0
        self.last_attempt = float('-inf')
        self.lock = threading.Lock()

    def _fetch_jwks(self):
        """HTTPS with system CA/hostname verification; no redirects or proxies."""
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = http.client.HTTPSConnection(self.issuer.removeprefix('https://'), 443, timeout=3, context=context)
        response = None
        try:
            with bounded_connection(connection, 3):
                transport = connection.sock
                deadline = connection._transport_deadline
                connection.request('GET', '/cdn-cgi/access/certs', headers={'Accept': 'application/json', 'Connection': 'close'})
                response = connection.getresponse()
                _validate_response_framing(response)
                if response.status != 200:
                    raise Rejected()
                raw = bytearray()
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or len(raw) > MAX_JWKS:
                        raise Rejected()
                    # read1 can close the socket while returning final bytes.
                    if response.isclosed():
                        break
                    transport.settimeout(remaining)
                    chunk = response.read1(min(8192, MAX_JWKS + 1 - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
                if len(raw) > MAX_JWKS:
                    raise Rejected()
                _validate_response_complete(response)
                result = bounded_json_loads(raw)
            return result
        except ssl.SSLError:
            raise
        except ValueError:
            raise Rejected() from None
        finally:
            if response is not None:
                response.close()

    def _key(self, kid):
        with self.lock:
            now = time.monotonic()
            if now < self.expires and kid in self.keys:
                return self.keys[kid]
            if now - self.last_attempt < REFRESH_SECONDS:
                raise Rejected()
            self.last_attempt = now
            document = self._fetch_jwks()
            entries = document.get('keys') if isinstance(document, dict) else None
            if not isinstance(entries, list) or not 1 <= len(entries) <= 16:
                raise Rejected()
            keys = {}
            for entry in entries:
                if (not isinstance(entry, dict) or entry.get('kty') != 'RSA'
                        or entry.get('alg', 'RS256') != 'RS256' or entry.get('use', 'sig') != 'sig'
                        or entry.get('key_ops', ['verify']) != ['verify']
                        or not isinstance(entry.get('kid'), str) or not 1 <= len(entry['kid']) <= 256
                        or entry['kid'] in keys or any(k in entry for k in ('d', 'p', 'q', 'dp', 'dq', 'qi'))):
                    raise Rejected()
                key = self.rsa.from_jwk(json.dumps(entry))
                if not 2048 <= key.key_size <= 8192:
                    raise Rejected()
                keys[entry['kid']] = key
            # Atomic replacement only after complete validation; never stale fallback.
            self.keys, self.expires = keys, time.monotonic() + CACHE_SECONDS
            if kid not in keys:
                raise Rejected()
            return keys[kid]

    def verify(self, headers) -> Principal:
        try:
            assertions = headers.get_all('Cf-Access-Jwt-Assertion', [])
            if len(assertions) != 1:
                raise Rejected()
            assertion = assertions[0]
            if not isinstance(assertion, str) or len(assertion) > 16384 or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', assertion):
                raise Rejected()
            header = self.jwt.get_unverified_header(assertion)
            if (header.get('alg') != 'RS256' or not isinstance(header.get('kid'), str)
                    or not 1 <= len(header['kid']) <= 256
                    or any(k in header for k in ('jku', 'jwk', 'x5u', 'x5c', 'crit'))):
                raise Rejected()
            claims = self.jwt.decode(assertion, self._key(header['kid']), algorithms=['RS256'],
                                     issuer=self.issuer, audience=self.audience, leeway=0,
                                     options={'require': ['iss', 'aud', 'sub', 'exp', 'iat', 'nbf', 'type']})
            # Human Access application tokens only; email is neither required nor
            # authority. Service-token and non-application identities stay denied.
            if (claims['type'] != 'app' or claims['sub'] not in self.subjects
                    or any(k in claims for k in ('common_name', 'service_token_id', 'service_token_status'))
                    or any(type(claims[k]) is not int for k in ('exp', 'iat', 'nbf'))
                    or not claims['iat'] <= claims['exp'] or not claims['nbf'] <= claims['exp']):
                raise Rejected()
            principal = Principal(claims['sub'], claims['exp'])
            principal.check()
            return principal
        except Exception:
            raise Rejected() from None


class SecretEdge:
    def __init__(self, verifier: AccessVerifier, service: SecretDelivery):
        if service.origin != ORIGIN:
            raise Rejected()
        self.verifier, self.service = verifier, service

    @classmethod
    def from_config(cls, path: Path):
        config = private_json(path)
        if (set(config) != {'enabled', 'origin', 'access_issuer', 'access_audience', 'operator_subjects', 'manifest', 'vault'}
                or config['enabled'] is not True or config['origin'] != ORIGIN):
            raise Rejected()
        verifier = AccessVerifier(config['access_issuer'], config['access_audience'], config['operator_subjects'])
        service = SecretDelivery.from_manifest(Path(config['manifest']), Path(config['vault']))
        return cls(verifier, service)

    def handle(self, handler):
        # This MUST remain before service/body and outside generic proxy journaling.
        try:
            principal = self.verifier.verify(handler.headers)
        except Exception:
            reply(handler, 403, {'error': 'secret-delivery-denied'})
            return
        self.service.handle(handler, principal)
