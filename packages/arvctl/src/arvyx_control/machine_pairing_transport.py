"""Loopback-only proof-of-possession enrollment transport; no task authority."""
import base64
import hashlib
import json
from .security import bounded_json_loads
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from urllib.request import Request

from .http_bounds import BoundedOpener
from .public_onboarding_api import BoundedWorkers
from .machine_pairing import MachineIdentity, PairingStore


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


class BoundedPairingServer(BoundedWorkers, ThreadingHTTPServer):
    """Bound accepted intake workers and preheader/body socket lifetime."""


def _crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:
        raise ValueError('Ed25519 requires the approved secret-edge cryptography extra') from exc
    return Ed25519PrivateKey, Ed25519PublicKey, serialization


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != os.getuid() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError('state directory must be owned by current user and mode 0700')
    return path


def load_identity(directory):
    private, _, serialization = _crypto()
    directory = private_directory(directory)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = '.identity-' + secrets.token_hex(16)
    owned = False
    try:
        try:
            os.stat('identity.key', dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
            owned = True
            with os.fdopen(fd, 'wb') as stream:
                raw = private.generate().private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                # Exclusive publication of complete bytes; a concurrent winner
                # is retained, never rotated or overwritten by initialization.
                os.link(temporary, 'identity.key', src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
            except FileExistsError:
                pass
        fd = os.open('identity.key', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077 or not stat.S_ISREG(info.st_mode):
                raise ValueError('identity key must be private regular file')
            try:
                key = private.from_private_bytes(stream.read(33))
            except ValueError:
                raise ValueError('invalid identity key; explicit identity recovery required, refusing rotation') from None
            os.fsync(stream.fileno())
        # Repeat the namespace barrier on retries after uncertain publication.
        os.fsync(directory_fd)
        return key
    finally:
        if owned:
            os.unlink(temporary, dir_fd=directory_fd)
        os.close(directory_fd)


class PairingTransport:
    def __init__(self, directory, *, clock=time.time, limit=30):
        _crypto()
        directory = private_directory(directory)
        # Precreate the DB privately before sqlite opens it.
        path = directory / 'pairing.sqlite3'
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self.store = PairingStore(path, clock=clock, limit=limit)
        self.clock = clock
        self.store.db.executescript('''CREATE TABLE IF NOT EXISTS pairing_challenges (
            nonce TEXT PRIMARY KEY, name TEXT NOT NULL, public_key TEXT NOT NULL,
            purpose TEXT NOT NULL, message TEXT NOT NULL, expires REAL NOT NULL,
            used INTEGER NOT NULL DEFAULT 0);''')

    @staticmethod
    def public(key, name):
        _, _, serialization = _crypto()
        return {'name': name, 'public_key': base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()}

    def close(self):
        self.store.close()

    def challenge(self, data):
        # Global persistent bucket: identity/IP changes cannot bypass the limit.
        with self.store._transaction():
            limited = self.store._limited('transport_challenge', self.store._now())
        if limited:
            raise ValueError('rate_limited')
        identity = MachineIdentity(data['name'], data['public_key'])
        purpose = data['purpose']
        if purpose not in ('confirm', 'check'):
            raise ValueError('invalid purpose')
        nonce = secrets.token_hex(32)
        expires = self.store._now() + 30
        message = base64.b64encode(json.dumps({'protocol': 'amc-pairing-v1', 'nonce': nonce, 'name': identity.name, 'public_key': identity.public_key, 'purpose': purpose, 'code_digest': hashlib.sha256(data.get('code', '').encode()).hexdigest(), 'expires': expires}, sort_keys=True, separators=(',', ':')).encode()).decode()
        with self.store._transaction():
            self.store.db.execute('DELETE FROM pairing_challenges WHERE expires < ?', (self.store._now()-600,))
            self.store.db.execute('INSERT INTO pairing_challenges VALUES (?,?,?,?,?,?,0)', (nonce, identity.name, identity.public_key, purpose, message, expires))
        return {'challenge': nonce, 'message': message, 'expires_at': expires}

    def prove(self, data):
        if not isinstance(data.get('challenge'), str) or not isinstance(data.get('signature'), str):
            raise ValueError('challenge and signature strings required')
        # Consume before verification, including invalid proofs; serialized across processes.
        with self.store._transaction():
            limited = self.store._limited('transport_proof', self.store._now())
            row = self.store.db.execute('SELECT * FROM pairing_challenges WHERE nonce=?', (data['challenge'],)).fetchone()
            if not limited and row and not row['used']:
                self.store.db.execute('UPDATE pairing_challenges SET used=1 WHERE nonce=?', (row['nonce'],))
        if limited:
            raise ValueError('rate_limited')
        if not row or row['used']:
            raise ValueError('invalid or replayed challenge')
        if self.store._now() >= row['expires']:
            raise ValueError('expired challenge')
        _, public, _ = _crypto()
        try:
            public.from_public_bytes(base64.b64decode(row['public_key'], validate=True)).verify(base64.b64decode(data['signature'], validate=True), base64.b64decode(row['message'], validate=True))
        except Exception as exc:
            raise ValueError('invalid proof') from exc
        identity = MachineIdentity(row['name'], row['public_key'])
        if row['purpose'] == 'confirm':
            binding = json.loads(base64.b64decode(row['message']))
            code = data.get('code', '')
            if not isinstance(code, str) or hashlib.sha256(code.encode()).hexdigest() != binding['code_digest']:
                raise ValueError('code binding mismatch')
            decision = self.store.claim(code, identity)
            if not decision.allowed:
                raise ValueError(decision.reason)
            return {'fingerprint': identity.fingerprint, 'status': decision.reason}
        decision = self.store.check(identity)
        return {'allowed': decision.allowed, 'reason': decision.reason, 'fingerprint': identity.fingerprint}


def make_server(transport, port=0):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # Never log codes or signatures.

        def do_POST(self):
            # Never renew the lifetime timer installed before header parsing.
            self.close_connection = True
            try:
                lengths = self.headers.get_all('Content-Length', [])
                if (len(lengths) != 1 or not lengths[0].isascii()
                        or not lengths[0].isdigit()
                        or self.headers.get_all('Transfer-Encoding') is not None):
                    raise ValueError('invalid request framing')
                length = int(lengths[0])
                if not 0 < length <= 8192:
                    raise ValueError('invalid request size')
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError('incomplete request body')
                data = bounded_json_loads(body, object_pairs_hook=_unique_object)
                if not isinstance(data, dict):
                    raise ValueError('object required')
                if self.path == '/challenge':
                    result = transport.challenge(data)
                elif self.path == '/prove':
                    result = transport.prove(data)
                else:
                    raise ValueError('unsupported endpoint')
                status = 200
            except (ValueError, KeyError, TypeError):
                result, status = {'error': 'pairing request denied'}, 400
            payload = json.dumps(result).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
    return BoundedPairingServer(('127.0.0.1', port), Handler)


def remote_action(directory, url, name, purpose, code=None):
    parts = urlsplit(url)
    if parts.scheme != 'http' or parts.hostname != '127.0.0.1' or parts.username or parts.password or parts.path not in ('', '/') or parts.query or parts.fragment:
        raise ValueError('only literal loopback HTTP (or an approved SSH tunnel) is supported')
    key = load_identity(directory)
    opener = BoundedOpener()
    deadline = time.monotonic() + 10
    def post(path, data):
        request = Request(url.rstrip('/') + path, data=json.dumps(data).encode(), headers={'Content-Type': 'application/json'}, method='POST')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('pairing deadline exceeded; nothing retried')
        with opener.open(request, timeout=remaining) as response:
            lengths = response.headers.get_all('Content-Length', [])
            if (len(lengths) > 1 or (lengths and
                    (not lengths[0].isascii() or not lengths[0].isdigit()))
                    or response.headers.get_all('Transfer-Encoding') is not None):
                raise ValueError('invalid pairing response framing')
            payload = response.read(16385)
            if len(payload) > 16384:
                raise ValueError('pairing response size limit exceeded')
            if response.length not in (None, 0):
                raise ValueError('incomplete pairing response; nothing retried')
            result = bounded_json_loads(payload, object_pairs_hook=_unique_object)
            if not isinstance(result, dict):
                raise ValueError('pairing response object required')
        return result
    challenge = post('/challenge', {**PairingTransport.public(key, name), 'purpose': purpose, 'code': code or ''})
    message = base64.b64decode(challenge['message'], validate=True)
    binding = bounded_json_loads(message)
    expected = PairingTransport.public(key, name)
    if (binding.get('protocol') != 'amc-pairing-v1' or binding.get('nonce') != challenge['challenge']
            or binding.get('purpose') != purpose or binding.get('name') != name
            or binding.get('public_key') != expected['public_key']
            or binding.get('code_digest') != hashlib.sha256((code or '').encode()).hexdigest()):
        raise ValueError('server challenge binding mismatch')
    signature = base64.b64encode(key.sign(message)).decode()
    return post('/prove', {'challenge': challenge['challenge'], 'signature': signature, 'code': code or ''})
