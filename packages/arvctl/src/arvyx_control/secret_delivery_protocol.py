"""Private Secret Delivery protocol: bounded metadata, no value-derived identifiers."""
from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
import hashlib
import http.client
import json
from .security import bounded_json_loads
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import threading
import time
from urllib.parse import urlsplit

from .http_bounds import bounded_connection, _validate_response_framing, _validate_response_complete

MAX_BODY = 98304
KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
IDENT = re.compile(r"[a-zA-Z0-9_-]{1,80}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
STATUSES = frozenset({"saved", "ambiguous", "rejected", "version-conflict", "overwrite-required"})


class Rejected(Exception):
    """Fixed message only; never chain an input-bearing exception."""
    def __init__(self):
        super().__init__("secret-delivery-rejected")


@dataclass(frozen=True, repr=False)
class Principal:
    """Internal verified human principal; never constructed from request JSON."""
    sub: str
    expires: float

    def check(self):
        if (not isinstance(self.sub, str) or not re.fullmatch(r'[!-~]{1,256}', self.sub)
                or self.expires <= time.time()):
            raise Rejected()


def envelope(payload: dict) -> bytes:
    """Use the browser's compact UTF-8 encoding, validate BEFORE reservation."""
    try:
        raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
        if len(raw) <= MAX_BODY:
            return raw
    except Exception:
        pass
    raise Rejected()


def validate_response(action, result):
    if not isinstance(result, dict):
        raise Rejected()
    if action == 'prepare':
        if (set(result) != {'exists', 'version'} or type(result['exists']) is not bool
                or not isinstance(result['version'], str) or not 1 <= len(result['version']) <= 256):
            raise Rejected()
    elif action == 'send':
        if set(result) != {'status'} or result['status'] not in STATUSES:
            raise Rejected()
    else:
        raise Rejected()
    return result


def safe_parents(path: Path):
    for parent in path.absolute().parents:
        info = parent.lstat()
        sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or (info.st_mode & 0o022 and not sticky_root)):
            raise Rejected()


def private_json(path: Path) -> dict:
    """Operator-owned configuration only, no symlink or writable parent."""
    try:
        path = Path(path).absolute()
        safe_parents(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > MAX_BODY:
                raise Rejected()
            raw = os.read(fd, MAX_BODY + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_BODY:
            raise Rejected()
        result = bounded_json_loads(raw)
        if not isinstance(result, dict):
            raise Rejected()
        return result
    except Exception:
        pass
    raise Rejected()


def body(handler) -> dict:
    """Call only AFTER authentication. Do not include parser details in errors."""
    try:
        if handler.headers.get_all("Transfer-Encoding") or len(handler.headers.get_all("Content-Length", [])) != 1:
            raise Rejected()
        if handler.headers.get_all("Content-Type") != ["application/json"]:
            raise Rejected()
        raw_length = handler.headers['Content-Length']
        if not re.fullmatch(r'[0-9]{1,6}', raw_length, re.ASCII):
            raise Rejected()
        length = int(raw_length)
        if not 0 < length <= MAX_BODY:
            raise Rejected()
        handler.connection.settimeout(5)
        raw = handler.rfile.read(length)
        if len(raw) != length:
            raise Rejected()
        result = bounded_json_loads(raw)
        if not isinstance(result, dict):
            raise Rejected()
        return result
    except Exception:
        pass
    raise Rejected()


def reply(handler, status: int, result: dict, cookie: str | None = None):
    data = envelope(result)
    handler.close_connection = True
    try:
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        handler.send_header("X-Frame-Options", "DENY")
        handler.send_header("Content-Length", str(len(data)))
        handler.send_header("Connection", "close")
        if cookie:
            handler.send_header("Set-Cookie", cookie)
        handler.end_headers()
        handler.wfile.write(data)
    except OSError:
        pass


def peer_pin(handler) -> str:
    if not isinstance(handler.connection, ssl.SSLSocket):
        raise Rejected()
    der = handler.connection.getpeercert(binary_form=True)
    if not der:
        raise Rejected()
    return hashlib.sha256(der).hexdigest()


class Receipts:
    """Crash-safe metadata only. Reserve ambiguous BEFORE any possible write.

    Never prune dedupe records automatically. Lost response/restart means query
    status, not replay. SQLite stores neither payload nor value fingerprints.
    """
    def __init__(self, path: Path):
        path = Path(path)
        safe_parents(path)
        info = path.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise Rejected()
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        info = os.fstat(fd)
        os.close(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise Rejected()
        self.path = path
        self.lock = threading.Lock()
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS receipts (id TEXT PRIMARY KEY, target TEXT, key TEXT, status TEXT, actor TEXT, created INTEGER)")
            # Prior rows used literal 'operator': never grant them to a new sub.
            columns = {row[1] for row in db.execute('PRAGMA table_info(receipts)')}
            if 'actor_bound' not in columns:
                db.execute('ALTER TABLE receipts ADD COLUMN actor_bound INTEGER NOT NULL DEFAULT 0')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def get(self, delivery_id: str, actor: str):
        Principal(actor, time.time() + 1).check()
        if not isinstance(delivery_id, str) or not IDENT.fullmatch(delivery_id):
            raise Rejected()
        with self.connect() as db:
            row = db.execute("SELECT id,target,key,status,actor,created,actor_bound FROM receipts WHERE id=?", (delivery_id,)).fetchone()
        if row and (row[4] != actor or row[6] != 1):
            raise Rejected()
        return dict(zip(("delivery_id", "target", "key", "status", "actor", "created"), row)) if row else None

    def reserve(self, delivery_id, target, key, actor):
        Principal(actor, time.time() + 1).check()
        if not all(isinstance(x, str) and IDENT.fullmatch(x) for x in (delivery_id, target)) or not isinstance(key, str) or not KEY.fullmatch(key):
            raise Rejected()
        with self.lock, self.connect() as db:
            cursor = db.execute("INSERT OR IGNORE INTO receipts (id,target,key,status,actor,created,actor_bound) VALUES (?,?,?,?,?,?,1)", (delivery_id, target, key, "ambiguous", actor, int(time.time())))
            fresh = cursor.rowcount == 1
        receipt = self.get(delivery_id, actor)
        if receipt is None or receipt["target"] != target or receipt["key"] != key:
            raise Rejected()
        return fresh, receipt

    def finish(self, delivery_id, status, actor):
        if status not in STATUSES:
            raise Rejected()
        with self.connect() as db:
            db.execute("UPDATE receipts SET status=? WHERE id=? AND actor=? AND actor_bound=1", (status, delivery_id, actor))
        return self.get(delivery_id, actor)


@dataclass(frozen=True)
class Target:
    id: str
    agent: str
    runtime: str
    url: str
    server_pin: str
    ca_file: str
    client_cert: str
    client_key: str = field(repr=False)
    allowed_keys: tuple[str, ...] = ()

    def __post_init__(self):
        parsed = urlsplit(self.url)
        if (not all(IDENT.fullmatch(x) for x in (self.id, self.agent, self.runtime))
                or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path != "/v1/deliver"
                or not HEX.fullmatch(self.server_pin) or not self.allowed_keys
                or not all(KEY.fullmatch(x) for x in self.allowed_keys)):
            raise Rejected()

    def exchange(self, payload: dict) -> dict:
        """Direct TLS only: verify CA, hostname AND enrolled certificate pin.

        No urllib environment proxy discovery, redirect following, retries or
        exception repr. Pin is checked before transmitting HTTP headers/body.
        """
        response = None
        try:
            raw = envelope(payload)
            parsed = urlsplit(self.url)
            if parsed.hostname is None:
                raise Rejected()
            context = ssl.create_default_context(cafile=self.ca_file)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(self.client_cert, self.client_key)
            connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, context=context, timeout=5)
            with bounded_connection(connection, 5):
                certificate = connection.sock.getpeercert(binary_form=True)
                if not certificate or hashlib.sha256(certificate).hexdigest() != self.server_pin:
                    raise Rejected()
                connection.request("POST", "/v1/deliver", raw, {"Content-Type": "application/json"})
                response = connection.getresponse()
                _validate_response_framing(response)
                if response.status != 200 or response.getheader("Content-Type") != "application/json":
                    raise Rejected()
                response_body = response.read(MAX_BODY + 1)
                if len(response_body) > MAX_BODY:
                    raise Rejected()
                _validate_response_complete(response)
                result = validate_response(payload.get('action'), bounded_json_loads(response_body))
            return result
        except Exception:
            pass
        finally:
            if response is not None:
                response.close()
        raise Rejected()
