"""Linux destination writer, not transport or a general dotenv editor.

Integration: construct Destination(operator_resolved_absolute_directory, basename,
trusted_uid, allowed_keys=frozenset(operator_enrolled_keys)). Never pass client paths
or client key policies. Default policy allows NO keys. prepare(key) (also inspect)
returns existence and a non-secret stat-based version string. write(key, value,
overwrite_version=explicitly_confirmed_version) returns metadata only. Bind the
confirmation to authenticated actor/target/key at ingress; a version is not auth.

Supports a conservative UTF-8 python-dotenv grammar; rejects ambiguous/unsupported
files rather than guessing. ${ is unsupported because the real reader interpolates.
This is NOT compatible with AMC brokers._resolve_envfile's simplistic quote stripping.
Values ending in a backslash fail closed: python-dotenv can consume the following
binding when that backslash precedes a closing quote. Hermes strips non-ASCII from
uppercase credential suffix keys (_API_KEY/_TOKEN/_SECRET/_KEY); those key/value
combinations also fail closed. Other keys retain Unicode. No restart, secret
logging, persistent value hashes, or parser dependency.

Security boundary: trusted runtime UID/root and local POSIX filesystem. Ancestors
must be root/UID owned and not writable by others (root sticky temp dirs permitted);
terminal directory is owner-only. Locks serialize cooperative writers. Revalidation
detects external changes before rename but POSIX has no atomic compare-and-rename:
a hostile owner/root ignoring locks can race the final check, replace ancestors or
read plaintext. ACLs, hostile mounts, xattrs/SELinux labels and network filesystems
are outside this component's guarantee. Replacement preserves uid/gid, not ACLs or
xattrs. io-ambiguous means replacement may have happened: NEVER blindly retry.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
import re
import secrets
import stat
import time

from .locks import try_exclusive_lock

# A socket deadline cannot interrupt flock. Bound acquisition in the writer itself.
LOCK_WAIT_SECONDS = 0.5
LOCK_POLL_SECONDS = 0.01

MAX_VALUE_BYTES = 65536
MAX_FILE_BYTES = 1048576
_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}\Z', re.ASCII)
# Full binding consumption, with spans used only to replace the selected binding.
_PREFIX = re.compile(r'[ \t]*(?:export[ \t]+)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*')
_QUOTED = {
    '"': re.compile(r'"((?:\\"|[^"])*)"'),
    "'": re.compile(r"'((?:\\'|[^'])*)'"),
}
_TAIL = re.compile(r'[ \t]*(?:\#[^\r\n]*)?(?:\r\n|\n|\r|\Z)')
_UNQUOTED = re.compile(r'[^\r\n]*')
_BLANK = re.compile(r'[ \t]*(?:\#[^\r\n]*)?(?:\r\n|\n|\r|\Z)')


def _require_posix_ownership() -> None:
    """Delivery destinations are defined by POSIX uid, sticky-bit and mode semantics."""
    if os.name != "posix":
        raise DeliveryError("unsupported-platform")


class DeliveryError(Exception):
    """Only fixed secret-free codes cross this boundary."""


@dataclass(frozen=True)
class Prepared:
    key: str
    exists: bool
    version: str


@dataclass(frozen=True)
class Receipt:
    key: str
    replaced: bool
    version: str
    status: str = 'stored'


def _stamp(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _bindings(raw):
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        text = None
    if text is None:
        raise DeliveryError('unsupported-file')
    if '\x00' in text or text.startswith('\ufeff'):
        raise DeliveryError('unsupported-file')
    pos, found = 0, {}
    while pos < len(text):
        match = _BLANK.match(text, pos)
        if match is not None and match.end() > pos:
            pos = match.end()
            continue
        match = _PREFIX.match(text, pos)
        if match is None:
            raise DeliveryError('unsupported-file')
        key = match['key']
        value_start = match.end()
        quote = text[value_start:value_start + 1]
        if quote in _QUOTED:
            value_match = _QUOTED[quote].match(text, value_start)
            if value_match is None or value_match[1].endswith('\\'):
                raise DeliveryError('unsupported-file')
        else:
            value_match = _UNQUOTED.match(text, value_start)
        tail = _TAIL.match(text, value_match.end())
        if tail is None:
            raise DeliveryError('unsupported-file')
        if key in found:
            raise DeliveryError('duplicate-key')
        found[key] = (pos, tail.end())
        pos = tail.end()
    return text, found


class Destination:
    def __init__(self, directory: str, filename: str, trusted_uid: int, *, allowed_keys=frozenset()):
        if (not isinstance(directory, str) or not directory.startswith('/') or '\x00' in directory
                or any(p in ('', '.', '..') for p in directory.split('/')[1:])
                or not isinstance(filename, str) or filename in ('', '.', '..')
                or '/' in filename or '\x00' in filename or len(filename) > 120
                or type(trusted_uid) is not int or trusted_uid < 0):
            raise DeliveryError('invalid-destination')
        self.directory, self.filename, self.trusted_uid = directory, filename, trusted_uid
        self.allowed_keys = frozenset(allowed_keys)
        self.lockname = '.' + filename + '.secret-delivery.lock'

    def _key(self, key):
        if not isinstance(key, str) or not _NAME.fullmatch(key):
            raise DeliveryError('invalid-name')
        if key not in self.allowed_keys:
            raise DeliveryError('key-not-enrolled')

    def _directory(self):
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            parts = self.directory.split('/')[1:]
            for i, part in enumerate(parts):
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = nxt
                st = os.fstat(fd)
                terminal = i == len(parts) - 1
                sticky_root = st.st_uid == 0 and bool(st.st_mode & stat.S_ISVTX)
                if (st.st_uid not in (0, self.trusted_uid)
                        or (st.st_mode & 0o022 and not sticky_root)
                        or (terminal and (st.st_uid != self.trusted_uid or st.st_mode & 0o077))):
                    raise DeliveryError('unsafe-destination')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _regular(self, st):
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != self.trusted_uid or st.st_mode & 0o7077):
            raise DeliveryError('unsafe-destination')

    @contextmanager
    def _locked(self):
        directory = lock = None
        try:
            directory = self._directory()
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            try:
                lock = os.open(self.lockname, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
            except FileExistsError:
                lock = os.open(self.lockname, flags, dir_fd=directory)
            else:
                os.fchown(lock, self.trusted_uid, -1)
                os.fchmod(lock, 0o600)
            self._regular(os.fstat(lock))
            deadline = time.monotonic() + LOCK_WAIT_SECONDS
            while True:
                if time.monotonic() >= deadline:
                    raise DeliveryError('lock-timeout')
                if try_exclusive_lock(lock):
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DeliveryError('lock-timeout')
                time.sleep(min(LOCK_POLL_SECONDS, remaining))
            # Do not proceed to any mutation after the acquisition budget expired.
            if time.monotonic() >= deadline:
                raise DeliveryError('lock-timeout')
            self._regular(os.fstat(lock))
            if _stamp(os.fstat(lock)) != _stamp(os.stat(self.lockname, dir_fd=directory, follow_symlinks=False)):
                raise DeliveryError('version-conflict')
            yield directory
        except OSError:
            raise DeliveryError('io-failure') from None
        finally:
            if lock is not None:
                os.close(lock)
            if directory is not None:
                os.close(directory)

    def _read(self, directory):
        try:
            fd = os.open(self.filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        except FileNotFoundError:
            return b'', None
        try:
            before = os.fstat(fd)
            self._regular(before)
            if before.st_size > MAX_FILE_BYTES:
                raise DeliveryError('unsupported-file')
            data = bytearray()
            while len(data) <= MAX_FILE_BYTES:
                chunk = os.read(fd, min(65536, MAX_FILE_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > MAX_FILE_BYTES:
                raise DeliveryError('unsupported-file')
            if (_stamp(before) != _stamp(os.fstat(fd))
                    or _stamp(before) != _stamp(os.stat(self.filename, dir_fd=directory, follow_symlinks=False))):
                raise DeliveryError('version-conflict')
            return bytes(data), before
        finally:
            os.close(fd)

    def _version(self, directory, key, st):
        ds = os.fstat(directory)
        return json.dumps([self.directory, self.filename, self.trusted_uid, key,
                           ds.st_dev, ds.st_ino, _stamp(st) if st else None], separators=(',', ':'))

    def prepare(self, key: str) -> Prepared:
        self._key(key)
        with self._locked() as directory:
            raw, st = self._read(directory)
            _, bindings = _bindings(raw)
            return Prepared(key, key in bindings, self._version(directory, key, st))

    inspect = prepare

    def write(self, key: str, value: str, *, overwrite_version: str | None = None) -> Receipt:
        self._key(key)
        if not isinstance(value, str) or len(value) > MAX_VALUE_BYTES:
            raise DeliveryError('unsupported-value')
        try:
            encoded = value.encode('utf-8')
        except UnicodeError:
            encoded = None
        if encoded is None:
            raise DeliveryError('unsupported-value')
        if (len(encoded) > MAX_VALUE_BYTES or '\x00' in value or '${' in value
                or value.endswith('\\')
                or (key.endswith(('_API_KEY', '_TOKEN', '_SECRET', '_KEY')) and not value.isascii())):
            raise DeliveryError('unsupported-value')
        escaped = value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
        line = key + '="' + escaped + '"\n'
        with self._locked() as directory:
            raw, st = self._read(directory)
            text, bindings = _bindings(raw)
            version = self._version(directory, key, st)
            if overwrite_version is not None and overwrite_version != version:
                raise DeliveryError('version-conflict')
            if key in bindings and overwrite_version is None:
                raise DeliveryError('overwrite-required')
            if key in bindings:
                start, end = bindings[key]
                result = text[:start] + line + text[end:]
            else:
                result = text + ('\n' if text and not text.endswith(('\n', '\r')) else '') + line
            payload = result.encode('utf-8')
            if len(payload) > MAX_FILE_BYTES:
                raise DeliveryError('unsupported-file')
            temp = '.' + self.filename + '.' + secrets.token_hex(16) + '.tmp'
            fd = None
            renamed = False
            try:
                fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
                os.fchown(fd, self.trusted_uid, st.st_gid if st else -1)
                os.fchmod(fd, 0o600)
                view = memoryview(payload)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise OSError('write failure')
                    view = view[count:]
                os.fsync(fd)
                fresh_raw, fresh_st = self._read(directory)
                if raw != fresh_raw or version != self._version(directory, key, fresh_st):
                    raise DeliveryError('version-conflict')
                check = self._directory()
                try:
                    if (os.fstat(check).st_dev, os.fstat(check).st_ino) != (os.fstat(directory).st_dev, os.fstat(directory).st_ino):
                        raise DeliveryError('version-conflict')
                finally:
                    os.close(check)
                os.replace(temp, self.filename, src_dir_fd=directory, dst_dir_fd=directory)
                renamed = True
                os.fsync(directory)
                after, after_st = self._read(directory)
                if after_st is None or after != payload or _stamp(after_st) != _stamp(os.fstat(fd)):
                    raise DeliveryError('io-ambiguous')
                return Receipt(key, key in bindings, self._version(directory, key, after_st))
            except DeliveryError:
                if renamed:
                    raise DeliveryError('io-ambiguous') from None
                raise
            except OSError:
                raise DeliveryError('io-ambiguous' if renamed else 'io-failure') from None
            finally:
                if fd is not None:
                    os.close(fd)
                    if not renamed:
                        try:
                            os.unlink(temp, dir_fd=directory)
                        except OSError:
                            pass
