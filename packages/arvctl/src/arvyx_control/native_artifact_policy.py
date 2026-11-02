"""Pinned native bytes; execution is exclusively through sealed Linux snapshots.

Build receipts cannot enroll another digest. No filesystem pathname is execution
 authority. Unsupported sealing platforms fail closed rather than fall back.
"""
try:
    import fcntl
except ImportError:  # Unsupported native platform: inspection may still import.
    fcntl = None
import hashlib
import os
import stat
import platform
import sys
from pathlib import Path
from .agent_sessions import RoutingError

NATIVE_MOUSE_BINARY_SHA256='c8cd3a11b577a23dc37b34f64814e37242e4d2af27726149e3feed6c21c0fd5a'
# Reproducible source build of herdr 5bd900d8 with the Arvyx onboarding overlay
# (frontends/arvyx), admitted 2026-11-02 under the owner's production directive.
# Receipt: frontends/arvyx/receipts/onboarding-v1-linux-x86_64.json (cargo 1.96.1,
# zig 0.16.0, native shell tests executed). Admission is byte-exact; it is not
# runtime acceptance on any machine other than the ones that ran the receipts.
NATIVE_ONBOARDING_BINARY_SHA256='4c29b4d9f65f35c566acadc729d03334be5458520f747db82f8c795ba6d1a3ca'
MAX_NATIVE_BYTES = 128 * 1024 * 1024


def admitted_native_artifacts():
    """Exact admitted digests and the capabilities each carries, read at call time."""
    return {
        NATIVE_MOUSE_BINARY_SHA256: frozenset({'mouse-existing'}),
        NATIVE_ONBOARDING_BINARY_SHA256: frozenset({'mouse-existing', 'onboarding-v1'}),
    }


def native_platform_policy():
    """Source and installer share the admitted architecture/capability policy."""
    identifier=sys.platform+'-'+platform.machine().lower()
    if sys.platform!='linux' or platform.machine() not in ('x86_64','AMD64'):
        return dict(platform=identifier,available=False,capabilities=[],reason='No independently admitted artifact and sealed execution implementation for this platform.')
    admitted=admitted_native_artifacts()
    capabilities=sorted(set().union(*admitted.values()))
    return dict(platform='linux-x86_64',available=True,capabilities=capabilities,binary_sha256=NATIVE_MOUSE_BINARY_SHA256,
                onboarding_binary_sha256=NATIVE_ONBOARDING_BINARY_SHA256,
                artifacts={digest:sorted(caps) for digest,caps in admitted.items()})
_SEALS = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
          if all(hasattr(fcntl, name) for name in (
              'F_SEAL_WRITE', 'F_SEAL_GROW', 'F_SEAL_SHRINK', 'F_SEAL_SEAL',
              'F_ADD_SEALS', 'F_GET_SEALS')) else None)


def open_native_directory(path):
    """Return a pinned, no-follow directory with the artifact ancestor policy."""
    path = Path(os.path.abspath(path))
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
            info = os.fstat(directory)
            if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
                raise RoutingError('unsafe native artifact ancestor')
        return directory
    except BaseException:
        os.close(directory)
        raise


def read_native_bytes(binary):
    """Walk no-follow directory descriptors, then read a bounded regular file."""
    path = Path(os.path.abspath(binary))
    directory = open_native_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111 or not 0 < info.st_size <= MAX_NATIVE_BYTES:
                raise RoutingError('bounded regular executable artifact required')
            data = stream.read(MAX_NATIVE_BYTES + 1)
            if len(data) != info.st_size:
                raise RoutingError('native source changed while reading')
            return data
    finally:
        os.close(directory)


def verify_native_artifact(binary, binding=None, *, required_capability=None):
    """Inspection only; launch callers must retain VerifiedNative instead."""
    return verify_native_bytes(read_native_bytes(binary), binding, required_capability=required_capability)


def verify_native_bytes(data, binding=None, *, required_capability=None):
    policy=native_platform_policy()
    if not policy['available']:
        raise RoutingError(policy['reason'])
    digest=hashlib.sha256(data).hexdigest()
    admitted=admitted_native_artifacts()
    if digest not in admitted:
        raise RoutingError('unapproved native mouse artifact; build provenance is not runtime acceptance')
    if binding is not None and digest!=binding.get('binary_sha256'):
        raise RoutingError('native artifact does not match the exact frontend binding')
    if required_capability is not None and required_capability not in admitted[digest]:
        raise RoutingError('approved native artifact lacks the requested capability; new builds require independent approval')
    return digest


def admitted_capabilities(digest):
    """Capabilities admitted for an exact digest (empty for an unknown digest)."""
    return sorted(admitted_native_artifacts().get(digest, frozenset()))


class VerifiedNative:
    """Own one sealed object across server, CLI, attach and watcher subprocesses."""
    def __init__(self, binary=None, binding=None, *, required_capability=None, inherited_fd=None):
        self.fd = None
        if _SEALS is None or not all(hasattr(os, name) for name in ('memfd_create', 'MFD_ALLOW_SEALING', 'MFD_CLOEXEC')):
            raise RoutingError('native artifact sealing unavailable on this platform')
        fd = None
        try:
            if inherited_fd is None:
                data = read_native_bytes(binary)
                verify_native_bytes(data, binding, required_capability=required_capability)
                fd = os.memfd_create('amc-approved-native', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                view = memoryview(data)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise OSError('short native snapshot write')
                    view = view[count:]
                os.fchmod(fd, 0o500)
                fcntl.fcntl(fd, fcntl.F_ADD_SEALS, _SEALS)
            else:
                fd = os.dup(inherited_fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_NATIVE_BYTES
                    or fcntl.fcntl(fd, fcntl.F_GET_SEALS) & _SEALS != _SEALS):
                raise RoutingError('sealed bounded native descriptor required')
            # Check the final sealed object, including inherited watcher objects.
            data = os.pread(fd, info.st_size + 1, 0)
            self.digest = verify_native_bytes(data, binding, required_capability=required_capability)
            self.fd = fd
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise

    @property
    def path(self):
        if self.fd is None:
            raise RoutingError('native snapshot already closed')
        return f'/proc/self/fd/{self.fd}'

    def invoke(self, operation, args, **kwargs):
        return operation([self.path, *args], pass_fds=(self.fd,), **kwargs)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
