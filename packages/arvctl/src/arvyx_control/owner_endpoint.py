"""The owner's local endpoint: a Unix socket on POSIX, a loopback TCP port plus a private token on Windows.

On POSIX the cockpit owner listens on ``<runtime>/cockpit.sock`` (mode 0600): any
process of the same user may connect, nobody else. Windows Python has no
``AF_UNIX``, so the owner listens on ``127.0.0.1`` at an ephemeral port and writes
``<runtime>/cockpit.sock`` as a private *file* (the trusted-set DACL) holding the
port and a fresh random token. A client reads that file, checks that it is still
private, connects to the port and presents the token as the ``_token`` field of its
request envelope; the owner refuses any request without the exact token. The
reachable set is the same as on POSIX: processes that can read the user's private
runtime directory. Loopback TCP is reachable by every local process, which is why
the token, not the port, is the credential.

Both halves keep the existing one-frame protocol (``cockpit_client.send_frame`` /
``receive_frame``); only how the socket is obtained differs.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
from pathlib import Path

_WINDOWS = os.name == "nt"
TOKEN_FIELD = "_token"


class OwnerListener:
    """Listening socket plus the token the owner must require (``None`` on POSIX)."""

    def __init__(self, server: socket.socket, endpoint: str, token: str | None):
        self.server = server
        self.endpoint = endpoint
        self.token = token

    def accept(self):
        return self.server.accept()

    def close(self) -> None:
        try:
            self.server.close()
        finally:
            Path(self.endpoint).unlink(missing_ok=True)

    def authorize(self, request: dict) -> None:
        """Pop ``_token`` from a request envelope and refuse a mismatch (Windows); POSIX ignores it."""
        presented = request.pop(TOKEN_FIELD, None)
        if self.token is None:
            return
        if not isinstance(presented, str) or not secrets.compare_digest(presented, self.token):
            raise ValueError("owner endpoint token missing or wrong; operation not delivered")


def listen(endpoint: str, *, backlog: int = 8) -> OwnerListener:
    """Bind the owner endpoint. POSIX: the Unix socket, mode 0600. Windows: loopback port + private token file."""
    from . import private_paths
    if not _WINDOWS:
        server = socket.socket(socket.AF_UNIX)
        try:
            Path(endpoint).unlink(missing_ok=True)
            server.bind(endpoint)
            private_paths.apply_mode(path=endpoint, mode=0o600)
            server.listen(backlog)
        except BaseException:
            server.close()
            raise
        return OwnerListener(server, endpoint, None)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(backlog)
        token = secrets.token_urlsafe(32)
        record = json.dumps({"schema": 1, "host": "127.0.0.1", "port": server.getsockname()[1], "token": token})
        path = Path(endpoint).absolute()
        path.unlink(missing_ok=True)
        from . import safe_open
        parent = safe_open.open_root(path.parent)
        try:
            # Created owner-only: safe_open applies the trusted-set DACL to the new file.
            fd = safe_open.open_file_at(parent, path.name, write=True, create=True, exclusive=True, mode=0o600)
            try:
                os.write(fd, record.encode("utf-8") + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(parent)
    except BaseException:
        server.close()
        Path(endpoint).unlink(missing_ok=True)
        raise
    return OwnerListener(server, endpoint, token)


def connect(endpoint, timeout: float) -> tuple[socket.socket, str | None]:
    """Connect to the owner endpoint; returns the socket and the token to present (``None`` on POSIX)."""
    if not _WINDOWS:
        client = socket.socket(socket.AF_UNIX)
        try:
            client.settimeout(timeout)
            client.connect(str(endpoint))
        except BaseException:
            client.close()
            raise
        return client, None
    from . import private_paths
    path = Path(endpoint)
    info = path.lstat()
    import stat
    if not stat.S_ISREG(info.st_mode) or not private_paths.owner_private(info, path=path):
        raise OSError("owner endpoint record is not a private regular file")
    with path.open("rb") as handle:
        record = json.loads(handle.read(4096).decode("utf-8"))
    if (not isinstance(record, dict) or record.get("schema") != 1 or record.get("host") != "127.0.0.1"
            or type(record.get("port")) is not int or not isinstance(record.get("token"), str)):
        raise OSError("owner endpoint record is invalid")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.settimeout(timeout)
        client.connect(("127.0.0.1", record["port"]))
    except BaseException:
        client.close()
        raise
    return client, record["token"]
