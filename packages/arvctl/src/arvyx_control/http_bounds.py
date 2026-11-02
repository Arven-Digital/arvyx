"""Direct HTTP(S), no redirects/proxies, bounded total socket lifetime."""
from contextlib import contextmanager
import http.client
import io
import math
import socket
import threading
import time
from types import MethodType

_HTTPS_CONNECTION = http.client.HTTPSConnection
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit


# A stuck platform resolver cannot be cancelled. Bound *all* outstanding
# resolver work (including timed-out calls), with no executor backlog.
_DNS_SLOTS = threading.BoundedSemaphore(4)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('transport deadline exceeded')
    return remaining


def _resolve(host, port, deadline):
    if not _DNS_SLOTS.acquire(timeout=_remaining(deadline)):
        raise TimeoutError('resolver capacity deadline exceeded')
    result = []
    done = threading.Event()
    def resolve():
        try:
            result.append((True, socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)))
        except BaseException as exc:
            result.append((False, exc))
        finally:
            _DNS_SLOTS.release()
            done.set()
    worker = threading.Thread(target=resolve, name='bounded-http-dns', daemon=True)
    try:
        worker.start()
    except BaseException:
        _DNS_SLOTS.release()
        raise
    if not done.wait(_remaining(deadline)):
        raise TimeoutError('DNS deadline exceeded')
    _remaining(deadline)
    ok, value = result[0]
    if not ok:
        raise value
    return value


def _connect_tcp(address, deadline, *, source_address=None, active=None):
    """Resolve and connect all candidates under one non-renewable deadline."""
    addresses = _resolve(address[0], address[1], deadline)
    last_error = None
    for family, kind, proto, _, sockaddr in addresses:
        remaining = _remaining(deadline)
        sock = socket.socket(family, kind, proto)
        if active is not None:
            active[0] = sock
        try:
            sock.settimeout(remaining)
            if source_address:
                sock.bind(source_address)
            sock.settimeout(_remaining(deadline))
            sock.connect(sockaddr)
            sock.settimeout(_remaining(deadline))
            return sock
        except BaseException as exc:
            sock.close()
            if active is not None:
                active[0] = None
            if not isinstance(exc, OSError):
                raise
            last_error = exc
    _remaining(deadline)
    raise last_error or OSError('DNS returned no addresses')


def bounded_tcp_connection(address, timeout):
    """Caller owns the returned socket; DNS shares HTTP's bounded capacity."""
    timeout = float(timeout)
    if not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError('finite bounded transport timeout required')
    return _connect_tcp(address, time.monotonic() + timeout)


class _DeadlineHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        http.client.HTTPConnection.connect(self)
        # Publish the TLS socket before handshake so the deadline callback can
        # interrupt a peer that trickles handshake records indefinitely.
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=self.host, do_handshake_on_connect=False)
        self.sock.settimeout(_remaining(self._transport_deadline))
        self.sock.do_handshake()


def _validate_response_framing(response):
    """Check original header fields, not HTTPResponse's permissive length.

    Equal repeated lengths are unambiguous; comma lists and unsupported
    transfer codings are refused rather than interpreted differently by peers.
    """
    lengths = response.headers.get_all('Content-Length', [])
    transfers = response.headers.get_all('Transfer-Encoding', [])
    if transfers and (lengths or len(transfers) != 1
                      or transfers[0].lower() != 'chunked' or not response.chunked):
        raise ValueError('invalid HTTP response framing; nothing retried')
    normalized = []
    for value in lengths:
        value = value.strip()
        if not value or any(char not in '0123456789' for char in value):
            raise ValueError('invalid HTTP response framing; nothing retried')
        try:
            parsed = int(value)
        except ValueError:
            raise ValueError('invalid HTTP response framing; nothing retried') from None
        normalized.append(parsed)
    if normalized and any(value != normalized[0] for value in normalized):
        raise ValueError('conflicting HTTP response framing; nothing retried')

    no_body = response._method == 'HEAD' or response.status in (204, 304) or 100 <= response.status < 200
    if normalized and not no_body and (response.chunked or response.length != normalized[0]):
        raise ValueError('parser disagrees with HTTP response framing; nothing retried')


def _validate_response_complete(response):
    if response.length not in (None, 0):
        raise ValueError('incomplete HTTP response; nothing retried')
    # read(n) need not close an EOF-delimited response after a short nonempty
    # read. Prove EOF (or the terminal chunk) under the same transport deadline.
    if response.length is None and not response.isclosed():
        if response.read(1) or not response.isclosed():
            raise ValueError('incomplete HTTP response; nothing retried')


def parse_complete_response(raw, max_body_bytes):
    """Parse an already byte-bounded, EOF-collected HTTP response strictly.

    Reuse the streaming transport's framing policy; also reject bytes beyond
    the declared message rather than silently trusting a valid JSON prefix.
    """
    header, separator, _ = raw.partition(b'\r\n\r\n')
    protocol = header.split(b' ', 1)[0]
    if not separator or protocol not in (b'HTTP/1.0', b'HTTP/1.1'):
        raise ValueError('invalid HTTP response headers')

    class Buffer(io.BytesIO):
        def close(self):
            # HTTPResponse closes its file at message end; retain the cursor
            # until the exact wire-consumption check below has completed.
            pass

        def makefile(self, mode):
            return self

    stream = Buffer(raw)
    response = http.client.HTTPResponse(stream, method='GET')
    try:
        response.begin()
        _validate_response_framing(response)
        body = response.read(max_body_bytes + 1)
        if len(body) > max_body_bytes:
            raise ValueError('HTTP response body too large')
        _validate_response_complete(response)
        if stream.tell() != len(raw):
            raise ValueError('trailing HTTP response bytes')
        return response.status, body
    finally:
        response.close()
        io.BytesIO.close(stream)


@contextmanager
def bounded_connection(connection, timeout):
    """One non-renewable deadline from DNS through caller body consumption.

    Keep the caller's CA/hostname/client-certificate context intact. Publish
    TLS before handshake so expiry can interrupt handshake as well as HTTP.
    """
    timeout = float(timeout)
    if not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError('finite bounded transport timeout required')
    if isinstance(connection, _HTTPS_CONNECTION):
        connection.connect = MethodType(_DeadlineHTTPSConnection.connect, connection)
    deadline = time.monotonic() + timeout
    connection._transport_deadline = deadline
    timer = None
    active = [None]
    def expire():
        # During TLS wrapping the raw socket may be detached; include the
        # connection's socket as well as the currently connecting socket.
        for sock in (active[0], connection.sock):
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
    def create_connection(address, timeout=None, source_address=None):
        return _connect_tcp(address, deadline, source_address=source_address, active=active)
    connection._create_connection = create_connection
    try:
        timer = threading.Timer(_remaining(deadline), expire)
        timer.daemon = True
        timer.start()
        connection.connect()
        active[0] = connection.sock
        _remaining(deadline)
        yield connection
        _remaining(deadline)
    finally:
        if timer is not None:
            timer.cancel()
            timer.join()
        connection.close()


class BoundedOpener:
    @contextmanager
    def open(self, request, timeout: float = 10):
        timeout = float(timeout)
        if not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError('finite bounded transport timeout required')
        url = urlsplit(request.full_url)
        if url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password:
            raise ValueError('HTTP(S) destination without embedded credentials required')
        cls = _DeadlineHTTPSConnection if url.scheme == 'https' else http.client.HTTPConnection
        connection = cls(url.hostname, url.port, timeout=timeout)
        response = None
        try:
            with bounded_connection(connection, timeout):
                path = url.path or '/'
                if url.query:path += '?' + url.query
                connection.request(request.get_method(), path, body=request.data, headers=dict(request.header_items()))
                response = connection.getresponse()
                _validate_response_framing(response)
                if not 200 <= response.status < 300:
                    # Redirects are failures; do not contact Location or forward auth.
                    body = response.read(4096) if response.status >= 400 else b''
                    raise HTTPError(request.full_url, response.status, response.reason, response.headers, io.BytesIO(body))
                yield response
                _validate_response_complete(response)
        except HTTPError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise URLError('transport failed or deadline exceeded; nothing retried') from exc
        finally:
            if response is not None:response.close()

