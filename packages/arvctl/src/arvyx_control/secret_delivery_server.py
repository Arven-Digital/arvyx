"""Bounded TLS server for the private receiver (not browser authentication).

The dashboard lives at the existing edge adapter. TLS handshakes run only after
acquiring a worker slot, never in accept(), and fail silently within five seconds.
"""
from __future__ import annotations

import socket
import threading

from .api import BoundedThreadingHTTPServer


class SecretTLSServer(BoundedThreadingHTTPServer):
    handshake_timeout = 5

    def __init__(self, address, handler, context):
        self.tls_context = context
        super().__init__(address, handler, max_workers=8)

    def process_request_thread(self, request, client_address):
        secured = None
        ownership = threading.Lock()
        expired = threading.Event()

        def expire():
            # wrap_socket transfers the descriptor: never target the detached raw
            # socket after wrapping. Serialize that transfer with expiration.
            with ownership:
                expired.set()
                try:
                    (secured if secured is not None else request).shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        deadline = threading.Timer(self.request_lifetime_seconds, expire)
        deadline.daemon = True
        started = False
        try:
            deadline.start()
            started = True
            request.settimeout(self.handshake_timeout)
            with ownership:
                if expired.is_set():
                    return
                secured = self.tls_context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
            secured.do_handshake()
            if not expired.is_set():
                self.finish_request(secured, client_address)
        except Exception:
            # No HTTP sent to unauthenticated TLS peers and no traceback details.
            pass
        finally:
            deadline.cancel()
            if started:
                deadline.join()
            try:
                self.shutdown_request(secured if secured is not None else request)
            finally:
                self._worker_slots.release()

    def handle_error(self, request, client_address):
        pass
