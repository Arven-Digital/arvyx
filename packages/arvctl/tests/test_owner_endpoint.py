"""The owner's local endpoint on both platforms: Unix socket on POSIX, loopback port plus private token on Windows."""
import json
import os
import pathlib
import socket
import tempfile
import threading
import unittest

from arvyx_control import owner_endpoint
from arvyx_control.cockpit_client import receive_frame, send_frame, exchange_deadline, remaining


class OwnerEndpointTests(unittest.TestCase):
    def setUp(self):
        base_dir = os.environ.get("LOCALAPPDATA") if os.name == "nt" else None
        self.base = pathlib.Path(tempfile.mkdtemp(prefix="arvyx-endpoint-", dir=base_dir))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.base, ignore_errors=True))
        self.endpoint = str(self.base / "cockpit.sock")

    def _serve_once(self, listener, seen):
        client, _ = listener.accept()
        with client:
            with exchange_deadline(5) as end:
                raw = receive_frame(client, end, 65536)
                request = json.loads(raw)
                try:
                    listener.authorize(request)
                    seen.append(request)
                    response = {"ok": True}
                except ValueError as exc:
                    response = {"ok": False, "error": str(exc)}
                send_frame(client, json.dumps(response).encode() + b"\n", end, 65536)

    def test_round_trip_with_the_platform_credential(self):
        listener = owner_endpoint.listen(self.endpoint)
        self.addCleanup(listener.close)
        seen = []
        thread = threading.Thread(target=self._serve_once, args=(listener, seen), daemon=True)
        thread.start()
        with exchange_deadline(5) as end:
            client, token = owner_endpoint.connect(self.endpoint, remaining(end))
            with client:
                envelope = {"operation": "ping"}
                if token is not None:
                    envelope[owner_endpoint.TOKEN_FIELD] = token
                send_frame(client, json.dumps(envelope).encode() + b"\n", end, 65536)
                self.assertEqual(json.loads(receive_frame(client, end, 65536)), {"ok": True})
        thread.join(5)
        self.assertEqual(seen, [{"operation": "ping"}])  # the token never reaches the operation
        if os.name == "nt":
            self.assertIsNotNone(token)
            self.assertIsNotNone(listener.token)
        else:
            self.assertIsNone(token)
            self.assertIsNone(listener.token)

    @unittest.skipUnless(os.name == "nt", "loopback token is the Windows credential")
    def test_wrong_or_missing_token_is_refused_on_windows(self):
        listener = owner_endpoint.listen(self.endpoint)
        self.addCleanup(listener.close)
        for envelope in ({"operation": "ping"}, {"operation": "ping", owner_endpoint.TOKEN_FIELD: "nope"}):
            seen = []
            thread = threading.Thread(target=self._serve_once, args=(listener, seen), daemon=True)
            thread.start()
            with exchange_deadline(5) as end:
                client, _token = owner_endpoint.connect(self.endpoint, remaining(end))
                with client:
                    send_frame(client, json.dumps(envelope).encode() + b"\n", end, 65536)
                    response = json.loads(receive_frame(client, end, 65536))
            thread.join(5)
            self.assertFalse(response["ok"])
            self.assertIn("token", response["error"])
            self.assertEqual(seen, [])

    @unittest.skipUnless(os.name == "nt", "the endpoint record is a private file on Windows")
    def test_endpoint_record_is_private_and_removed_on_close(self):
        from arvyx_control import windows_acl
        listener = owner_endpoint.listen(self.endpoint)
        record = pathlib.Path(self.endpoint)
        self.assertIsNone(windows_acl.private_path_problem(record))
        self.assertEqual(json.loads(record.read_bytes())["host"], "127.0.0.1")
        listener.close()
        self.assertFalse(record.exists())

    @unittest.skipIf(os.name == "nt", "Unix socket mode is the POSIX credential")
    def test_unix_socket_is_owner_only(self):
        import stat
        listener = owner_endpoint.listen(self.endpoint)
        self.addCleanup(listener.close)
        info = os.lstat(self.endpoint)
        self.assertTrue(stat.S_ISSOCK(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode) & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
