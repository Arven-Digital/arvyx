from __future__ import annotations
from arvyx_control.replica_authority import authority_context

import base64
from datetime import UTC
from datetime import datetime
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from arvyx_control.api import make_handler
from arvyx_control.audit_log import append_audit
from arvyx_control.auth import issue_token
from arvyx_control.control import create_task, list_bus_messages
from arvyx_control.health import report_failures_to_bus, run_health
from arvyx_control.recall import recall
from arvyx_control.replica import (
    REPLICA_MARKER,
    REPLICA_STATUS,
    replica_status,
    sync_replica,
)
from arvyx_control.vault import init_vault


def _serve(vault: Path, state: Path, **kwargs):
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(vault=vault, state=state, **kwargs))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_port}"


def _stop(server, thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


class ReplicationTests(unittest.TestCase):
    def test_replica_sync_round_trip_and_failover_recall(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            primary = Path(tmp) / "primary"
            replica = Path(tmp) / "replica"
            state = Path(tmp) / "state" / "control-events.jsonl"
            init_vault(primary)
            with authority_context(primary, state):
                create_task(state=state, title="Replicated task", owner="demobot")
            token = issue_token(primary, "demobot", scopes=["replica.read"]).token

            server, thread, base = _serve(primary, state)
            try:
                first = sync_replica(base, replica, token=token, state_dir=Path(tmp) / "replica-state")
                self.assertTrue(first.fetched)
                self.assertIn("control-events.jsonl", first.state_fetched)

                # incremental: nothing changed, nothing fetched
                second = sync_replica(base, replica, token=token)
                self.assertEqual(second.fetched, [])
                self.assertGreater(second.unchanged, 0)

                # primary edits propagate; local divergence is repaired
                status_doc = primary / "projects" / "demo-agent" / "STATUS.md"
                addition = "\n- The zephyr quorum is three machines.\n"
                status_doc.write_text(status_doc.read_text(encoding="utf-8") + addition, encoding="utf-8")
                (replica / "projects" / "demo-agent" / "DECISIONS.md").write_text("tampered", encoding="utf-8")
                third = sync_replica(base, replica, token=token)
                self.assertIn("projects/demo-agent/STATUS.md", third.fetched)
                self.assertIn("projects/demo-agent/DECISIONS.md", third.fetched)
            finally:
                _stop(server, thread)

            # failover: recall works straight off the replica vault
            result = recall("what is the zephyr quorum", vault=replica, project="demo-agent")
            self.assertTrue(any("STATUS.md" in source.path for source in result.sources))

            # agent token hashes replicated with the registry, so issued
            # tokens keep working after promotion
            self.assertTrue((replica / "registry" / "tokens" / "demobot.json").is_file())

            status = replica_status(replica)
            self.assertTrue(status.is_replica)
            self.assertIsNotNone(status.age_seconds)

    def test_replica_endpoints_require_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            primary = Path(tmp) / "primary"
            init_vault(primary)
            state = Path(tmp) / "events.jsonl"
            weak_token = issue_token(primary, "demobot", scopes=["memory.read"]).token
            server, thread, base = _serve(primary, state)
            try:
                request = Request(
                    f"{base}/replica/manifest",
                    headers={"Authorization": f"Bearer {weak_token}"},
                    method="GET",
                )
                with self.assertRaises(HTTPError) as caught:
                    urlopen(request, timeout=5)
                self.assertEqual(caught.exception.code, 403)

                # unauthenticated is denied too: the full vault includes
                # lanes recall deliberately excludes
                with self.assertRaises(HTTPError) as caught:
                    urlopen(Request(f"{base}/replica/manifest", method="GET"), timeout=5)
                self.assertEqual(caught.exception.code, 401)
            finally:
                _stop(server, thread)

    def test_markers_are_not_replicated(self) -> None:
        from arvyx_control.replica import build_manifest
        from arvyx_control.vault import VAULT_MARKER

        with tempfile.TemporaryDirectory() as tmp:
            primary = Path(tmp) / "primary"
            replica = Path(tmp) / "replica"
            init_vault(primary)
            self.assertTrue((primary / VAULT_MARKER).is_file())
            manifest = build_manifest(vault=primary)
            self.assertNotIn(VAULT_MARKER, manifest["files"])
            token = issue_token(primary, "backup-1", scopes=["replica.read"]).token

            server, thread, base = _serve(primary, Path(tmp) / "state.jsonl")
            try:
                sync_replica(base, replica, token=token)
            finally:
                _stop(server, thread)
            # the replica must not carry the primary's vault marker, or losing
            # .arvyx-replica would misclassify it as a primary and block re-sync
            self.assertFalse((replica / VAULT_MARKER).is_file())
            self.assertTrue((replica / REPLICA_MARKER).is_file())

    def test_stale_vault_marker_is_reaped_on_resync(self) -> None:
        from arvyx_control.vault import VAULT_MARKER

        with tempfile.TemporaryDirectory() as tmp:
            primary = Path(tmp) / "primary"
            replica = Path(tmp) / "replica"
            init_vault(primary)
            token = issue_token(primary, "backup-1", scopes=["replica.read"]).token
            server, thread, base = _serve(primary, Path(tmp) / "state.jsonl")
            try:
                sync_replica(base, replica, token=token)
                # simulate a replica left carrying the primary marker (pre-fix state)
                (replica / VAULT_MARKER).write_text("arvyx-vault-format: 1\n", encoding="utf-8")
                sync_replica(base, replica, token=token)
            finally:
                _stop(server, thread)
            # the stray primary marker is reaped; the replica's own marker and cache survive
            self.assertFalse((replica / VAULT_MARKER).is_file())
            self.assertTrue((replica / REPLICA_MARKER).is_file())
            self.assertTrue((replica / REPLICA_STATUS).is_file())

    def test_sync_refuses_primary_vault_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            with self.assertRaises(ValueError):
                sync_replica("http://127.0.0.1:1", target)

    def test_state_file_hash_mismatch_is_refused(self) -> None:
        state_bytes = b"tampered state\n"

        class CorruptStateHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/replica/manifest":
                    body = {
                        "schema_version": 1,
                        "files": {},
                        "state_files": {
                            "control-events.jsonl": {"sha256": "0" * 64, "size": len(state_bytes)},
                        },
                    }
                elif self.path.startswith("/replica/state"):
                    body = {
                        "path": "control-events.jsonl",
                        "content_b64": base64.b64encode(state_bytes).decode("ascii"),
                        "size": len(state_bytes),
                    }
                else:
                    body = {"ok": True}
                data = json.dumps({"status": 200, "body": body}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: object) -> None:
                return

        with tempfile.TemporaryDirectory() as tmp:
            server = ThreadingHTTPServer(("127.0.0.1", 0), CorruptStateHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with self.assertRaisesRegex(ValueError, "state file hash mismatch"):
                    sync_replica(
                        f"http://127.0.0.1:{server.server_port}",
                        Path(tmp) / "replica",
                        state_dir=Path(tmp) / "replica-state",
                    )
                self.assertFalse((Path(tmp) / "replica-state" / "control-events.jsonl").exists())
            finally:
                _stop(server, thread)

    def test_state_file_missing_hash_is_refused(self) -> None:
        state_bytes = b"state without manifest hash\n"

        class MissingStateHashHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/replica/manifest":
                    body = {
                        "schema_version": 1,
                        "files": {},
                        "state_files": {
                            "control-events.jsonl": {"size": len(state_bytes)},
                        },
                    }
                elif self.path.startswith("/replica/state"):
                    body = {
                        "path": "control-events.jsonl",
                        "content_b64": base64.b64encode(state_bytes).decode("ascii"),
                        "size": len(state_bytes),
                    }
                else:
                    body = {"ok": True}
                data = json.dumps({"status": 200, "body": body}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: object) -> None:
                return

        with tempfile.TemporaryDirectory() as tmp:
            server = ThreadingHTTPServer(("127.0.0.1", 0), MissingStateHashHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with self.assertRaisesRegex(ValueError, "missing sha256"):
                    sync_replica(
                        f"http://127.0.0.1:{server.server_port}",
                        Path(tmp) / "replica",
                        state_dir=Path(tmp) / "replica-state",
                    )
                self.assertFalse((Path(tmp) / "replica-state" / "control-events.jsonl").exists())
            finally:
                _stop(server, thread)

    def test_state_file_deletions_are_propagated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            replica = Path(tmp) / "replica"
            state_dir = Path(tmp) / "replica-state"
            control_bytes = b"control event\n"
            audit_bytes = b"audit event\n"
            include_audit = True

            class StateDeletionHandler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:  # noqa: N802
                    from urllib.parse import urlsplit, parse_qs
                    route = urlsplit(self.path)
                    query = parse_qs(route.query, strict_parsing=True)
                    state_files = {
                        "control-events.jsonl": {
                            "sha256": hashlib.sha256(control_bytes).hexdigest(),
                            "size": len(control_bytes),
                        }
                    }
                    if include_audit:
                        state_files["audit-log.jsonl"] = {
                            "sha256": hashlib.sha256(audit_bytes).hexdigest(),
                            "size": len(audit_bytes),
                        }
                    if self.path == "/replica/manifest":
                        body = {"schema_version": 1, "files": {}, "state_files": state_files}
                    elif route.path == '/replica/state' and query.get('name') == ['control-events.jsonl']:
                        assert query['size'] == [str(len(control_bytes))]
                        assert query['sha256'] == [hashlib.sha256(control_bytes).hexdigest()]
                        body = {
                            "path": "control-events.jsonl",
                            "content_b64": base64.b64encode(control_bytes).decode("ascii"),
                            "size": len(control_bytes),
                        }
                    elif route.path == '/replica/state' and query.get('name') == ['audit-log.jsonl']:
                        assert query['size'] == [str(len(audit_bytes))]
                        assert query['sha256'] == [hashlib.sha256(audit_bytes).hexdigest()]
                        body = {
                            "path": "audit-log.jsonl",
                            "content_b64": base64.b64encode(audit_bytes).decode("ascii"),
                            "size": len(audit_bytes),
                        }
                    else:
                        body = {"ok": True}
                    data = json.dumps({"status": 200, "body": body}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)

                def log_message(self, format: str, *args: object) -> None:
                    return

            server = ThreadingHTTPServer(("127.0.0.1", 0), StateDeletionHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                first = sync_replica(base, replica, state_dir=state_dir)
                self.assertIn("audit-log.jsonl", first.state_fetched)
                self.assertTrue((state_dir / "audit-log.jsonl").exists())
                include_audit = False
                second = sync_replica(base, replica, state_dir=state_dir)
            finally:
                _stop(server, thread)

            self.assertFalse((state_dir / "audit-log.jsonl").exists())
            self.assertIn("audit-log.jsonl", second.state_deleted)

    def test_manifest_reserved_path_is_refused(self) -> None:
        marker_bytes = b"arvyx-vault-format: 1\n"
        marker_hash = hashlib.sha256(marker_bytes).hexdigest()

        class ReservedPathHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/replica/manifest":
                    body = {
                        "schema_version": 1,
                        "files": {
                            ".arvyx-vault": {"sha256": marker_hash, "size": len(marker_bytes)},
                        },
                        "state_files": {},
                    }
                elif self.path.startswith("/replica/file"):
                    body = {
                        "path": ".arvyx-vault",
                        "content_b64": base64.b64encode(marker_bytes).decode("ascii"),
                        "size": len(marker_bytes),
                    }
                else:
                    body = {"ok": True}
                data = json.dumps({"status": 200, "body": body}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: object) -> None:
                return

        with tempfile.TemporaryDirectory() as tmp:
            replica = Path(tmp) / "replica"
            server = ThreadingHTTPServer(("127.0.0.1", 0), ReservedPathHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with self.assertRaisesRegex(ValueError, "path is not replicable"):
                    sync_replica(f"http://127.0.0.1:{server.server_port}", replica)
            finally:
                _stop(server, thread)

            self.assertFalse((replica / ".arvyx-vault").exists())
            self.assertTrue((replica / REPLICA_MARKER).exists())


class HealthCheckTests(unittest.TestCase):
    def test_health_against_live_server_and_bus_alerting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            with authority_context(vault, state):
                server, thread, base = _serve(vault, state)
                try:
                    healthy = run_health(
                        url=base,
                        recall_question="what did we decide about safe mcp bridge",
                        recall_project="demo-agent",
                    )
                    self.assertTrue(healthy.ok, healthy.to_json())
                finally:
                    _stop(server, thread)

                # server is down now: checks fail and an alert lands on the bus
                down = run_health(url=base, timeout=2.0)
                self.assertFalse(down.ok)
                message_id = report_failures_to_bus(state=state, result=down, host_label="test-host")
                self.assertIsNotNone(message_id)
                messages = list_bus_messages(state=state, channel="ops").messages
                self.assertTrue(any(message.severity == "alert" for message in messages))

    def test_health_replica_freshness_and_audit_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            with authority_context(Path(tmp) / "authority-vault"):
                append_audit(log, {"surface": "api", "route": "/x", "decision": "allowed"})

            replica = Path(tmp) / "replica"
            (replica / REPLICA_STATUS).parent.mkdir(parents=True, exist_ok=True)
            (replica / REPLICA_MARKER).write_text("replica-of: test\n", encoding="utf-8")
            def write_status(last_synced_at: str) -> None:
                (replica / REPLICA_STATUS).write_text(
                    json.dumps({"source": "http://primary", "last_synced_at": last_synced_at, "files": 10, "sync_complete": True}),
                    encoding="utf-8",
                )

            now = datetime.now(UTC).replace(microsecond=0)
            write_status(now.isoformat().replace("+00:00", "Z"))
            fresh = run_health(audit_log=log, replica_vault=replica, max_replica_age_minutes=60)
            self.assertTrue(fresh.ok, fresh.to_json())

            stale_time = now.replace(year=now.year - 1)
            write_status(stale_time.isoformat().replace("+00:00", "Z"))
            stale = run_health(audit_log=log, replica_vault=replica, max_replica_age_minutes=60)
            self.assertFalse(stale.ok)

    def test_health_with_no_checks_fails(self) -> None:
        self.assertFalse(run_health().ok)


class FailoverTests(unittest.TestCase):
    def _make_replica(self, tmp: str, last_synced_at: str | None = None, source: str = "http://primary", *, sync_complete: bool | None = True) -> Path:
        replica = Path(tmp) / "replica"
        (replica / REPLICA_STATUS).parent.mkdir(parents=True, exist_ok=True)
        (replica / REPLICA_MARKER).write_text(f"replica-of: {source}\n", encoding="utf-8")
        if last_synced_at is None:
            last_synced_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        (replica / REPLICA_STATUS).write_text(
            json.dumps({"source": source, "last_synced_at": last_synced_at, "files": 3,
                        **({"sync_complete": sync_complete} if sync_complete is not None else {})}),
            encoding="utf-8",
        )
        return replica

    def test_manual_promote_is_unavailable(self) -> None:
        # NOT_EXECUTED: writable promotion is temporarily UNAVAILABLE.
        from arvyx_control.replica import promote_replica, auto_failover
        from arvyx_control.replica_authority import ReplicaAuthorityUnavailable
        with tempfile.TemporaryDirectory() as tmp:
            replica = self._make_replica(tmp)
            before = (replica / REPLICA_MARKER).read_bytes()
            with self.assertRaises(ReplicaAuthorityUnavailable):
                promote_replica(replica, reason="drill")
            self.assertEqual((replica / REPLICA_MARKER).read_bytes(), before)
            self.assertFalse((replica / ".arvyx/failover.json").exists())

    def test_promote_refuses_primary_vault(self) -> None:
        from arvyx_control.replica import promote_replica

        with tempfile.TemporaryDirectory() as tmp:
            primary = Path(tmp) / "vault"
            init_vault(primary)
            with self.assertRaises(ValueError):
                promote_replica(primary)

    def test_auto_failover_source_assertion_rejects_unrelated_primary(self) -> None:
        from arvyx_control.replica import auto_failover
        from unittest.mock import Mock

        with tempfile.TemporaryDirectory() as tmp:
            replica = self._make_replica(tmp)
            probe = Mock(return_value=True)
            result = auto_failover(replica, "http://unrelated", peers=("http://p1",), probe=probe)
            self.assertFalse(result.promoted)
            self.assertEqual(result.reason, "replica-source-mismatch")
            probe.assert_not_called()
            self.assertTrue((replica / REPLICA_MARKER).exists())

    def test_auto_failover_authority_refusal_after_availability_gates(self) -> None:
        # NOT_EXECUTED: exercise completion/freshness/quorum, not force bypass.
        from arvyx_control.replica import auto_failover, replica_status
        from arvyx_control.replica_authority import ReplicaAuthorityUnavailable
        with tempfile.TemporaryDirectory() as tmp:
            replica = self._make_replica(tmp)
            self.assertTrue(replica_status(replica).sync_complete)
            before = (replica / REPLICA_MARKER).read_bytes()
            probes = []
            def probe(url, *args):
                probes.append(url)
                return url == "http://p1"
            with self.assertRaises(ReplicaAuthorityUnavailable):
                auto_failover(replica, "http://primary", peers=("http://p1",), probe=probe)
            self.assertEqual(probes, ["http://primary", "http://p1"])
            self.assertEqual((replica / REPLICA_MARKER).read_bytes(), before)
            self.assertFalse((replica / ".arvyx/failover.json").exists())

    def test_auto_failover_rechecks_source_under_promotion_lock(self) -> None:
        from arvyx_control.replica import auto_failover

        for replacement in ("http://new-primary", None, "http://primary/other"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as tmp:
                replica = self._make_replica(tmp)

                def probe(url, *args):
                    if url == "http://primary":
                        path = replica / REPLICA_STATUS
                        payload = json.loads(path.read_text(encoding="utf-8"))
                        payload["source"] = replacement
                        path.write_text(json.dumps(payload), encoding="utf-8")
                    return url == "http://p1"

                result = auto_failover(replica, "http://primary", peers=("http://p1",), probe=probe)
                self.assertFalse(result.promoted)
                self.assertIn(result.reason, {"replica-source-changed", "replica-source-missing-or-invalid"})
                self.assertTrue((replica / REPLICA_MARKER).exists())

    def test_auto_failover_force_does_not_restore_missing_authority(self) -> None:
        # NOT_EXECUTED: writable promotion is temporarily UNAVAILABLE.
        from arvyx_control.replica import promote_replica, auto_failover
        from arvyx_control.replica_authority import ReplicaAuthorityUnavailable
        with tempfile.TemporaryDirectory() as tmp:
            replica = self._make_replica(tmp)
            before = (replica / REPLICA_MARKER).read_bytes()
            with self.assertRaises(ReplicaAuthorityUnavailable):
                auto_failover(replica, "http://primary", force=True, probe=lambda *a: True)
            self.assertEqual((replica / REPLICA_MARKER).read_bytes(), before)
            self.assertFalse((replica / ".arvyx/failover.json").exists())

    def test_auto_failover_force_still_requires_journal_authority(self) -> None:
        # NOT_EXECUTED: writable promotion is temporarily UNAVAILABLE.
        from arvyx_control.replica import promote_replica, auto_failover
        from arvyx_control.replica_authority import ReplicaAuthorityUnavailable
        with tempfile.TemporaryDirectory() as tmp:
            replica = self._make_replica(tmp)
            before = (replica / REPLICA_MARKER).read_bytes()
            with self.assertRaises(ReplicaAuthorityUnavailable):
                auto_failover(replica, "http://primary", force=True, probe=lambda *a: True)
            self.assertEqual((replica / REPLICA_MARKER).read_bytes(), before)
            self.assertFalse((replica / ".arvyx/failover.json").exists())

    def test_auto_failover_refuses_when_primary_reachable(self) -> None:
        from arvyx_control.replica import auto_failover

        with tempfile.TemporaryDirectory() as tmp:
            replica = self._make_replica(tmp)
            result = auto_failover(replica, "http://primary", probe=lambda *a, **k: True)
            self.assertFalse(result.promoted)
            self.assertEqual(result.reason, "primary-reachable")

    def test_auto_failover_refuses_without_quorum(self) -> None:
        from arvyx_control.replica import auto_failover

        with tempfile.TemporaryDirectory() as tmp:
            replica = self._make_replica(tmp)
            # primary down, both peers unreachable => reachable=1, required=2
            result = auto_failover(
                replica, "http://primary", peers=("http://p1", "http://p2"), probe=lambda *a, **k: False
            )
            self.assertFalse(result.promoted)
            self.assertEqual(result.reason, "no-quorum")
            self.assertEqual((result.quorum_reachable, result.quorum_required), (1, 2))

    def test_auto_failover_refuses_without_peers(self) -> None:
        from arvyx_control.replica import auto_failover

        with tempfile.TemporaryDirectory() as tmp:
            replica = self._make_replica(tmp)
            # primary down, but no --peer configured: quorum is meaningless, refuse
            result = auto_failover(replica, "http://primary", probe=lambda *a, **k: False)
            self.assertFalse(result.promoted)
            self.assertEqual(result.reason, "quorum-requires-peers")

    def test_auto_failover_refuses_unknown_freshness(self) -> None:
        from arvyx_control.replica import REPLICA_STATUS, auto_failover

        with tempfile.TemporaryDirectory() as tmp:
            replica = self._make_replica(tmp)
            (replica / REPLICA_STATUS).unlink()  # marked replica, never successfully synced
            # Missing status fails the completion gate before freshness.
            result = auto_failover(
                replica,
                "http://primary",
                peers=("http://p1",),
                probe=lambda *a, **k: False,
                max_staleness_seconds=3600,
            )
            self.assertFalse(result.promoted)
            self.assertEqual(result.reason, "replica-incomplete")

    def test_auto_failover_quorum_cannot_supply_journal_authority(self) -> None:
        # NOT_EXECUTED: writable promotion is temporarily UNAVAILABLE.
        from arvyx_control.replica import promote_replica, auto_failover
        from arvyx_control.replica_authority import ReplicaAuthorityUnavailable
        with tempfile.TemporaryDirectory() as tmp:
            replica = self._make_replica(tmp)
            before = (replica / REPLICA_MARKER).read_bytes()
            with self.assertRaises(ReplicaAuthorityUnavailable):
                auto_failover(replica, "http://primary", peers=("http://p1",), probe=lambda url, *a: url == "http://p1")
            self.assertEqual((replica / REPLICA_MARKER).read_bytes(), before)
            self.assertFalse((replica / ".arvyx/failover.json").exists())

    def test_auto_failover_refuses_stale_replica(self) -> None:
        from arvyx_control.replica import auto_failover

        with tempfile.TemporaryDirectory() as tmp:
            now = datetime.now(UTC).replace(microsecond=0)
            stale = now.replace(year=now.year - 1).isoformat().replace("+00:00", "Z")
            replica = self._make_replica(tmp, last_synced_at=stale)
            result = auto_failover(
                replica, "http://primary", probe=lambda *a, **k: False, max_staleness_seconds=3600
            )
            self.assertFalse(result.promoted)
            self.assertEqual(result.reason, "replica-stale")

    def test_legacy_and_explicit_incomplete_status_refuse_promotion(self) -> None:
        from arvyx_control.replica import auto_failover

        for completion in (None, False):
            with self.subTest(completion=completion), tempfile.TemporaryDirectory() as tmp:
                replica = self._make_replica(tmp, sync_complete=completion)
                result = auto_failover(replica, "http://primary", peers=("http://p1",),
                                       probe=lambda url, *args: url == "http://p1")
                self.assertFalse(result.promoted)
                self.assertEqual(result.reason, "replica-incomplete")
                self.assertTrue((replica / REPLICA_MARKER).exists())

    def test_complete_status_without_known_age_refuses_as_stale(self) -> None:
        from arvyx_control.replica import auto_failover

        with tempfile.TemporaryDirectory() as tmp:
            replica = self._make_replica(tmp, last_synced_at="invalid")
            result = auto_failover(replica, "http://primary", peers=("http://p1",),
                                   probe=lambda *args: False)
            self.assertEqual(result.reason, "replica-stale")
            self.assertFalse(result.promoted)

    def test_duplicate_and_invalid_peers_rejected_before_any_probe(self) -> None:
        from arvyx_control.replica import auto_failover
        from unittest.mock import Mock

        peer_sets = (
            ("http://p1", "http://p1", "http://p2", "http://p3"),
            ("HTTP://P1:80/", "http://p1"),
            ("http://primary/",), ("file:///p1",), ("http://p1?alias=1",),
        )
        for peers in peer_sets:
            with self.subTest(peers=peers), tempfile.TemporaryDirectory() as tmp:
                replica = self._make_replica(tmp)
                probe = Mock(return_value=True)
                with self.assertRaises(ValueError):
                    auto_failover(replica, "http://primary", peers=peers, probe=probe)
                probe.assert_not_called()
                self.assertTrue((replica / REPLICA_MARKER).exists())

    def test_promotion_refuses_before_durable_publication(self) -> None:
        # NOT_EXECUTED: writable promotion is temporarily UNAVAILABLE.
        from arvyx_control.replica import promote_replica, auto_failover
        from arvyx_control.replica_authority import ReplicaAuthorityUnavailable
        with tempfile.TemporaryDirectory() as tmp:
            replica = self._make_replica(tmp)
            before = (replica / REPLICA_MARKER).read_bytes()
            with self.assertRaises(ReplicaAuthorityUnavailable):
                promote_replica(replica, reason="drill")
            self.assertEqual((replica / REPLICA_MARKER).read_bytes(), before)
            self.assertFalse((replica / ".arvyx/failover.json").exists())

    def test_promotion_refusal_does_not_remove_replica_marker(self) -> None:
        # NOT_EXECUTED: writable promotion is temporarily UNAVAILABLE.
        from arvyx_control.replica import promote_replica, auto_failover
        from arvyx_control.replica_authority import ReplicaAuthorityUnavailable
        with tempfile.TemporaryDirectory() as tmp:
            replica = self._make_replica(tmp)
            before = (replica / REPLICA_MARKER).read_bytes()
            with self.assertRaises(ReplicaAuthorityUnavailable):
                auto_failover(replica, "http://primary", force=True, probe=lambda *a: True)
            self.assertEqual((replica / REPLICA_MARKER).read_bytes(), before)
            self.assertFalse((replica / ".arvyx/failover.json").exists())

    def test_force_cannot_supply_journal_authority(self) -> None:
        # NOT_EXECUTED: writable promotion is temporarily UNAVAILABLE.
        from arvyx_control.replica import promote_replica, auto_failover
        from arvyx_control.replica_authority import ReplicaAuthorityUnavailable
        with tempfile.TemporaryDirectory() as tmp:
            replica = self._make_replica(tmp)
            before = (replica / REPLICA_MARKER).read_bytes()
            with self.assertRaises(ReplicaAuthorityUnavailable):
                auto_failover(replica, "http://primary", force=True, probe=lambda *a: True)
            self.assertEqual((replica / REPLICA_MARKER).read_bytes(), before)
            self.assertFalse((replica / ".arvyx/failover.json").exists())


if __name__ == "__main__":
    unittest.main()
