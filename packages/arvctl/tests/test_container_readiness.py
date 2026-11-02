from __future__ import annotations
from arvyx_control.replica_authority import authority_context

from pathlib import Path
import json
import tempfile
import unittest
from unittest import mock

from arvyx_control.audit_log import append_audit
from arvyx_control.container_readiness import check_readiness
from arvyx_control.vault import VAULT_MARKER


class _Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size: int) -> bytes:
        from arvyx_control.container_readiness import _HEALTH_MAX_BYTES
        if size != _HEALTH_MAX_BYTES + 1:
            raise AssertionError('HTTP health read must be byte bounded')
        return b'{"status": 200, "body": {"ok": true}}'


class _BoundedStateReader:
    def __init__(self, handle, max_bytes: int) -> None:
        self._handle = handle
        self._max_bytes = max_bytes

    def __enter__(self):
        self._handle.__enter__()
        return self

    def __exit__(self, *args):
        return self._handle.__exit__(*args)

    def seek(self, *args):
        return self._handle.seek(*args)

    def read(self, size: int = -1) -> bytes:
        if size < 0 or size > self._max_bytes:
            raise AssertionError(f"state readiness read was unbounded: {size}")
        return self._handle.read(size)


class ContainerReadinessTests(unittest.TestCase):
    # Review50 additions: NOT_EXECUTED (no test execution authorized).
    def test_health_bounded_body_and_transport_failures(self):
        from arvyx_control.container_readiness import _HEALTH_MAX_BYTES
        from urllib.error import URLError
        for payload in (b'x' * (_HEALTH_MAX_BYTES + 1), b'[]', b'{bad', b'\xff'):
            with self.subTest(payload_length=len(payload)), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / VAULT_MARKER).write_text('arvyx-vault-format: 1\n')
                response = _Response()
                response.read = mock.Mock(return_value=payload)
                with mock.patch('arvyx_control.container_readiness.BoundedOpener.open', return_value=response) as opener:
                    result = check_readiness(vault=root, state=root/'state', audit_log=root/'audit', health_url='http://localhost/health')
                self.assertFalse(result['ok'])
                self.assertTrue(any('HTTP health failed' in e for e in result['errors']))
                response.read.assert_called_once_with(_HEALTH_MAX_BYTES + 1)
                self.assertEqual(opener.call_args.kwargs['timeout'], 2)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / VAULT_MARKER).write_text('arvyx-vault-format: 1\n')
            with mock.patch('arvyx_control.container_readiness.BoundedOpener.open', side_effect=URLError('DNS/body deadline')):
                result = check_readiness(vault=root, state=root/'state', audit_log=root/'audit', health_url='http://localhost/health')
            self.assertFalse(result['ok'])

    def test_ready_requires_marker_readable_vault_writable_state_and_http(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = root / "vault"
            vault.mkdir()
            (vault / VAULT_MARKER).write_text("arvyx-vault-format: 1\n", encoding="utf-8")
            with mock.patch("arvyx_control.container_readiness.BoundedOpener.open", return_value=_Response()):
                result = check_readiness(
                    vault=vault,
                    state=root / "control-events.jsonl",
                    audit_log=root / "audit-log.jsonl",
                    health_url="http://127.0.0.1:8765/health",
                )
        self.assertTrue(result["ok"])

    def test_missing_marker_or_unwritable_data_blocks_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = root / "vault"
            vault.mkdir()
            with (
                mock.patch("arvyx_control.container_readiness.BoundedOpener.open", return_value=_Response()),
                mock.patch("arvyx_control.container_readiness.os.access", return_value=False),
            ):
                result = check_readiness(
                    vault=vault,
                    state=root / "control-events.jsonl",
                    audit_log=root / "audit-log.jsonl",
                    health_url="http://127.0.0.1:8765/health",
                )
        self.assertFalse(result["ok"])
        self.assertTrue(any("marker" in error for error in result["errors"]))
        self.assertTrue(any("writable" in error for error in result["errors"]))

    def test_non_http_health_url_is_rejected_without_opening_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = root / "vault"
            vault.mkdir()
            (vault / VAULT_MARKER).write_text("arvyx-vault-format: 1\n", encoding="utf-8")
            with mock.patch("arvyx_control.container_readiness.BoundedOpener.open") as opener:
                result = check_readiness(
                    vault=vault,
                    state=root / "control-events.jsonl",
                    audit_log=root / "audit-log.jsonl",
                    health_url="file:///etc/passwd",
                )
        self.assertFalse(result["ok"])
        opener.assert_not_called()

    def test_directory_or_malformed_state_blocks_readiness(self) -> None:
        for malformed in ("directory", "json"):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                vault = root / "vault"
                vault.mkdir()
                (vault / VAULT_MARKER).write_text("arvyx-vault-format: 1\n", encoding="utf-8")
                state = root / "control-events.jsonl"
                if malformed == "directory":
                    state.mkdir()
                else:
                    state.write_text("{not-json}\n", encoding="utf-8")
                with mock.patch("arvyx_control.container_readiness.BoundedOpener.open", return_value=_Response()):
                    result = check_readiness(
                        vault=vault,
                        state=state,
                        audit_log=root / "audit-log.jsonl",
                        health_url="http://127.0.0.1:8765/health",
                    )
                self.assertFalse(result["ok"])
                self.assertTrue(any("state" in error for error in result["errors"]))

    def test_invalid_marker_or_broken_audit_chain_blocks_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = root / "vault"
            vault.mkdir()
            (vault / VAULT_MARKER).write_text("wrong-format\n", encoding="utf-8")
            audit = root / "audit-log.jsonl"
            with authority_context(vault):
                append_audit(audit, {"action": "synthetic"})
            audit.write_text(audit.read_text(encoding="utf-8").replace('"action": "synthetic"', '"action": "tampered"'), encoding="utf-8")
            with mock.patch("arvyx_control.container_readiness.BoundedOpener.open", return_value=_Response()):
                result = check_readiness(
                    vault=vault,
                    state=root / "control-events.jsonl",
                    audit_log=audit,
                    health_url="http://127.0.0.1:8765/health",
                )
        self.assertFalse(result["ok"])
        self.assertTrue(any("marker" in error for error in result["errors"]))
        self.assertTrue(any("audit" in error for error in result["errors"]))

    def test_pending_mutation_outcome_blocks_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = root / "vault"
            vault.mkdir()
            (vault / VAULT_MARKER).write_text("arvyx-vault-format: 1\n", encoding="utf-8")
            audit = root / "audit-log.jsonl"
            with authority_context(vault):
                append_audit(audit, {"phase": "intent", "operation_id": "synthetic-operation"})
            with mock.patch("arvyx_control.container_readiness.BoundedOpener.open", return_value=_Response()):
                result = check_readiness(
                    vault=vault,
                    state=root / "control-events.jsonl",
                    audit_log=audit,
                    health_url="http://127.0.0.1:8765/health",
                )
        self.assertFalse(result["ok"])
        self.assertIn("audit has pending mutation outcomes", result["errors"])

    def test_large_state_log_readiness_reads_only_a_bounded_tail(self) -> None:
        from arvyx_control.container_readiness import _STATE_READINESS_TAIL_BYTES

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = root / "vault"
            vault.mkdir()
            (vault / VAULT_MARKER).write_text("arvyx-vault-format: 1\n", encoding="utf-8")
            state = root / "control-events.jsonl"
            event = json.dumps(
                {
                    "id": "event-1",
                    "type": "bus.message",
                    "task_id": "message-1",
                    "timestamp": "2026-08-10T12:00:00Z",
                    "payload": {},
                }
            ) + "\n"
            repeats = (_STATE_READINESS_TAIL_BYTES // len(event)) + 100
            state.write_text(event * repeats, encoding="utf-8")
            self.assertGreater(state.stat().st_size, _STATE_READINESS_TAIL_BYTES)
            original_open = Path.open

            def bounded_open(path: Path, *args, **kwargs):
                handle = original_open(path, *args, **kwargs)
                mode = args[0] if args else kwargs.get("mode", "r")
                if path == state:
                    if "b" not in mode:
                        handle.close()
                        raise AssertionError("state readiness used an unbounded text read")
                    return _BoundedStateReader(handle, _STATE_READINESS_TAIL_BYTES)
                return handle

            with (
                mock.patch.object(Path, "open", bounded_open),
                mock.patch("arvyx_control.container_readiness.BoundedOpener.open", return_value=_Response()),
            ):
                result = check_readiness(
                    vault=vault,
                    state=state,
                    audit_log=root / "audit-log.jsonl",
                    health_url="http://127.0.0.1:8765/health",
                )
            self.assertTrue(result["ok"], result)

    def test_corrupt_or_torn_state_tail_blocks_readiness(self) -> None:
        valid_record = json.dumps(
            {
                "id": "event-1",
                "type": "bus.message",
                "task_id": "message-1",
                "timestamp": "2026-08-10T12:00:00Z",
                "payload": {},
            }
        )
        for tail in ("{not-json}\n", valid_record):
            with self.subTest(tail=tail), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                vault = root / "vault"
                vault.mkdir()
                (vault / VAULT_MARKER).write_text("arvyx-vault-format: 1\n", encoding="utf-8")
                state = root / "control-events.jsonl"
                state.write_text(valid_record + "\n" + tail, encoding="utf-8")
                with mock.patch("arvyx_control.container_readiness.BoundedOpener.open", return_value=_Response()):
                    result = check_readiness(
                        vault=vault,
                        state=state,
                        audit_log=root / "audit-log.jsonl",
                        health_url="http://127.0.0.1:8765/health",
                    )
                self.assertFalse(result["ok"])
                self.assertIn("state event log is invalid", result["errors"])

    def test_unreadable_state_tail_blocks_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = root / "vault"
            vault.mkdir()
            (vault / VAULT_MARKER).write_text("arvyx-vault-format: 1\n", encoding="utf-8")
            state = root / "control-events.jsonl"
            state.write_text("{}\n", encoding="utf-8")
            original_open = Path.open

            def unreadable_state(path: Path, *args, **kwargs):
                if path == state:
                    raise PermissionError("synthetic unreadable state")
                return original_open(path, *args, **kwargs)

            with (
                mock.patch.object(Path, "open", unreadable_state),
                mock.patch("arvyx_control.container_readiness.BoundedOpener.open", return_value=_Response()),
            ):
                result = check_readiness(
                    vault=vault,
                    state=state,
                    audit_log=root / "audit-log.jsonl",
                    health_url="http://127.0.0.1:8765/health",
                )
            self.assertFalse(result["ok"])
            self.assertIn("state event log is invalid", result["errors"])

    def test_large_complete_legacy_audit_is_ready_after_journal_bootstrap(self) -> None:
        from arvyx_control.audit_log import _READINESS_TAIL_BYTES, append_audit
        from arvyx_control.operation_journal import journal_path

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = root / "vault"
            vault.mkdir()
            (vault / VAULT_MARKER).write_text("arvyx-vault-format: 1\n", encoding="utf-8")
            audit = root / "audit-log.jsonl"
            with authority_context(vault):
                append_audit(
                    audit,
                    {
                        "phase": "intent",
                        "operation_id": "ready-legacy-1",
                        "event_id": "ready-legacy-1:intent",
                    },
                )
            with authority_context(vault):
                append_audit(
                    audit,
                    {
                        "phase": "outcome",
                        "operation_id": "ready-legacy-1",
                        "event_id": "ready-legacy-1:outcome",
                        "decision": "allowed",
                    },
                )
            while audit.stat().st_size <= _READINESS_TAIL_BYTES:
                with authority_context(vault):
                    append_audit(audit, {"action": "noise", "detail": "z" * 4096})
            self.assertFalse(journal_path(audit).exists())
            with mock.patch("arvyx_control.container_readiness.BoundedOpener.open", return_value=_Response()):
                result = check_readiness(
                    vault=vault,
                    state=root / "control-events.jsonl",
                    audit_log=audit,
                    health_url="http://127.0.0.1:8765/health",
                )
            self.assertTrue(result["ok"], result)
            self.assertTrue(journal_path(audit).exists())


if __name__ == "__main__":
    unittest.main()
