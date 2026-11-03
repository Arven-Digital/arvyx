from __future__ import annotations
from arvyx_control.replica_authority import authority_context

from contextlib import redirect_stdout
from dataclasses import replace as replace_document
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control import dispatcher as dispatcher_module
from arvyx_control.agent_delivery import AgentDeliveryResult, AgentRoute
from arvyx_control.cli import main as cli_main
from arvyx_control.control import create_task
from arvyx_control.dispatcher import (
    ROUTE_DOCUMENT_SCHEMA,
    dispatch_once,
    load_route_document,
    load_routes,
    main as dispatcher_main,
)
from arvyx_control.outbox import enqueue, project_dispatcher_tick, record_dispatcher_tick


NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
ENV = {"DOC_URL": "http://127.0.0.1:9999/wake", "DOC_SECRET": "doc-route-secret"}
ROUTE = AgentRoute("amir", "hermes-webhook", "DOC_URL", "DOC_SECRET")
METADATA = {
    "schema": ROUTE_DOCUMENT_SCHEMA,
    "revision": "2026-08-29-r1",
    "approved_at": "2026-08-29T12:00:00Z",
    "owner": "elin",
}
ROUTES_BODY = {
    "amir": {
        "runtime": "hermes-webhook",
        "url_env": "DOC_URL",
        "credential_env": "DOC_SECRET",
        "timeout_seconds": 10,
    }
}


def _write_document(
    path: Path,
    metadata: dict[str, object] | None = None,
    routes_body: dict[str, object] | None = None,
) -> Path:
    payload: dict[str, object] = dict(metadata or {})
    payload["routes"] = ROUTES_BODY if routes_body is None else routes_body
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


class RouteDocumentTests(unittest.TestCase):
    def test_unknown_top_level_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_document(Path(tmp) / "routes.json", {"distribution": "canary"})
            with self.assertRaisesRegex(ValueError, "unsupported top-level keys: distribution"):
                load_route_document(path)
            with self.assertRaisesRegex(ValueError, "unsupported top-level keys: distribution"):
                load_routes(path)

    def test_unknown_schema_value_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_document(Path(tmp) / "routes.json", {"schema": "v3.agent-delivery-routes/9"})
            with self.assertRaisesRegex(ValueError, "schema must be v2.agent-delivery-routes/1"):
                load_route_document(path)

    def test_empty_or_nonstring_metadata_is_rejected(self) -> None:
        for metadata in ({"revision": ""}, {"owner": " elin "}, {"revision": 7}, {"owner": ""}):
            with self.subTest(metadata=metadata), tempfile.TemporaryDirectory() as tmp:
                path = _write_document(Path(tmp) / "routes.json", metadata)
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    load_route_document(path)

    def test_malformed_approved_at_is_rejected(self) -> None:
        for approved_at in ("yesterday", "2026-08-29T12:00:00", "2026-13-01T00:00:00Z"):
            with self.subTest(approved_at=approved_at), tempfile.TemporaryDirectory() as tmp:
                path = _write_document(Path(tmp) / "routes.json", {"approved_at": approved_at})
                with self.assertRaisesRegex(ValueError, "approved_at must be a timezone-aware RFC3339"):
                    load_route_document(path)
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_document(Path(tmp) / "routes.json", {"approved_at": "2026-08-29T12:00:00+00:00"})
            self.assertEqual(load_route_document(path).approved_at, "2026-08-29T12:00:00+00:00")

    def test_previous_breadcrumb_is_validated_and_surfaced(self) -> None:
        valid_hash = "c" * 64
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_document(
                Path(tmp) / "routes.json",
                {**METADATA, "previous": {"revision": "2026-08-20-r4", "sha256": valid_hash}},
            )
            document = load_route_document(path)
            self.assertEqual(document.previous_revision, "2026-08-20-r4")
            self.assertEqual(document.previous_sha256, valid_hash)
        for previous in (
            {"revision": "2026-08-20-r4"},
            {"revision": "2026-08-20-r4", "sha256": valid_hash, "owner": "elin"},
            {"revision": "", "sha256": valid_hash},
            {"revision": "2026-08-20-r4", "sha256": "abc"},
            {"revision": "2026-08-20-r4", "sha256": "C" * 64},
            "2026-08-20-r4",
        ):
            with self.subTest(previous=previous), tempfile.TemporaryDirectory() as tmp:
                path = _write_document(Path(tmp) / "routes.json", {"previous": previous})
                with self.assertRaises(ValueError):
                    load_route_document(path)

    def test_unversioned_document_loads_and_is_observably_unversioned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_document(Path(tmp) / "routes.json")
            document = load_route_document(path)
            self.assertFalse(document.versioned)
            self.assertEqual(document.schema, "")
            self.assertEqual(document.revision, "")
            self.assertEqual(document.approved_at, "")
            self.assertEqual(document.owner, "")
            self.assertEqual(document.attested_sha256, "")
            self.assertEqual(document.sha256, hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(set(load_routes(path)), {"amir"})
            self.assertEqual(document.routes["amir"].url_env, "DOC_URL")

    def test_versioned_document_hashes_raw_file_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_document(Path(tmp) / "routes.json", METADATA)
            document = load_route_document(path)
            self.assertTrue(document.versioned)
            self.assertEqual(document.revision, "2026-08-29-r1")
            self.assertEqual(document.sha256, hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(document.attested_sha256, document.sha256)
            # canonical content is the exact byte stream: a whitespace-only
            # rewrite is a different attested document.
            reserialized = json.dumps(json.loads(path.read_text(encoding="utf-8")), indent=2)
            rewritten = Path(tmp) / "rewritten.json"
            rewritten.write_text(reserialized, encoding="utf-8")
            self.assertNotEqual(load_route_document(rewritten).sha256, document.sha256)


class DispatcherTickAttestationTests(unittest.TestCase):
    def test_tick_persists_and_projects_route_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                record_dispatcher_tick(
                    state,
                    configured_targets={"amir"},
                    route_revision="2026-08-29-r1",
                    route_sha256="a" * 64,
                    now=NOW,
                )
                tick = project_dispatcher_tick(state)
                self.assertTrue(tick["initialized"])
                self.assertEqual(tick["route_revision"], "2026-08-29-r1")
                self.assertEqual(tick["route_sha256"], "a" * 64)

    def test_legacy_tick_without_attestation_projects_empty_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                record_dispatcher_tick(state, configured_targets={"amir"}, now=NOW)
                row = json.loads(state.read_text(encoding="utf-8"))
                del row["payload"]["route_revision"]
                del row["payload"]["route_sha256"]
                state.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
                tick = project_dispatcher_tick(state)
                self.assertTrue(tick["initialized"])
                self.assertEqual(tick["route_revision"], "")
                self.assertEqual(tick["route_sha256"], "")

    def test_malformed_tick_attestation_fails_closed(self) -> None:
        for value in (5, "abc", "Z" * 64):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / "events.jsonl"
                vault = Path(tmp) / "authority-vault"
                vault.mkdir(exist_ok=True)
                with authority_context(vault, state):
                    record_dispatcher_tick(state, configured_targets={"amir"}, now=NOW)
                    row = json.loads(state.read_text(encoding="utf-8"))
                    row["payload"]["route_sha256"] = value
                    state.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "route attestation is malformed"):
                        project_dispatcher_tick(state)

    def test_dispatch_once_records_route_attestation_in_tick(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                enqueue(
                    state,
                    subject_id="handoff_1",
                    target="amir",
                    payload={"source_event_id": "event_1", "source_event_type": "handoff.created"},
                    now=NOW,
                )
                document_sha = "b" * 64
                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    deliverer=lambda *_args, **_kwargs: AgentDeliveryResult(True, "accepted", 202, "accepted"),
                    route_revision="2026-08-29-r1",
                    route_sha256=document_sha,
                )
                self.assertTrue(result.ok)
                tick = project_dispatcher_tick(state)
                self.assertEqual(tick["route_revision"], "2026-08-29-r1")
                self.assertEqual(tick["route_sha256"], document_sha)

    def test_dispatcher_main_emits_loaded_route_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                routes = _write_document(Path(tmp) / "routes.json", METADATA)
                expected_sha = hashlib.sha256(routes.read_bytes()).hexdigest()
                create_task(state, "Versioned dispatch", owner="amir")
                deliver_after = (
                    (datetime.now(timezone.utc) - timedelta(hours=1))
                    .isoformat()
                    .replace("+00:00", "Z")
                )
                output = io.StringIO()
                with patch.dict(
                    os.environ,
                    {"DOC_URL": "https://runtime.invalid/hook", "DOC_SECRET": "doc-route-secret"},
                    clear=False,
                ):
                    with redirect_stdout(output):
                        code = dispatcher_main(
                            ["--vault", str(vault),
                                "--state", str(state),
                                "--routes", str(routes),
                                "--deliver-after", deliver_after,
                                "--worker", "attested-worker",
                                "--dry-run",
                            ]
                        )
                report = json.loads(output.getvalue())
                self.assertEqual(code, 0)
                self.assertTrue(report["dry_run"])
                self.assertEqual(report["route_revision"], "2026-08-29-r1")
                self.assertEqual(report["route_sha256"], expected_sha)
                self.assertNotIn("doc-route-secret", output.getvalue())


class RoutesDoctorCliTests(unittest.TestCase):
    def _doctor(self, *arguments: str) -> tuple[int, str]:
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli_main(["routes", "doctor", *arguments])
        return code, output.getvalue()

    def test_doctor_happy_path_reports_document_without_secret_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json", METADATA)
            with patch.dict(
                os.environ,
                {"DOC_URL": "http://127.0.0.1:9/hook/doctor-url-capability", "DOC_SECRET": "doctor-credential-value"},
                clear=False,
            ):
                code, out = self._doctor("--routes", str(routes), "--json")
            report = json.loads(out)
            self.assertEqual(code, 0)
            self.assertTrue(report["ok"])
            self.assertEqual(report["validation_errors"], [])
            self.assertEqual(report["document"]["sha256"], hashlib.sha256(routes.read_bytes()).hexdigest())
            self.assertEqual(report["document"]["schema"], ROUTE_DOCUMENT_SCHEMA)
            self.assertEqual(report["document"]["revision"], "2026-08-29-r1")
            self.assertEqual(report["document"]["owner"], "elin")
            self.assertTrue(report["routes"]["amir"]["url_env_present"])
            self.assertTrue(report["routes"]["amir"]["credential_env_present"])
            self.assertNotIn("doctor-credential-value", out)
            self.assertNotIn("doctor-url-capability", out)
            self.assertNotIn("/hook", out)

    def test_doctor_reports_unversioned_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            with patch.dict(
                os.environ,
                {"DOC_URL": "http://127.0.0.1:9/hook", "DOC_SECRET": "doctor-credential-value"},
                clear=False,
            ):
                code, out = self._doctor("--routes", str(routes), "--json")
            report = json.loads(out)
            self.assertEqual(code, 0)
            self.assertFalse(report["document"]["versioned"])
            for field in ("schema", "revision", "approved_at", "owner"):
                self.assertEqual(report["document"][field], "unversioned")

    def test_doctor_missing_env_reference_fails_validation_without_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json", METADATA)
            with patch.dict(os.environ, {}, clear=True):
                code, out = self._doctor("--routes", str(routes), "--json")
            report = json.loads(out)
            self.assertEqual(code, 1)
            self.assertFalse(report["ok"])
            self.assertTrue(any("DOC_URL" in error for error in report["validation_errors"]))
            self.assertFalse(report["routes"]["amir"]["url_env_present"])

    def test_doctor_rejects_invalid_document_with_nonzero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json", {"distribution": "canary"})
            code, out = self._doctor("--routes", str(routes), "--json")
            report = json.loads(out)
            self.assertEqual(code, 2)
            self.assertFalse(report["ok"])
            self.assertIn("unsupported top-level keys", report["error"])

    def test_doctor_probe_reports_host_port_only(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json", METADATA)
            with patch.dict(
                os.environ,
                {
                    "DOC_URL": f"http://127.0.0.1:{port}/hook/doctor-url-capability",
                    "DOC_SECRET": "doctor-credential-value",
                },
                clear=False,
            ):
                code, out = self._doctor("--routes", str(routes), "--probe", "--json")
            report = json.loads(out)
            self.assertEqual(code, 0)
            probe = report["routes"]["amir"]["probe"]
            self.assertTrue(probe["ok"])
            self.assertEqual(probe["endpoint"], f"127.0.0.1:{port}")
            self.assertNotIn("doctor-url-capability", out)
            self.assertNotIn("/hook", out)

    def test_doctor_probe_failure_is_reported_but_exit_stays_zero(self) -> None:
        placeholder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        placeholder.bind(("127.0.0.1", 0))
        refused_port = placeholder.getsockname()[1]
        placeholder.close()
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json", METADATA)
            with patch.dict(
                os.environ,
                {
                    "DOC_URL": f"http://127.0.0.1:{refused_port}/hook",
                    "DOC_SECRET": "doctor-credential-value",
                },
                clear=False,
            ):
                code, out = self._doctor("--routes", str(routes), "--probe", "--json")
            report = json.loads(out)
            self.assertEqual(code, 0)
            self.assertTrue(report["ok"])
            probe = report["routes"]["amir"]["probe"]
            self.assertFalse(probe["ok"])
            self.assertEqual(probe["endpoint"], f"127.0.0.1:{refused_port}")


class RoutesSealCliTests(unittest.TestCase):
    """`routes seal` authors the versioned route document.

    The deployed route directory is bind-mounted read-only into a container
    running as an unprivileged uid and its access is granted by mode/ACL, so a
    seal replaces the file atomically while preserving that metadata, and it
    reports the sha256 it actually wrote (re-loaded from disk) rather than a
    value it claims.
    """

    def _seal(self, *arguments: str) -> tuple[int, str]:
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli_main(["routes", "seal", *arguments])
        return code, output.getvalue()

    def _sealed(self, tmp: str, routes: Path, *extra: str, destination: Path) -> tuple[int, dict, str]:
        code, out = self._seal(
            "--routes", str(routes),
            "--revision", "2026-09-11-r1",
            "--owner", "operator-one",
            "--approved-at", "2026-09-11T05:00:00Z",
            "--out", str(destination),
            *extra,
            "--json",
        )
        return code, json.loads(out), out

    def test_seal_versions_an_unversioned_document_and_reports_the_written_sha(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            destination = Path(tmp) / "sealed.json"
            code, report, out = self._sealed(tmp, routes, destination=destination)

            self.assertEqual(code, 0)
            self.assertTrue(report["ok"])
            self.assertEqual(report["revision"], "2026-09-11-r1")
            self.assertEqual(report["owner"], "operator-one")
            self.assertEqual(report["targets"], ["amir"])
            self.assertFalse(report["dry_run"])

            written = hashlib.sha256(destination.read_bytes()).hexdigest()
            self.assertEqual(report["sha256"], written)
            # the attested value the dispatcher will record is the file hash
            self.assertEqual(report["route_sha256"], written)

            sealed = load_route_document(destination)
            self.assertTrue(sealed.versioned)
            self.assertEqual(sealed.revision, "2026-09-11-r1")
            self.assertEqual(sealed.attested_sha256, written)
            # an unversioned source has no previous revision to name
            self.assertEqual(sealed.previous_revision, "")
            self.assertEqual(report["previous_revision"], "")
            # the routes body survives byte-for-byte and the source is untouched
            self.assertEqual(json.loads(destination.read_text())["routes"], ROUTES_BODY)
            self.assertFalse(load_route_document(routes).versioned)
            # no secret value, only env-var names
            self.assertNotIn("doc-route-secret", out)

    def test_seal_records_the_previous_revision_and_sha256_of_a_versioned_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json", METADATA)
            original = hashlib.sha256(routes.read_bytes()).hexdigest()
            destination = Path(tmp) / "sealed.json"
            code, report, _ = self._sealed(tmp, routes, destination=destination)

            self.assertEqual(code, 0)
            self.assertEqual(report["previous_revision"], METADATA["revision"])
            self.assertEqual(report["previous_sha256"], original)
            sealed = load_route_document(destination)
            self.assertEqual(sealed.previous_revision, METADATA["revision"])
            self.assertEqual(sealed.previous_sha256, original)
            self.assertEqual(json.loads(destination.read_text())["routes"], ROUTES_BODY)

    def test_seal_refuses_the_current_revision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json", METADATA)
            destination = Path(tmp) / "sealed.json"
            code, out = self._seal(
                "--routes", str(routes),
                "--revision", METADATA["revision"],
                "--owner", "operator-one",
                "--approved-at", "2026-09-11T05:00:00Z",
                "--out", str(destination),
                "--json",
            )
            report = json.loads(out)
            self.assertEqual(code, 2)
            self.assertFalse(report["ok"])
            self.assertIn("must differ", report["error"])
            self.assertFalse(destination.exists())

    def test_seal_dry_run_writes_nothing_but_reports_the_planned_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            destination = Path(tmp) / "sealed.json"
            code, report, _ = self._sealed(tmp, routes, "--dry-run", destination=destination)

            self.assertEqual(code, 0)
            self.assertTrue(report["dry_run"])
            self.assertFalse(destination.exists())
            self.assertEqual(len(report["sha256"]), 64)
            self.assertFalse(load_route_document(routes).versioned)

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits")
    def test_seal_in_place_replaces_atomically_and_keeps_the_file_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            os.chmod(routes, 0o640)
            code, out = self._seal(
                "--routes", str(routes),
                "--revision", "2026-09-11-r1",
                "--owner", "operator-one",
                "--approved-at", "2026-09-11T05:00:00Z",
                "--in-place",
                "--json",
            )
            report = json.loads(out)
            self.assertEqual(code, 0)
            self.assertTrue(report["ok"])
            self.assertEqual(report["path"], str(routes))
            self.assertEqual(stat.S_IMODE(routes.stat().st_mode), 0o640)
            document = load_route_document(routes)
            self.assertTrue(document.versioned)
            self.assertEqual(document.attested_sha256, report["sha256"])
            self.assertEqual(json.loads(routes.read_text())["routes"], ROUTES_BODY)

    def test_seal_refuses_to_overwrite_an_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            destination = Path(tmp) / "sealed.json"
            destination.write_text("{}", encoding="utf-8")
            code, report, _ = self._sealed(tmp, routes, destination=destination)

            self.assertEqual(code, 2)
            self.assertFalse(report["ok"])
            self.assertIn("refusing to overwrite", report["error"])
            self.assertEqual(destination.read_text(encoding="utf-8"), "{}")

    def test_seal_requires_exactly_one_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            output = io.StringIO()
            with redirect_stdout(output):
                code_none = cli_main([
                    "routes", "seal", "--routes", str(routes),
                    "--revision", "2026-09-11-r1", "--owner", "operator-one",
                    "--approved-at", "2026-09-11T05:00:00Z", "--json",
                ])
            self.assertEqual(code_none, 2)
            self.assertIn("exactly one of --out or --in-place", output.getvalue())
            output = io.StringIO()
            with redirect_stdout(output):
                code_both = cli_main([
                    "routes", "seal", "--routes", str(routes),
                    "--revision", "2026-09-11-r1", "--owner", "operator-one",
                    "--approved-at", "2026-09-11T05:00:00Z",
                    "--in-place", "--out", str(Path(tmp) / "sealed.json"), "--json",
                ])
            self.assertEqual(code_both, 2)

    def test_seal_rejects_malformed_metadata_and_invalid_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            code, out = self._seal(
                "--routes", str(routes),
                "--revision", " 2026-09-11-r1 ",
                "--owner", "operator-one",
                "--approved-at", "2026-09-11T05:00:00Z",
                "--out", str(Path(tmp) / "sealed.json"),
                "--json",
            )
            self.assertEqual(code, 2)
            self.assertIn("whitespace", json.loads(out)["error"])

            code, out = self._seal(
                "--routes", str(routes),
                "--revision", "2026-09-11-r1",
                "--owner", "operator-one",
                "--approved-at", "2026-09-11 05:00:00",
                "--out", str(Path(tmp) / "sealed.json"),
                "--json",
            )
            self.assertEqual(code, 2)
            self.assertIn("approved_at", json.loads(out)["error"])

            broken = _write_document(Path(tmp) / "broken.json", {"distribution": "canary"})
            code, out = self._seal(
                "--routes", str(broken),
                "--revision", "2026-09-11-r1",
                "--owner", "operator-one",
                "--approved-at", "2026-09-11T05:00:00Z",
                "--out", str(Path(tmp) / "sealed.json"),
                "--json",
            )
            self.assertEqual(code, 2)
            self.assertIn("unsupported top-level keys", json.loads(out)["error"])


    def test_seal_reports_references_it_cannot_resolve_without_refusing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            destination = Path(tmp) / "sealed.json"
            with patch.dict(os.environ, {}, clear=True):
                code, report, _ = self._sealed(tmp, routes, destination=destination)
            self.assertEqual(code, 0)
            # every unresolved reference for the route is listed, not just the
            # first one validation would have stopped at
            self.assertEqual(
                report["unresolved_references"], ["amir: DOC_URL", "amir: DOC_SECRET"]
            )

            destination.unlink()
            with patch.dict(os.environ, ENV, clear=False):
                code, report, _ = self._sealed(tmp, routes, destination=destination)
            self.assertEqual(code, 0)
            self.assertEqual(report["unresolved_references"], [])

    def test_seal_refuses_a_structurally_invalid_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad_runtime = _write_document(
                Path(tmp) / "bad-runtime.json",
                None,
                {"amir": dict(ROUTES_BODY["amir"], runtime="nope")},
            )
            empty_reference = _write_document(
                Path(tmp) / "empty-reference.json",
                None,
                {"amir": dict(ROUTES_BODY["amir"], url_env="")},
            )
            destination = Path(tmp) / "sealed.json"
            for source in (bad_runtime, empty_reference):
                code, out = self._seal(
                    "--routes", str(source),
                    "--revision", "2026-09-11-r1",
                    "--owner", "operator-one",
                    "--approved-at", "2026-09-11T05:00:00Z",
                    "--out", str(destination),
                    "--json",
                )
                report = json.loads(out)
                self.assertEqual(code, 2)
                self.assertFalse(report["ok"])
                self.assertIn("not structurally valid", report["error"])
                self.assertFalse(destination.exists())

    def test_seal_refuses_a_revision_from_the_previous_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            previous = "2026-08-20-r4"
            routes = _write_document(
                Path(tmp) / "routes.json",
                dict(METADATA, previous={"revision": previous, "sha256": "a" * 64}),
            )
            destination = Path(tmp) / "sealed.json"
            code, out = self._seal(
                "--routes", str(routes),
                "--revision", previous,
                "--owner", "operator-one",
                "--approved-at", "2026-09-11T05:00:00Z",
                "--out", str(destination),
                "--json",
            )
            self.assertEqual(code, 2)
            self.assertIn("must not reuse", json.loads(out)["error"])
            self.assertFalse(destination.exists())

    @unittest.skipUnless(os.name == "posix" and shutil.which("setfacl") and shutil.which("getfacl"), "POSIX ACL tools required")
    def test_seal_in_place_preserves_an_acl_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            subprocess.run(
                ["setfacl", "-m", "u:10001:r", str(routes)], check=True, capture_output=True
            )
            before = subprocess.run(
                ["getfacl", "--absolute-names", "-cp", str(routes)], check=True, capture_output=True, text=True
            ).stdout
            self.assertIn("user:10001:r--", before)

            code, out = self._seal(
                "--routes", str(routes),
                "--revision", "2026-09-11-r1",
                "--owner", "operator-one",
                "--approved-at", "2026-09-11T05:00:00Z",
                "--in-place",
                "--json",
            )
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(out)["ok"])
            after = subprocess.run(
                ["getfacl", "--absolute-names", "-cp", str(routes)], check=True, capture_output=True, text=True
            ).stdout
            self.assertIn("user:10001:r--", after)
            self.assertEqual(before, after)

    def test_seal_leaves_the_original_in_place_when_the_staged_file_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            original_bytes = routes.read_bytes()
            real_loader = load_route_document

            def loader(path: Path):
                document = real_loader(path)
                if path != routes:
                    # Simulate a staged file that does not verify (e.g. a
                    # truncated write): the source must survive untouched.
                    return replace_document(document, revision="something-else")
                return document

            with patch("arvyx_control.dispatcher.load_route_document", side_effect=loader):
                code, out = self._seal(
                    "--routes", str(routes),
                    "--revision", "2026-09-11-r1",
                    "--owner", "operator-one",
                    "--approved-at", "2026-09-11T05:00:00Z",
                    "--in-place",
                    "--json",
                )
            self.assertEqual(code, 2)
            self.assertIn("failed verification", json.loads(out)["error"])
            self.assertEqual(routes.read_bytes(), original_bytes)
            self.assertEqual(
                [item.name for item in Path(tmp).iterdir() if item.name.startswith(".")], []
            )


    def test_seal_refuses_table_level_defects_the_dispatcher_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = _write_document(Path(tmp) / "empty.json", None, {})
            reserved = _write_document(Path(tmp) / "reserved.json", None, {"all": ROUTES_BODY["amir"]})
            padded = _write_document(
                Path(tmp) / "padded.json", None, {"amir ": ROUTES_BODY["amir"]}
            )
            destination = Path(tmp) / "sealed.json"
            for source in (empty, reserved, padded):
                code, out = self._seal(
                    "--routes", str(source),
                    "--revision", "2026-09-11-r1",
                    "--owner", "operator-one",
                    "--approved-at", "2026-09-11T05:00:00Z",
                    "--out", str(destination),
                    "--json",
                )
                report = json.loads(out)
                self.assertEqual(code, 2, source)
                self.assertIn("not structurally valid", report["error"])
                self.assertFalse(destination.exists())

    def test_seal_refuses_a_configured_but_invalid_reference_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            destination = Path(tmp) / "sealed.json"
            with patch.dict(
                os.environ,
                {"DOC_URL": "http://evil.example/hook", "DOC_SECRET": "doc-route-secret"},
                clear=False,
            ):
                code, report, _ = self._sealed(tmp, routes, destination=destination)
            self.assertEqual(code, 2)
            self.assertIn("invalid configured references", report["error"])
            self.assertFalse(destination.exists())

    def test_seal_reports_a_blank_reference_value_as_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            destination = Path(tmp) / "sealed.json"
            with patch.dict(
                os.environ,
                {"DOC_URL": "   ", "DOC_SECRET": "doc-route-secret"},
                clear=False,
            ):
                code, report, _ = self._sealed(tmp, routes, destination=destination)
            self.assertEqual(code, 0)
            self.assertEqual(report["unresolved_references"], ["amir: DOC_URL"])

    def test_seal_text_output_names_the_unresolved_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            destination = Path(tmp) / "sealed.json"
            with patch.dict(os.environ, {}, clear=True):
                code, out = self._seal(
                    "--routes", str(routes),
                    "--revision", "2026-09-11-r1",
                    "--owner", "operator-one",
                    "--approved-at", "2026-09-11T05:00:00Z",
                    "--out", str(destination),
                )
            self.assertEqual(code, 0)
            self.assertIn("unresolved_references=2", out)
            self.assertIn("unresolved: amir: DOC_URL", out)
            self.assertIn("unresolved: amir: DOC_SECRET", out)

    def test_seal_refuses_a_source_that_changed_after_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            original_bytes = routes.read_bytes()
            real_loader = load_route_document

            def loader(path: Path):
                document = real_loader(path)
                if path == routes:
                    # The bytes on disk changed after the load that validated
                    # them: the attested table would be one that never passed
                    # validation, so the seal must refuse instead of copying it.
                    return replace_document(document, sha256="b" * 64)
                return document

            with patch("arvyx_control.dispatcher.load_route_document", side_effect=loader):
                code, out = self._seal(
                    "--routes", str(routes),
                    "--revision", "2026-09-11-r1",
                    "--owner", "operator-one",
                    "--approved-at", "2026-09-11T05:00:00Z",
                    "--in-place",
                    "--json",
                )
            self.assertEqual(code, 2)
            self.assertIn("changed while it was being sealed", json.loads(out)["error"])
            self.assertEqual(routes.read_bytes(), original_bytes)

    def test_seal_dry_run_plans_an_in_place_seal_without_a_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            before = routes.read_bytes()
            code, out = self._seal(
                "--routes", str(routes),
                "--revision", "2026-09-11-r1",
                "--owner", "operator-one",
                "--approved-at", "2026-09-11T05:00:00Z",
                "--dry-run",
                "--json",
            )
            report = json.loads(out)
            self.assertEqual(code, 0)
            self.assertTrue(report["dry_run"])
            self.assertEqual(report["path"], str(routes))
            self.assertEqual(routes.read_bytes(), before)


    def test_seal_names_whitespace_in_a_reference_name(self) -> None:
        """A padded reference name must be reported as what it is.

        `validate_agent_route` looks the raw name up, so a padded name reads as
        "not configured" and the operator chases a missing value instead of the
        typo.
        """
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(
                Path(tmp) / "routes.json",
                None,
                {"amir": dict(ROUTES_BODY["amir"], url_env=" DOC_URL")},
            )
            destination = Path(tmp) / "sealed.json"
            code, out = self._seal(
                "--routes", str(routes),
                "--revision", "2026-09-11-r1",
                "--owner", "marlow",
                "--approved-at", "2026-09-11T05:00:00Z",
                "--out", str(destination),
                "--json",
            )
            report = json.loads(out)
            self.assertEqual(code, 2)
            self.assertIn("not structurally valid", report["error"])
            self.assertIn("surrounding whitespace", report["error"])
            self.assertFalse(destination.exists())

    def test_seal_fails_closed_when_the_document_changes_after_the_swap(self) -> None:
        """The report must never carry two different hashes for one document."""
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            real_loader = load_route_document

            def loader(path: Path):
                document = real_loader(path)
                if Path(path) == routes and routes.read_text(encoding="utf-8").find('"revision"') != -1:
                    # the post-swap read sees a document that is no longer the
                    # one that was written and verified
                    return replace_document(document, sha256="c" * 64)
                return document

            with patch("arvyx_control.dispatcher.load_route_document", side_effect=loader):
                code, out = self._seal(
                    "--routes", str(routes),
                    "--revision", "2026-09-11-r1",
                    "--owner", "marlow",
                    "--approved-at", "2026-09-11T05:00:00Z",
                    "--in-place",
                    "--json",
                )
            self.assertEqual(code, 2)
            self.assertIn("changed after the swap", json.loads(out)["error"])

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits and extended attributes")
    def test_seal_applies_metadata_only_after_the_staged_file_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            routes = _write_document(Path(tmp) / "routes.json")
            os.chmod(routes, 0o640)
            calls = []
            real_copy = dispatcher_module._copy_file_metadata

            def recording_copy(source, source_stat, destination):
                staged_mode = stat.S_IMODE(Path(destination).stat().st_mode)
                calls.append(
                    {
                        "source": Path(source),
                        "stat_mode": stat.S_IMODE(source_stat.st_mode),
                        "staged_mode_at_call": staged_mode,
                    }
                )
                return real_copy(source, source_stat, destination)

            with patch("arvyx_control.dispatcher._copy_file_metadata", side_effect=recording_copy):
                code, out = self._seal(
                    "--routes", str(routes),
                    "--revision", "2026-09-11-r1",
                    "--owner", "marlow",
                    "--approved-at", "2026-09-11T05:00:00Z",
                    "--in-place",
                    "--json",
                )
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(out)["ok"])
            self.assertEqual(len(calls), 1)
            # metadata came from the verified observation of the source...
            self.assertEqual(calls[0]["source"], routes)
            self.assertEqual(calls[0]["stat_mode"], 0o640)
            # ...and was applied only once the staged file had been verified,
            # while it still carried the private mkstemp mode.
            self.assertEqual(calls[0]["staged_mode_at_call"], 0o600)
            self.assertEqual(stat.S_IMODE(routes.stat().st_mode), 0o640)


if __name__ == "__main__":
    unittest.main()
