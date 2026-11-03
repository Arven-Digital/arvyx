from __future__ import annotations
from arvyx_control.replica_authority import authority_context

import os
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from arvyx_control.defaults import DEFAULT_BENCHMARK_CASES
from arvyx_control.defaults import DEFAULT_VAULT
from arvyx_control.defaults import ensure_repo_checkout
from arvyx_control.defaults import resolve_default_benchmark_cases
from arvyx_control.defaults import resolve_default_vault
from arvyx_control.vault import VAULT_MARKER, init_vault
from arvyx_control.security import (
    DENYLIST_ENV,
    contains_literal_secret,
    load_private_denylist,
    load_secret_scan_allowlist,
    multiline_constant_shape_spans,
    private_name_patterns,
    private_patterns,
    python_constant_shape_spans,
    reviewed_line_fingerprint,
)


@unittest.skipUnless(os.name == 'nt', 'Windows byte-range lock backend')
class WindowsLockErrorTests(unittest.TestCase):
    def test_noncontention_error_escapes_without_deadline(self):
        import errno
        from arvyx_control import locks
        handle = mock.Mock()
        handle.fileno.return_value = 77
        failure = OSError(errno.EBADF, 'invalid descriptor')
        with mock.patch.object(locks.msvcrt, 'locking', side_effect=[failure, None]) as acquire, \
             mock.patch.object(locks.time, 'sleep') as sleep:
            with self.assertRaises(OSError) as caught:
                locks._lock(handle)
        self.assertIs(caught.exception, failure)
        self.assertEqual(acquire.call_count, 1)
        sleep.assert_not_called()

    def test_contention_retries_with_backoff_without_deadline(self):
        import errno
        from arvyx_control import locks
        handle = mock.Mock()
        with mock.patch.object(locks.msvcrt, 'locking',
                               side_effect=[OSError(errno.EACCES, 'contended'), None]) as acquire, \
             mock.patch.object(locks.time, 'sleep') as sleep:
            locks._lock(handle)
        self.assertEqual(acquire.call_count, 2)
        sleep.assert_called_once_with(.01)


class PrivateDenylistTests(unittest.TestCase):
    def _complete_scan_policy(self, repo: Path) -> None:
        # Positive audit fixtures need the same mandatory policy inputs as CI.
        import json
        config = repo / 'config'
        config.mkdir(exist_ok=True)
        (config / 'public-release-paths.json').write_text(json.dumps({
            'version': 1, 'paths': {p.relative_to(repo).as_posix(): 'reimplemented-clean-room'
                                    for p in repo.rglob('*') if p.is_file()},
        }), encoding='utf-8')
        denylist = repo / '.arvyx' / 'private-denylist.txt'
        if not denylist.exists():
            denylist.parent.mkdir(exist_ok=True)
            denylist.write_text('synthetic-person-only\n', encoding='utf-8')

    def test_denylist_loads_from_env_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            denylist = Path(tmp) / "deny.txt"
            denylist.write_text("# comment\nsecret-handle\n\nprivate-host\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {DENYLIST_ENV: str(denylist)}):
                terms = load_private_denylist()
        self.assertEqual(terms, ["secret-handle", "private-host"])

    def test_denylist_loads_from_repo_dot_arvyx(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".arvyx").mkdir()
            (repo / ".arvyx" / "private-denylist.txt").write_text("hidden-name\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop(DENYLIST_ENV, None)
                terms = load_private_denylist(repo)
        self.assertEqual(terms, ["hidden-name"])

    def test_private_patterns_match_denylist_terms_and_secret_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            denylist = Path(tmp) / "deny.txt"
            denylist.write_text("secret-handle\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {DENYLIST_ENV: str(denylist)}):
                patterns = private_patterns()
        self.assertTrue(any(p.search("mentions secret-handle here") for p in patterns))
        self.assertTrue(any(p.search("ghp_" + "a" * 24) for p in patterns))
        self.assertFalse(any(p.search("perfectly public text") for p in patterns))

    def test_no_denylist_still_scans_secret_shapes(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(DENYLIST_ENV, None)
            patterns = private_patterns()
        candidate = "api_key = 'abcdefgh12345678'"  # gitleaks:allow -- synthetic detector fixture
        self.assertTrue(any(p.search(candidate) for p in patterns))

    def test_literal_secret_detection_covers_operational_secret_shapes(self) -> None:
        telegram_fixture = "7123456789:AAHabcdefghijklmnopqrstuvwxyz123456"  # gitleaks:allow
        self.assertTrue(contains_literal_secret("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))
        slack_fixture = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"  # gitleaks:allow
        self.assertTrue(contains_literal_secret(telegram_fixture))
        self.assertTrue(contains_literal_secret(slack_fixture))
        self.assertTrue(contains_literal_secret("postgres://admin:SuperSecret123@db.example/app"))
        self.assertTrue(contains_literal_secret("jane.doe@arven.digital"))

    def test_literal_secret_detection_covers_common_package_and_oauth_tokens(self) -> None:
        fixtures = [
            "glpat-" + "a" * 24,
            "gho_" + "b" * 24,
            "npm_" + "c" * 24,
            "pypi-" + "d" * 24,
            "api_key = 'abc!defgh123456'",
        ]
        self.assertTrue(all(contains_literal_secret(value) for value in fixtures))

    def test_python_constant_scan_catches_multiline_literal_assembly(self) -> None:
        source = "value = (\n    'ghp_'\n    + '0123456789abcdefghij0123456789'\n)\n"
        self.assertEqual(python_constant_shape_spans(source), {(2, 3)})

    def test_cross_language_constant_scan_catches_javascript_assembly(self) -> None:
        source = 'const value = "ghp_" +\n  "0123456789abcdefghij0123456789";\n'
        self.assertEqual(multiline_constant_shape_spans(source), {(1, 2)})

    def test_cross_language_constant_scan_does_not_assemble_regex_definitions(self) -> None:
        source = """SECRET_PATTERNS = (\n    r\"sk-[A-Za-z0-9_-]{20,}\",\n    r\"ghp_[A-Za-z0-9_]{20,}\",\n)\n"""
        self.assertEqual(multiline_constant_shape_spans(source), set())

    def test_cross_language_constant_scan_does_not_join_unrelated_literals(self) -> None:
        source = 'title = "public";\npattern = "ghp_[A-Za-z0-9_]{20,}";\n'
        self.assertEqual(multiline_constant_shape_spans(source), set())

    def test_private_context_scan_fails_closed_without_denylist(self) -> None:
        import subprocess

        env = os.environ.copy()
        env.pop(DENYLIST_ENV, None)
        completed = subprocess.run(
            [sys.executable, "scripts/private_context_scan.py"],
            cwd=self.ROOT if hasattr(self, "ROOT") else Path(__file__).resolve().parents[3],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("no private denylist loaded", completed.stderr)

    def test_private_name_patterns_are_case_insensitive_and_term_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            denylist = Path(tmp) / "deny.txt"
            denylist.write_text("Private-Agent\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {DENYLIST_ENV: str(denylist)}):
                patterns = private_name_patterns()
        self.assertTrue(any(pattern.search("PRIVATE-AGENT reviewed this") for pattern in patterns))
        self.assertTrue(any(pattern.search("private-agentbot reviewed this") for pattern in patterns))
        self.assertTrue(any(pattern.search("private-agent2 reviewed this") for pattern in patterns))
        self.assertFalse(any(pattern.search("notprivate-agentized") for pattern in patterns))

    def test_release_mode_uses_identity_boundaries_not_arbitrary_substrings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            denylist = Path(tmp) / "deny.txt"
            denylist.write_text("PrivateName\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {DENYLIST_ENV: str(denylist)}):
                patterns = private_name_patterns(strict=True)
        self.assertFalse(any(pattern.search("prefixPrivateNameOps") for pattern in patterns))
        for text in ('PrivateName', 'PrivateName_bot', 'PrivateName2'):
            self.assertTrue(any(pattern.search(text) for pattern in patterns))

    def test_short_private_name_does_not_match_unrelated_word(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            denylist = Path(tmp) / "deny.txt"
            denylist.write_text("demoid\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {DENYLIST_ENV: str(denylist)}):
                patterns = private_name_patterns()
        self.assertTrue(any(pattern.search("demoidbot") for pattern in patterns))
        self.assertFalse(any(pattern.search("demolition") for pattern in patterns))

    def test_secret_scan_allowlist_uses_path_and_line_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            allowlist = repo / "fixtures" / "secret-scan-allowlist.txt"
            allowlist.parent.mkdir(parents=True)
            fingerprint = reviewed_line_fingerprint(Path("tests/example.py"), "token = 'synthetic-value'")
            allowlist.write_text(
                f"# synthetic test fixture\n{fingerprint} # tests/example.py:1\n",
                encoding="utf-8",
            )
            loaded = load_secret_scan_allowlist(repo)
        self.assertEqual(loaded, {fingerprint})
        self.assertNotEqual(
            fingerprint,
            reviewed_line_fingerprint(Path("tests/example.py"), "token = 'different-value'"),
        )

    def test_audit_scans_test_tree_for_private_terms(self) -> None:
        from arvyx_control.audit import _private_context_check

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            test_file = repo / "packages" / "arvctl" / "tests" / "test_example.py"
            test_file.parent.mkdir(parents=True)
            test_file.write_text("reviewer = 'PRIVATE-AGENT'\n", encoding="utf-8")
            denylist = repo / ".arvyx" / "private-denylist.txt"
            denylist.parent.mkdir(parents=True)
            denylist.write_text("private-agent\n", encoding="utf-8")
            self._complete_scan_policy(repo)
            with mock.patch.dict(os.environ, {DENYLIST_ENV: str(denylist)}):
                result = _private_context_check(repo)
        self.assertFalse(result.ok)
        self.assertEqual(result.findings, ["packages/arvctl/tests/test_example.py:1"])

    def test_audit_scans_utf16_text_and_blocks_invalid_text_encoding(self) -> None:
        from arvyx_control.audit import _private_context_check

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            denylist = repo / ".arvyx" / "private-denylist.txt"
            denylist.parent.mkdir(parents=True)
            denylist.write_text("PrivateName\n", encoding="utf-8")
            utf16 = repo / "notes.md"
            utf16.write_text("PrivateName_bot\n", encoding="utf-16")
            invalid = repo / "broken.md"
            invalid.write_bytes(b"\xff\xfe\x00")
            with mock.patch.dict(os.environ, {DENYLIST_ENV: str(denylist)}):
                result = _private_context_check(repo)
        self.assertFalse(result.ok)
        self.assertIn("notes.md:1", result.findings)
        self.assertIn("broken.md:decode-error", result.findings)

    def test_audit_skips_generated_coverage_databases(self) -> None:
        from arvyx_control.audit import _private_context_check

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            denylist = repo / ".arvyx" / "private-denylist.txt"
            denylist.parent.mkdir(parents=True)
            denylist.write_text("PrivateName\n", encoding="utf-8")
            (repo / ".coverage").write_bytes(b"\x00\xffgenerated-coverage-db")
            (repo / ".coverage.worker-1").write_bytes(b"\x00\xffgenerated-coverage-db")
            self._complete_scan_policy(repo)
            with mock.patch.dict(os.environ, {DENYLIST_ENV: str(denylist)}):
                result = _private_context_check(repo)
        self.assertTrue(result.ok)
        self.assertEqual(result.findings, [])

    def test_audit_scans_bomless_utf16_and_javascript_multiline_assembly(self) -> None:
        from arvyx_control.audit import _private_context_check

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            denylist = repo / ".arvyx" / "private-denylist.txt"
            denylist.parent.mkdir(parents=True)
            denylist.write_text("PrivateName\n", encoding="utf-8")
            (repo / "notes.md").write_bytes("PrivateName_bot\n".encode("utf-16-le"))
            source = 'const value = "ghp_" +\n  "0123456789abcdefghij0123456789";\n'
            (repo / "assembled.js").write_text(source, encoding="utf-8")
            with mock.patch.dict(os.environ, {DENYLIST_ENV: str(denylist)}):
                result = _private_context_check(repo)
        self.assertFalse(result.ok)
        self.assertIn("notes.md:1", result.findings)
        self.assertIn("assembled.js:1", result.findings)

    def test_audit_blocks_undecodable_unknown_suffix(self) -> None:
        from arvyx_control.audit import _private_context_check

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "payload.bin").write_bytes(b"\xff\xfe\xfd")
            result = _private_context_check(repo)
        self.assertFalse(result.ok)
        self.assertIn("payload.bin:decode-error", result.findings)

    def test_multiline_secret_span_cannot_be_partially_allowlisted(self) -> None:
        from arvyx_control.audit import _private_context_check

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            test_file = repo / "tests" / "assembled.py"
            test_file.parent.mkdir(parents=True)
            reviewed_line = bytes.fromhex(
                "20202020276768705f303132333435363738396162636465666768696a3031323334353637383927"
            ).decode("utf-8")
            source = "value = (\n" + reviewed_line + "\n    + '-adjacent-unreviewed-material'\n)\n"
            test_file.write_text(source, encoding="utf-8")
            allowlist = repo / "fixtures" / "secret-scan-allowlist.txt"
            allowlist.parent.mkdir(parents=True)
            allowlist.write_text(
                reviewed_line_fingerprint(test_file.relative_to(repo), reviewed_line) + "\n",
                encoding="utf-8",
            )
            result = _private_context_check(repo)
        self.assertFalse(result.ok)
        self.assertIn("tests/assembled.py:2", result.findings)

    def test_audit_allows_only_fingerprinted_secret_fixtures(self) -> None:
        from arvyx_control.audit import _private_context_check

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            test_file = repo / "packages" / "arvctl" / "tests" / "test_example.py"
            test_file.parent.mkdir(parents=True)
            line = "token = 'synthetic-fixture-value'"
            test_file.write_text(line + "\n", encoding="utf-8")
            allowlist = repo / "fixtures" / "secret-scan-allowlist.txt"
            allowlist.parent.mkdir(parents=True)
            allowlist.write_text(
                reviewed_line_fingerprint(test_file.relative_to(repo), line) + "\n",
                encoding="utf-8",
            )
            self._complete_scan_policy(repo)
            result = _private_context_check(repo)
            test_file.write_text("token = 'changed-unreviewed-value'\n", encoding="utf-8")
            changed = _private_context_check(repo)
        self.assertTrue(result.ok)
        self.assertFalse(changed.ok)

    def test_audit_rejects_stale_secret_fixture_fingerprint(self) -> None:
        from arvyx_control.audit import _private_context_check

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            allowlist = repo / "fixtures" / "secret-scan-allowlist.txt"
            allowlist.parent.mkdir(parents=True)
            stale_line = "token = 'synthetic-value'"  # gitleaks:allow -- stale-fingerprint test
            stale = reviewed_line_fingerprint(Path("tests/missing.py"), stale_line)
            allowlist.write_text(f"{stale} # tests/missing.py:1\n", encoding="utf-8")
            result = _private_context_check(repo)
        self.assertFalse(result.ok)
        self.assertTrue(any("stale" in finding for finding in result.findings))


class PackagedDefaultTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'POSIX mode bits and umask')
    def test_default_vault_survives_index_build_under_group_writable_umask(self):
        # Regression: the index writer created the vault metadata directory with the
        # ambient umask, so the next packaged-default resolution refused its own cache.
        import os, stat, tempfile
        from unittest import mock
        from arvyx_control import defaults
        from arvyx_control.index import load_index
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.umask(0o002)
            try:
                with mock.patch.object(defaults, "_CACHE_ROOT", None), \
                        mock.patch.object(defaults.tempfile, "gettempdir", return_value=tmp), \
                        mock.patch.object(defaults, "DEFAULT_VAULT", Path(tmp) / "absent-checkout-vault"):
                    vault = defaults.resolve_default_vault(defaults.DEFAULT_VAULT)
                    load_index(vault)
                    metadata = vault / ".arvyx"
                    self.assertFalse(stat.S_IMODE(metadata.stat().st_mode) & 0o022)
                    self.assertEqual(defaults.resolve_default_vault(defaults.DEFAULT_VAULT), vault)
            finally:
                os.umask(previous)

    def test_default_vault_materializes_when_checkout_fixture_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                (Path(tmp) / "cache").mkdir(mode=0o700)
                with mock.patch("arvyx_control.defaults._cache_root", return_value=Path(tmp) / "cache"):
                    vault = resolve_default_vault(DEFAULT_VAULT)
                self.assertTrue((vault / VAULT_MARKER).exists())
                self.assertTrue((vault / "projects/demo-agent/STATUS.md").exists())
            finally:
                os.chdir(cwd)

    @unittest.skipUnless(os.name == 'posix', 'POSIX mode bits and umask')
    def test_default_vault_materializes_under_group_writable_umask(self) -> None:
        previous = os.umask(0o002)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                cache = Path(tmp) / "cache"
                cache.mkdir(mode=0o700)
                with mock.patch("arvyx_control.defaults._cache_root", return_value=cache), \
                     mock.patch("arvyx_control.defaults.DEFAULT_VAULT", Path(tmp) / "absent"):
                    vault = resolve_default_vault(Path(tmp) / "absent")
                self.assertTrue((vault / VAULT_MARKER).exists())
                for path in [vault, *vault.rglob("*")]:
                    self.assertFalse(path.lstat().st_mode & 0o022, path)
        finally:
            os.umask(previous)

    @unittest.skipUnless(os.name == 'posix', 'POSIX mode bits and umask')
    def test_preexisting_writable_cache_entry_is_still_refused(self) -> None:
        # Negative control: tightening applies only to the tree just created.
        for kind in ("file", "vault-dir"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                cache = Path(tmp) / "cache"
                cache.mkdir(mode=0o700)
                if kind == "file":
                    planted = cache / "planted"
                    planted.write_text("x", encoding="utf-8")
                else:
                    planted = cache / "synthetic-vault"
                    planted.mkdir()
                    (planted / VAULT_MARKER).write_text("", encoding="utf-8")
                planted.chmod(0o666 if kind == "file" else 0o777)
                with mock.patch("arvyx_control.defaults._cache_root", return_value=cache), \
                     mock.patch("arvyx_control.defaults.DEFAULT_VAULT", Path(tmp) / "absent"):
                    with self.assertRaisesRegex(ValueError, "untrusted entry"):
                        resolve_default_vault(Path(tmp) / "absent")
                self.assertTrue(planted.lstat().st_mode & 0o022)

    def test_default_benchmark_cases_materializes_from_package_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                (Path(tmp) / "cache").mkdir(mode=0o700)
                with mock.patch("arvyx_control.defaults._cache_root", return_value=Path(tmp) / "cache"):
                    cases = resolve_default_benchmark_cases(DEFAULT_BENCHMARK_CASES)
                self.assertTrue(cases.exists())
                self.assertIn('"suite": "synthetic-vault-recall"', cases.read_text(encoding="utf-8"))
            finally:
                os.chdir(cwd)

    def test_repo_checkout_required_for_release_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "--repo must point"):
                ensure_repo_checkout(Path(tmp))


class InitForceGuardTests(unittest.TestCase):
    def test_force_refuses_directory_without_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "not-a-vault"
            target.mkdir()
            (target / "precious.txt").write_text("do not delete", encoding="utf-8")
            with self.assertRaises(ValueError):
                init_vault(target, force=True)
            self.assertTrue((target / "precious.txt").exists())

    def test_force_reinitializes_marked_vault(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "vault"
            init_vault(target)
            (target / "extra.md").write_text("stale", encoding="utf-8")
            result = init_vault(target, force=True)
            self.assertFalse((target / "extra.md").exists())
            self.assertIn(VAULT_MARKER, result.files_created)


class EvidenceHonestyTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[3]

    def test_self_attested_mcp_client_evidence_is_blocked(self) -> None:
        import json
        import subprocess
        from datetime import UTC, datetime

        from arvyx_control.release_host import release_host_report

        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "evidence.json"
            evidence.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "client": "arvyx-cli",
                        "checked_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                        "git_head": subprocess.run(
                            ["git", "rev-parse", "HEAD"],
                            cwd=self.ROOT,
                            text=True,
                            capture_output=True,
                            check=True,
                        ).stdout.strip(),
                        # Well-formed on purpose: this test is about the self-client
                        # rejection, and the evidence must not fail earlier for a
                        # missing tree.
                        "git_tree": subprocess.run(
                            ["git", "rev-parse", "HEAD^{tree}"],
                            cwd=self.ROOT,
                            text=True,
                            capture_output=True,
                            check=True,
                        ).stdout.strip(),
                        "transport": "stdio",
                        "command": "python -m arvyx_control.cli mcp",
                        "result": {
                            "tools_list_ok": True,
                            "recall_ok": True,
                            "sources_returned": True,
                            "private_paths_leaked": False,
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = release_host_report(repo=self.ROOT, mcp_client_evidence=evidence)
        checks = {check.id: check for check in result.checks}
        self.assertEqual(checks["mcp_client_real"].status, "blocked")
        self.assertIn("self client", " ".join(checks["mcp_client_real"].evidence))

    def test_release_status_strings_do_not_clear_blockers_without_attestation(self) -> None:
        from arvyx_control.audit import _release_blockers

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            docs = repo / "docs"
            docs.mkdir()
            (docs / "security-audit.md").write_text("audit-status: complete\n", encoding="utf-8")
            (docs / "release-gate.md").write_text("release-gate-status: complete\n", encoding="utf-8")
            blockers = _release_blockers(repo)

        self.assertIn("security audit multi-model review is missing or invalid", blockers)
        self.assertIn("public release gate multi-model review is missing or invalid", blockers)

    def _make_pinned_signer(self, tmp: str, principal: str = "auditor@ext.example") -> tuple[Path, Path, str]:
        import subprocess

        key = Path(tmp) / "signer_ed25519"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", principal, "-f", str(key)],
            check=True,
            capture_output=True,
        )
        pub = (Path(tmp) / "signer_ed25519.pub").read_text(encoding="utf-8").split()
        allowed = Path(tmp) / "allowed_signers"
        allowed.write_text(f"{principal} {pub[0]} {pub[1]}\n", encoding="utf-8")
        return key, allowed, principal

    def _make_pinned_signers(self, tmp: str, count: int = 2) -> tuple[list[tuple[Path, str]], Path]:
        import subprocess

        signers: list[tuple[Path, str]] = []
        lines: list[str] = []
        for index in range(count):
            principal = f"signer{index}@ext.example"
            key = Path(tmp) / f"signer{index}_ed25519"
            subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", principal, "-f", str(key)],
                check=True,
                capture_output=True,
            )
            pub = (Path(tmp) / f"signer{index}_ed25519.pub").read_text(encoding="utf-8").split()
            lines.append(f"{principal} {pub[0]} {pub[1]}")
            signers.append((key, principal))
        allowed = Path(tmp) / "allowed_signers_multi"
        allowed.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return signers, allowed

    def _external_mcp_payload(self) -> dict[str, object]:
        import subprocess
        from datetime import UTC, datetime

        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.ROOT, text=True, capture_output=True, check=True
        ).stdout.strip()
        tree = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=self.ROOT, text=True, capture_output=True, check=True
        ).stdout.strip()
        return {
            "schema_version": 1,
            "client": "codex",
            # Synthetic protocol fixture, not evidence that an SDK ran here.
            "client_version": "fixture-1",
            "client_provenance": {
                "kind": "third-party-sdk", "distribution": "mcp",
                "version": "fixture-1", "implementation_sha256": "1" * 64,
            },
            "capture_sha256": "2" * 64,
            "capture_bytes": 1,
            "scan_scope": ["initialize", "tools/list", "memory.recall"],
            "checked_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "git_head": head,
            "git_tree": tree,
            "transport": "stdio",
            "command": "python -m arvyx_control.cli mcp --vault fixtures/synthetic-vault",
            "result": {
                "tools_list_ok": True,
                "recall_ok": True,
                "sources_returned": True,
                "private_paths_leaked": False,
            },
        }

    def test_pinned_signer_mcp_evidence_is_accepted(self) -> None:
        import json
        from unittest.mock import patch

        from arvyx_control.mcp_client_evidence import attest_evidence_file
        from arvyx_control.release_host import release_host_report

        with tempfile.TemporaryDirectory() as tmp:
            key, allowed, principal = self._make_pinned_signer(tmp)
            evidence = Path(tmp) / "evidence.json"
            evidence.write_text(json.dumps(self._external_mcp_payload()), encoding="utf-8")
            attest_evidence_file(evidence, key_path=key, principal=principal)
            with (
                patch("arvyx_control.attestation.allowed_signers_path", return_value=allowed),
                patch("arvyx_control.attestation.release_grade_principals", return_value=frozenset({principal})),
            ):
                result = release_host_report(repo=self.ROOT, mcp_client_evidence=evidence)
        checks = {check.id: check for check in result.checks}
        self.assertEqual(checks["mcp_client_real"].status, "complete")

    def test_operator_forge_with_unpinned_key_is_blocked(self) -> None:
        # The whole point of the asymmetric gate: the release operator can sign
        # with THEIR OWN key and even claim the pinned principal's identity, but
        # without the pinned private key the signature never verifies.
        import json
        import subprocess
        from unittest.mock import patch

        from arvyx_control.mcp_client_evidence import attest_evidence_file
        from arvyx_control.release_host import release_host_report

        with tempfile.TemporaryDirectory() as tmp:
            _pinned_key, allowed, principal = self._make_pinned_signer(tmp)
            operator_key = Path(tmp) / "operator_ed25519"
            subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(operator_key)],
                check=True,
                capture_output=True,
            )
            evidence = Path(tmp) / "evidence.json"
            evidence.write_text(json.dumps(self._external_mcp_payload()), encoding="utf-8")
            # Establish the positive using the same payload and effective policy
            # seams, then change only the signing key, not provenance or scope.
            with (
                patch("arvyx_control.attestation.allowed_signers_path", return_value=allowed),
                patch("arvyx_control.attestation.release_grade_principals", return_value=frozenset({principal})),
            ):
                attest_evidence_file(evidence, key_path=_pinned_key, principal=principal)
                valid = release_host_report(repo=self.ROOT, mcp_client_evidence=evidence)
                self.assertEqual(next(check for check in valid.checks if check.id == "mcp_client_real").status, "complete")
                attest_evidence_file(evidence, key_path=operator_key, principal=principal)
                result = release_host_report(repo=self.ROOT, mcp_client_evidence=evidence)
        checks = {check.id: check for check in result.checks}
        self.assertEqual(checks["mcp_client_real"].status, "blocked")
        self.assertEqual(checks["mcp_client_real"].evidence, [
            "attestation invalid: attestation signature is not from a pinned trusted signer",
            "verified attestation is required in release mode",
        ])

    def test_release_model_reviews_require_tree_binding(self) -> None:
        import json
        from arvyx_control.audit import _release_blockers

        with tempfile.TemporaryDirectory() as tmp:
            repo, tree = self._temp_release_repo(tmp)
            reviews = [
                ("openai-codex", "gpt-5.6-sol", "approve"),
                ("xai-oauth", "grok-4.5", "approve-with-findings"),
            ]
            self._write_model_review_attestation(repo, "security-audit", tree, reviews)
            self._write_model_review_attestation(repo, "release-gate", tree, reviews)
            blockers_valid = _release_blockers(repo)
            path = repo / ".arvyx" / "release-reviews" / "security-audit.attestation.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["artifact_git_tree"] = "0" * 40
            path.write_text(json.dumps(payload), encoding="utf-8")
            blockers_tampered = _release_blockers(repo)

        self.assertEqual(blockers_valid, [])
        self.assertIn("security audit multi-model review is missing or invalid", blockers_tampered)

    # --- step 3: CI run-provenance -------------------------------------------

    def _write_provenance(self, provdir: Path, check_id: str, key: Path, principal: str, *, result: str = "pass") -> None:
        import json

        from arvyx_control.attestation import NS_RUN_PROVENANCE, git_tree_sha, sign_payload

        payload: dict[str, object] = {
            "schema_version": 1,
            "check_id": check_id,
            "git_tree": git_tree_sha(self.ROOT),
            "result": result,
            "workflow": "release-provenance.yml@sha",
            "ran_at": "2026-07-15T00:00:00Z",
        }
        payload["attestation"] = sign_payload(payload, key_path=key, principal=principal, namespace=NS_RUN_PROVENANCE)
        (provdir / f"{check_id}.provenance.json").write_text(json.dumps(payload), encoding="utf-8")

    def test_ci_run_provenance_is_accepted(self) -> None:
        from unittest.mock import patch

        from arvyx_control.release_host import release_host_report

        with tempfile.TemporaryDirectory() as tmp:
            key, allowed, principal = self._make_pinned_signer(tmp)
            provdir = Path(tmp) / "prov"
            provdir.mkdir()
            self._write_provenance(provdir, "docker_runtime", key, principal)
            self._write_provenance(provdir, "safe_mcp_bridge_e2e", key, principal)
            with patch("arvyx_control.release_host.allowed_signers_path", return_value=allowed):
                # Pinned but not release-grade: a verifying signature alone is refused.
                with patch("arvyx_control.release_host.release_grade_principals", return_value=frozenset()):
                    refused = release_host_report(repo=self.ROOT, require_provenance=True, provenance_dir=provdir)
                with patch("arvyx_control.release_host.release_grade_principals", return_value=frozenset({principal})):
                    result = release_host_report(repo=self.ROOT, require_provenance=True, provenance_dir=provdir)
        refused_checks = {check.id: check for check in refused.checks}
        for check_id in ("docker_runtime", "safe_mcp_bridge_e2e"):
            self.assertEqual(refused_checks[check_id].status, "blocked")
            self.assertIn("provenance signer is not release-grade", refused_checks[check_id].evidence)
        checks = {check.id: check.status for check in result.checks}
        self.assertEqual(checks["docker_runtime"], "complete")
        self.assertEqual(checks["safe_mcp_bridge_e2e"], "complete")

    def test_operator_cannot_forge_run_provenance(self) -> None:
        import subprocess
        from unittest.mock import patch

        from arvyx_control.release_host import release_host_report

        with tempfile.TemporaryDirectory() as tmp:
            _pinned_key, allowed, principal = self._make_pinned_signer(tmp)
            operator_key = Path(tmp) / "operator_ed25519"
            subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(operator_key)], check=True, capture_output=True
            )
            provdir = Path(tmp) / "prov"
            provdir.mkdir()
            # operator signs provenance with their own (unpinned) key, claiming the pinned id
            self._write_provenance(provdir, "docker_runtime", operator_key, principal)
            with patch("arvyx_control.release_host.allowed_signers_path", return_value=allowed):
                result = release_host_report(repo=self.ROOT, require_provenance=True, provenance_dir=provdir)
        docker = {check.id: check for check in result.checks}["docker_runtime"]
        self.assertEqual(docker.status, "blocked")

    def test_run_provenance_missing_is_blocked(self) -> None:
        from unittest.mock import patch

        from arvyx_control.release_host import release_host_report

        with tempfile.TemporaryDirectory() as tmp:
            _key, allowed, _principal = self._make_pinned_signer(tmp)
            provdir = Path(tmp) / "prov"
            provdir.mkdir()
            with patch("arvyx_control.release_host.allowed_signers_path", return_value=allowed):
                result = release_host_report(repo=self.ROOT, require_provenance=True, provenance_dir=provdir)
        checks = {check.id: check.status for check in result.checks}
        self.assertEqual(checks["docker_runtime"], "blocked")
        self.assertEqual(checks["safe_mcp_bridge_e2e"], "blocked")

    # --- step 4: multi-model release review -----------------------------------

    def _temp_release_repo(self, tmp: str) -> tuple[Path, str]:
        import subprocess

        repo = Path(tmp) / "repo"
        repo.mkdir()

        def git(*args: str) -> None:
            subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)

        subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
        git("config", "user.email", "t@example")
        git("config", "user.name", "t")
        # Review receipts are ignored local evidence, as in the real repository;
        # adding them must not simulate untracked candidate source changes.
        (repo / ".gitignore").write_text(".arvyx/\n", encoding="utf-8")
        docs = repo / "docs"
        docs.mkdir()
        (docs / "security-audit.md").write_text("audit-status: complete\n", encoding="utf-8")
        (docs / "release-gate.md").write_text("release-gate-status: complete\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "init")
        tree = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], text=True, capture_output=True, check=True
        ).stdout.strip()
        return repo, tree

    def _write_model_review_attestation(
        self,
        repo: Path,
        subject: str,
        tree: str,
        reviewers: list[tuple[str, str, str]],
        *,
        synthesis_decision: str = "approve",
    ) -> None:
        import json
        import hashlib

        reviews: list[dict[str, object]] = []
        review_dir = repo / ".arvyx" / "model-reviews"
        review_dir.mkdir(parents=True, exist_ok=True)
        for index, (provider, model, verdict) in enumerate(reviewers):
            report = review_dir / f"{subject}-{index}.md"
            report.write_text(f"# {provider}/{model}\n\nVerdict: {verdict}\n", encoding="utf-8")
            reviews.append(
                {
                    "reviewer_id": f"{provider}/{model}",
                    "provider": provider,
                    "model": model,
                    "verdict": verdict,
                    "reviewed_at": "2026-07-15T00:00:00Z",
                    "scope": ["release diff", "tests", "threat model"],
                    "report_path": report.relative_to(repo).as_posix(),
                    "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
                }
            )
        payload: dict[str, object] = {
            "schema_version": 1,
            "subject": subject,
            "status": "complete",
            "artifact_git_tree": tree,
            "policy_version": "multi-model-review-v1",
            "custody": "operator-authored-unsigned",
            "reviews": reviews,
            "synthesis": {
                "decision": synthesis_decision,
                "synthesizer": "review-orchestrator/gpt-5.6-sol",
                "synthesized_at": "2026-07-15T00:00:00Z",
                "agreements": ["tree binding is correct"],
                "disagreements": [],
                "resolution": "reviewed by the orchestrator",
            },
        }
        receipt_dir = repo / ".arvyx" / "release-reviews"
        receipt_dir.mkdir(parents=True, exist_ok=True)
        (receipt_dir / f"{subject}.attestation.json").write_text(json.dumps(payload), encoding="utf-8")

    def test_single_model_review_fails_minimum(self) -> None:
        from arvyx_control.audit import _release_blockers

        with tempfile.TemporaryDirectory() as tmp:
            repo, tree = self._temp_release_repo(tmp)
            one = [("openai-codex", "gpt-5.6-sol", "approve")]
            two = [*one, ("xai-oauth", "grok-4.5", "approve-with-findings")]
            self._write_model_review_attestation(repo, "security-audit", tree, one)
            self._write_model_review_attestation(repo, "release-gate", tree, two)
            blockers = _release_blockers(repo)
        self.assertIn("security audit multi-model review is missing or invalid", blockers)
        self.assertNotIn("public release gate multi-model review is missing or invalid", blockers)

    def test_duplicate_model_identity_does_not_count_twice(self) -> None:
        from arvyx_control.audit import _release_blockers

        with tempfile.TemporaryDirectory() as tmp:
            repo, tree = self._temp_release_repo(tmp)
            duplicate = [
                ("openai-codex", "gpt-5.6-sol", "approve"),
                ("openai-codex", "gpt-5.6-sol", "approve-with-findings"),
            ]
            self._write_model_review_attestation(repo, "security-audit", tree, duplicate)
            self._write_model_review_attestation(repo, "release-gate", tree, duplicate)
            blockers = _release_blockers(repo)
        self.assertTrue(any("multi-model review is missing or invalid" in blocker for blocker in blockers))

    def test_blocking_model_verdict_blocks_release(self) -> None:
        from arvyx_control.audit import _release_blockers

        with tempfile.TemporaryDirectory() as tmp:
            repo, tree = self._temp_release_repo(tmp)
            reviews = [
                ("openai-codex", "gpt-5.6-sol", "approve"),
                ("xai-oauth", "grok-4.5", "block"),
            ]
            self._write_model_review_attestation(repo, "security-audit", tree, reviews)
            self._write_model_review_attestation(repo, "release-gate", tree, reviews)
            blockers = _release_blockers(repo)
        self.assertTrue(any("multi-model review is missing or invalid" in blocker for blocker in blockers))

    def test_tampered_model_report_hash_blocks_release(self) -> None:
        from arvyx_control.audit import _release_blockers

        with tempfile.TemporaryDirectory() as tmp:
            repo, tree = self._temp_release_repo(tmp)
            reviews = [
                ("openai-codex", "gpt-5.6-sol", "approve"),
                ("xai-oauth", "grok-4.5", "approve-with-findings"),
            ]
            self._write_model_review_attestation(repo, "security-audit", tree, reviews)
            self._write_model_review_attestation(repo, "release-gate", tree, reviews)
            before = _release_blockers(repo)
            report = repo / ".arvyx" / "model-reviews" / "security-audit-0.md"
            report.write_text("tampered\n", encoding="utf-8")
            after = _release_blockers(repo)
        self.assertEqual(before, [])
        self.assertIn("security audit multi-model review is missing or invalid", after)

    def test_invalid_model_review_minimum_fails_closed(self) -> None:
        from unittest.mock import patch

        from arvyx_control.audit import _release_blockers

        with tempfile.TemporaryDirectory() as tmp:
            repo, tree = self._temp_release_repo(tmp)
            reviews = [
                ("openai-codex", "gpt-5.6-sol", "approve"),
                ("xai-oauth", "grok-4.5", "approve"),
            ]
            self._write_model_review_attestation(repo, "security-audit", tree, reviews)
            self._write_model_review_attestation(repo, "release-gate", tree, reviews)
            for invalid_minimum in ("not-an-int", "1", "0", "-1"):
                with self.subTest(invalid_minimum=invalid_minimum):
                    with patch.dict("os.environ", {"ARVYX_RELEASE_MIN_MODEL_REVIEWS": invalid_minimum}):
                        blockers = _release_blockers(repo)
                    self.assertIn("security audit multi-model review is missing or invalid", blockers)
                    self.assertIn("public release gate multi-model review is missing or invalid", blockers)

    def test_model_review_requires_explicit_approve_synthesis(self) -> None:
        from arvyx_control.audit import _release_blockers

        with tempfile.TemporaryDirectory() as tmp:
            repo, tree = self._temp_release_repo(tmp)
            reviews = [
                ("openai-codex", "gpt-5.6-sol", "approve"),
                ("xai-oauth", "grok-4.5", "approve-with-findings"),
            ]
            self._write_model_review_attestation(repo, "security-audit", tree, reviews, synthesis_decision="block")
            self._write_model_review_attestation(repo, "release-gate", tree, reviews)
            blockers = _release_blockers(repo)
        self.assertIn("security audit multi-model review is missing or invalid", blockers)

    def test_model_review_cli_records_two_models_and_synthesis(self) -> None:
        import json

        from arvyx_control.attestation import verify_model_review_attestation
        from arvyx_control.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            repo, _tree = self._temp_release_repo(tmp)
            reports = repo / ".arvyx" / "model-reviews"
            reports.mkdir(parents=True)
            sol = reports / "sol.md"
            grok = reports / "grok.md"
            sol.write_text("## Verdict\n\napprove\n", encoding="utf-8")
            grok.write_text("## Verdict\n\napprove-with-findings\n", encoding="utf-8")

            common = [
                "attest",
                "model-review",
                "--subject",
                "release-gate",
                "--repo",
                str(repo),
                "--scope",
                "release diff",
            ]
            self.assertEqual(
                main(
                    [
                        *common,
                        "--provider",
                        "openai-codex",
                        "--model",
                        "gpt-5.6-sol",
                        "--verdict",
                        "approve",
                        "--report",
                        str(sol),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        *common,
                        "--provider",
                        "xai-oauth",
                        "--model",
                        "grok-4.5",
                        "--verdict",
                        "approve-with-findings",
                        "--report",
                        str(grok),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "attest",
                        "model-synthesis",
                        "--subject",
                        "release-gate",
                        "--repo",
                        str(repo),
                        "--decision",
                        "approve",
                        "--synthesizer",
                        "review-orchestrator/gpt-5.6-sol",
                        "--agreement",
                        "tree binding",
                        "--disagreement",
                        "run-provenance signing is integrity, not review",
                        "--resolution",
                        "retain provenance signing; governance is model review diversity",
                    ]
                ),
                0,
            )
            receipt = repo / ".arvyx" / "release-reviews" / "release-gate.attestation.json"
            payload = json.loads(receipt.read_text(encoding="utf-8"))
            ok, models, error = verify_model_review_attestation(payload, repo=repo, subject="release-gate")
            self.assertTrue(ok, error)
            self.assertEqual(models, ["openai-codex/gpt-5.6-sol", "xai-oauth/grok-4.5"])

            from copy import deepcopy
            duplicate = deepcopy(payload)
            alias = deepcopy(duplicate['reviews'][0])
            alias['provider'] = ' ' + alias['provider']
            alias['model'] += ' '
            duplicate['reviews'] = [duplicate['reviews'][0], alias]
            accepted, identities, error = verify_model_review_attestation(
                duplicate, repo=repo, subject='release-gate', min_reviews=2)
            self.assertFalse(accepted)
            self.assertIn('duplicate model review identity', error)
            self.assertEqual(identities, ['openai-codex/gpt-5.6-sol'])

            third = reports / "third.md"
            third.write_text("## Verdict\n\napprove\n", encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        *common,
                        "--provider",
                        "anthropic",
                        "--model",
                        "claude-opus-4.6",
                        "--verdict",
                        "approve",
                        "--report",
                        str(third),
                    ]
                ),
                0,
            )
            updated = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual(updated["status"], "pending")
            self.assertNotIn("synthesis", updated)
            valid_after_append, _models, _error = verify_model_review_attestation(
                updated, repo=repo, subject="release-gate"
            )
            self.assertFalse(valid_after_append)

    def test_model_review_cli_rejects_malformed_receipt_and_output_escape(self) -> None:
        from arvyx_control.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            repo, _tree = self._temp_release_repo(tmp)
            reports = repo / ".arvyx" / "model-reviews"
            reports.mkdir(parents=True)
            report = reports / "sol.md"
            report.write_text("## Verdict\n\napprove\n", encoding="utf-8")
            escaped = repo / "docs" / "release-gate.attestation.json"
            command = [
                "attest",
                "model-review",
                "--subject",
                "release-gate",
                "--repo",
                str(repo),
                "--provider",
                "openai-codex",
                "--model",
                "gpt-5.6-sol",
                "--verdict",
                "approve",
                "--scope",
                "release diff",
                "--report",
                str(report),
            ]
            self.assertEqual(main([*command, "--output", str(escaped)]), 1)
            self.assertFalse(escaped.exists())

            receipt = repo / ".arvyx" / "release-reviews" / "release-gate.attestation.json"
            receipt.parent.mkdir(parents=True)
            receipt.write_text("{not-json\n", encoding="utf-8")
            self.assertEqual(main(command), 1)
            self.assertEqual(
                main(
                    [
                        "attest",
                        "model-synthesis",
                        "--subject",
                        "release-gate",
                        "--repo",
                        str(repo),
                        "--decision",
                        "approve",
                        "--synthesizer",
                        "review-orchestrator/gpt-5.6-sol",
                        "--resolution",
                        "no disagreements",
                    ]
                ),
                1,
            )

    def test_model_review_cli_rejects_symlinked_evidence_lanes(self) -> None:
        from arvyx_control.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            repo, _tree = self._temp_release_repo(tmp)
            outside = Path(tmp) / "outside"
            outside.mkdir()
            report = outside / "sol.md"
            report.write_text("## Verdict\n\napprove\n", encoding="utf-8")
            arvyx_dir = repo / ".arvyx"
            arvyx_dir.mkdir()
            reports_link = arvyx_dir / "model-reviews"
            reports_link.symlink_to(outside, target_is_directory=True)
            command = [
                "attest",
                "model-review",
                "--subject",
                "release-gate",
                "--repo",
                str(repo),
                "--provider",
                "openai-codex",
                "--model",
                "gpt-5.6-sol",
                "--verdict",
                "approve",
                "--scope",
                "release diff",
                "--report",
                str(reports_link / "sol.md"),
            ]
            self.assertEqual(main(command), 1)

            reports_link.unlink()
            reports_link.mkdir()
            local_report = reports_link / "sol.md"
            local_report.write_text("# Sol review\n\nApprove.\n", encoding="utf-8")
            receipts_link = arvyx_dir / "release-reviews"
            receipts_link.symlink_to(outside, target_is_directory=True)
            command[-1] = str(local_report)
            self.assertEqual(main(command), 1)

    def test_run_bridge_executes_live_smoke(self) -> None:
        import subprocess
        from unittest.mock import patch

        from arvyx_control.release_host import release_host_report

        calls: list[list[str]] = []
        real_run = subprocess.run

        def fake_run(command, **kwargs):
            if command[0] == 'git':return real_run(command, **kwargs)
            calls.append([str(part) for part in command])
            return subprocess.CompletedProcess(command, 0, "bridge smoke passed", "")

        with patch("arvyx_control.release_host.subprocess.run", side_effect=fake_run):
            result = release_host_report(repo=self.ROOT, run_bridge=True)
        checks = {check.id: check for check in result.checks}
        self.assertEqual(checks["safe_mcp_bridge_e2e"].status, "complete")
        self.assertTrue(any("bridge_dogfood_smoke.py" in part for call in calls for part in call))



class VaultIndexTests(unittest.TestCase):
    def test_index_persists_and_invalidates_on_edit(self) -> None:
        from arvyx_control.index import INDEX_RELATIVE, load_index
        from arvyx_control.recall import recall

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            load_index(vault)
            self.assertTrue((vault / INDEX_RELATIVE).exists())

            status = vault / "projects" / "demo-agent" / "STATUS.md"
            addition = "".join(["\n", "- The zephyr quorum is three machines.", "\n"])
            status.write_text(status.read_text(encoding="utf-8") + addition, encoding="utf-8")
            result = recall("what is the zephyr quorum", vault=vault, project="demo-agent")
        self.assertTrue(any("STATUS.md" in source.path for source in result.sources))
        self.assertIn("zephyr", result.answer[0].lower())

    def test_index_never_contains_forbidden_lanes(self) -> None:
        from arvyx_control.index import load_index

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            chunks = load_index(vault)
        paths = {chunk.relative_path for chunk in chunks}
        self.assertTrue(paths)
        for path in paths:
            self.assertNotIn("raw/", path)
            self.assertNotIn("archive/", path)
            self.assertNotIn("pending/", path)

    def test_read_only_vault_degrades_to_memory_index(self) -> None:
        from unittest.mock import patch

        from arvyx_control.index import load_index

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            with patch("arvyx_control.index.os.replace", side_effect=OSError("read-only")):
                chunks = load_index(vault)
        self.assertTrue(chunks)

    def test_stale_index_cache_is_ignored(self) -> None:
        from arvyx_control.index import INDEX_RELATIVE, load_index

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            cache = vault / INDEX_RELATIVE
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text("not json at all", encoding="utf-8")
            chunks = load_index(vault)
        self.assertTrue(chunks)


class IndexConfinementTests(unittest.TestCase):
    @staticmethod
    def _symlink(target: Path, link: Path) -> bool:
        try:
            os.symlink(target, link)
            return True
        except (OSError, NotImplementedError):
            return False

    def test_index_does_not_leak_content_via_symlink(self) -> None:
        from arvyx_control.recall import recall

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            outside = Path(tmp) / "secret.txt"
            outside.write_text("# Leak\n\nthe database password quokkazzz lives here\n", encoding="utf-8")
            if not self._symlink(outside, vault / "projects" / "demo-agent" / "leak.md"):
                self.skipTest("symlinks not permitted on this host")
            result = recall("database password quokkazzz", vault=vault, project="demo-agent")
            self.assertFalse(any("quokkazzz" in line for line in result.answer))
            self.assertFalse(any("leak.md" in source.path for source in result.sources))

    def test_index_tolerates_a_dangling_symlink(self) -> None:
        from arvyx_control.recall import recall

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            target = Path(tmp) / "gone.txt"
            target.write_text("x\n", encoding="utf-8")
            if not self._symlink(target, vault / "projects" / "demo-agent" / "dangling.md"):
                self.skipTest("symlinks not permitted on this host")
            target.unlink()  # now dangling
            # must not raise for the whole vault
            recall("safe mcp bridge", vault=vault, project="demo-agent")

    def test_index_detects_same_size_same_mtime_edit(self) -> None:
        from arvyx_control.index import load_index

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            status = vault / "projects" / "demo-agent" / "STATUS.md"
            load_index(vault)  # build the cache
            original = status.read_text(encoding="utf-8")
            mtime = status.stat().st_mtime_ns
            self.assertIn("safety", original)
            status.write_text(original.replace("safety", "qqqqqq", 1), encoding="utf-8")  # same length
            os.utime(status, ns=(mtime, mtime))  # preserve mtime (backup-restore scenario)
            terms: set[str] = set()
            for chunk in load_index(vault):
                if "STATUS" in chunk.relative_path:
                    terms |= set(chunk.terms)
            self.assertIn("qqqqqq", terms)
            self.assertNotIn("safety", terms)


class SecretRedactionTests(unittest.TestCase):
    def test_excerpt_redacts_secret_shapes(self) -> None:
        from arvyx_control.recall import excerpt

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            doc = vault / "projects" / "demo-agent" / "STATUS.md"
            token = "ghp_" + "a" * 24
            doc.write_text(
                doc.read_text(encoding="utf-8") + f"- leaked token {token} in status" + chr(10),
                encoding="utf-8",
            )
            line_count = len(doc.read_text(encoding="utf-8").splitlines())
            result = excerpt(
                vault=vault,
                source_path="projects/demo-agent/STATUS.md",
                lines=f"1-{line_count}",
            )
        self.assertNotIn(token, result.text)
        self.assertIn("[REDACTED-SECRET]", result.text)

    def test_bridge_redacts_secret_shapes_in_responses(self) -> None:
        from safe_mcp_bridge.cli import _redact_shapes

        token = "ghp_" + "b" * 24
        payload = {"result": {"content": [{"type": "text", "text": f"key {token} here"}]}}
        redacted, count = _redact_shapes(payload)
        self.assertEqual(count, 1)
        self.assertNotIn(token, str(redacted))

    def test_bridge_blocks_unknown_methods(self) -> None:
        import json as json_module

        from safe_mcp_bridge.cli import BLOCKED_METHOD_CODE, _handle_line

        config = {
            "target": {"url": "http://127.0.0.1:1/mcp"},
            "policy": {"mode": "allowlist", "allow_tools": ["memory.recall"]},
        }
        response = _handle_line(
            config,
            json_module.dumps({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {}}),
        )
        self.assertEqual(response["error"]["code"], BLOCKED_METHOD_CODE)


class GovernedWriteTests(unittest.TestCase):
    def test_suggest_is_excluded_until_promoted(self) -> None:
        from arvyx_control.recall import recall
        from arvyx_control.writes import list_pending, promote_memory, suggest_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            suggestion = suggest_memory(
                vault=vault,
                project="demo-agent",
                title="Quorum decision",
                content="The zephyr quorum requires three of five machines.",
                author="demobot",
            )
            self.assertTrue(suggestion.path.startswith("projects/demo-agent/pending/"))

            before = recall("what is the zephyr quorum", vault=vault, project="demo-agent")
            self.assertFalse(any("pending" in source.path for source in before.sources))

            pending = list_pending(vault=vault, project="demo-agent")
            self.assertEqual(len(pending.pending), 1)
            self.assertEqual(pending.pending[0].author, "demobot")

            promoted = promote_memory(
                vault=vault,
                project="demo-agent",
                source_path=suggestion.path,
                promoted_by="operator",
            )
            self.assertTrue(promoted.target.startswith("projects/demo-agent/notes/"))

            after = recall("what is the zephyr quorum", vault=vault, project="demo-agent")
            self.assertTrue(any(promoted.target == source.path for source in after.sources))
            self.assertIn("zephyr", after.answer[0].lower())

    def test_suggest_refuses_secret_shapes(self) -> None:
        from arvyx_control.writes import suggest_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            with self.assertRaises(ValueError):
                suggest_memory(
                    vault=vault,
                    project="demo-agent",
                    title="Leaked",
                    content="token = ghp_" + "c" * 24,
                    author="demobot",
                )

    def test_suggest_refuses_secret_shapes_in_metadata(self) -> None:
        from arvyx_control.writes import suggest_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            fixture_shape = "sk-" + "a" * 24
            cases = (
                {"author": fixture_shape, "tags": None},
                {"author": "demobot", "tags": ["safe", fixture_shape]},
            )
            for case in cases:
                with self.subTest(case=case):
                    with self.assertRaises(ValueError):
                        suggest_memory(
                            vault=vault,
                            project="demo-agent",
                            title="Safe title",
                            content="Safe content",
                            author=case["author"],
                            tags=case["tags"],
                        )

    def test_promote_and_reject_refuse_secret_shapes_in_metadata(self) -> None:
        from arvyx_control.writes import promote_memory, reject_memory, suggest_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            fixture_shape = "ghp_" + "c" * 24
            promoted = suggest_memory(
                vault=vault,
                project="demo-agent",
                title="Promote candidate",
                content="Safe content",
                author="demobot",
            )
            rejected = suggest_memory(
                vault=vault,
                project="demo-agent",
                title="Reject candidate",
                content="Safe content",
                author="demobot",
            )

            with self.assertRaises(ValueError):
                promote_memory(vault=vault, project="demo-agent", source_path=promoted.path, promoted_by=fixture_shape)
            with self.assertRaises(ValueError):
                reject_memory(vault=vault, project="demo-agent", source_path=rejected.path, rejected_by="operator", reason=fixture_shape)

    def test_reject_moves_to_archive(self) -> None:
        from arvyx_control.writes import list_pending, reject_memory, suggest_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            suggestion = suggest_memory(
                vault=vault,
                project="demo-agent",
                title="Bad idea",
                content="This should not become memory.",
                author="demobot",
            )
            result = reject_memory(
                vault=vault,
                project="demo-agent",
                source_path=suggestion.path,
                rejected_by="operator",
                reason="not accurate",
            )
            self.assertTrue(result.target.startswith("projects/demo-agent/archive/"))
            self.assertEqual(len(list_pending(vault=vault, project="demo-agent").pending), 0)

    def test_promote_refuses_curated_lanes(self) -> None:
        from arvyx_control.writes import promote_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            with self.assertRaises(ValueError):
                promote_memory(
                    vault=vault,
                    project="demo-agent",
                    source_path="projects/demo-agent/STATUS.md",
                    promoted_by="operator",
                )

    def test_mcp_profiles_scope_write_tools(self) -> None:
        from arvyx_control.mcp import tools_for_profile

        read_only = set(tools_for_profile("read-only"))
        agent = set(tools_for_profile("agent"))
        operator = set(tools_for_profile("operator"))
        self.assertNotIn("memory.suggest", read_only)
        self.assertIn("memory.suggest", agent)
        self.assertNotIn("memory.promote", agent)
        self.assertIn("memory.promote", operator)

    def test_checked_in_bridge_examples_match_generated_profiles(self) -> None:
        import json

        from arvyx_control.bridge import build_bridge_policy

        root = Path(__file__).resolve().parents[3]
        for profile in ("read-only", "operator"):
            with self.subTest(profile=profile):
                checked_in = json.loads(
                    (root / "examples" / "safe-mcp-bridge" / f"{profile}.json").read_text(encoding="utf-8")
                )
                generated = build_bridge_policy(profile=profile).policy
                self.assertEqual(checked_in, generated)

    def test_mcp_suggest_round_trip(self) -> None:
        from arvyx_control.mcp import handle_request, tools_for_profile

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            from arvyx_control.replica_authority import authority_context
            from arvyx_control.mcp import handle_request as dispatch
            def handle_request(payload, **kwargs):
                payload['idempotency_key'] = 'hardening-fixture-key-'+str(payload.get('id'))
                state=vault/'control-events.jsonl'
                with authority_context(vault,state):return dispatch(payload,state=state,**kwargs)
            response = handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "memory.suggest",
                        "arguments": {
                            "project": "demo-agent",
                            "title": "Bridge default",
                            "content": "Unknown JSON-RPC methods are denied by default.",
                            "author": "demobot",
                        },
                    },
                },
                vault=vault,
                allowed_tools=set(tools_for_profile("agent")),
            )
            structured = response["result"]["structuredContent"]
            self.assertTrue(structured["path"].startswith("projects/demo-agent/pending/"))

            blocked = handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "memory.promote",
                        "arguments": {
                            "project": "demo-agent",
                            "source_path": structured["path"],
                            "promoted_by": "demobot",
                        },
                    },
                },
                vault=vault,
                allowed_tools=set(tools_for_profile("agent")),
            )
            self.assertIn("error", blocked)


class RefinerQueueTests(unittest.TestCase):
    def test_refine_flow_pending_to_refining_to_notes(self) -> None:
        from arvyx_control.recall import recall
        from arvyx_control.writes import list_refining, promote_memory, refine_memory, suggest_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            suggestion = suggest_memory(
                vault=vault,
                project="demo-agent",
                title="Raw idea",
                content="The relay quorum needs three nodes.",
                author="demobot",
            )
            refined = refine_memory(
                vault=vault,
                project="demo-agent",
                source_path=suggestion.path,
                refined_by="vesper",
                content="# Relay quorum\n\nThe relay quorum requires three of five nodes.",
            )
            self.assertTrue(refined.target.startswith("projects/demo-agent/refining/"))
            self.assertFalse((vault / suggestion.path).exists())

            queue = list_refining(vault=vault, project="demo-agent")
            self.assertEqual(len(queue.refining), 1)
            self.assertEqual(queue.refining[0].author, "vesper")

            # refining is not curated yet: it must stay out of recall
            before = recall("relay quorum", vault=vault, project="demo-agent")
            self.assertFalse(any("refining" in source.path for source in before.sources))

            promoted = promote_memory(
                vault=vault,
                project="demo-agent",
                source_path=refined.target,
                promoted_by="operator",
            )
            self.assertTrue(promoted.target.startswith("projects/demo-agent/notes/"))
            after = recall("relay quorum", vault=vault, project="demo-agent")
            self.assertTrue(any(promoted.target == source.path for source in after.sources))
            self.assertEqual(len(list_refining(vault=vault, project="demo-agent").refining), 0)

    def test_refine_refuses_secret_shapes(self) -> None:
        from arvyx_control.writes import refine_memory, suggest_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            suggestion = suggest_memory(
                vault=vault,
                project="demo-agent",
                title="Raw idea",
                content="A harmless suggestion.",
                author="demobot",
            )
            with self.assertRaises(ValueError):
                refine_memory(
                    vault=vault,
                    project="demo-agent",
                    source_path=suggestion.path,
                    refined_by="vesper",
                    content="leaked token = ghp_" + "d" * 24,
                )

    def test_refine_notes_cannot_inject_frontmatter(self) -> None:
        from arvyx_control.writes import promote_memory, refine_memory, suggest_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            suggestion = suggest_memory(
                vault=vault, project="demo-agent", title="X", content="body text", author="demobot"
            )
            refined = refine_memory(
                vault=vault,
                project="demo-agent",
                source_path=suggestion.path,
                refined_by="vesper",
                notes="ok\nupdated_at: 2099-01-01T00:00:00Z",
            )
            promoted = promote_memory(
                vault=vault, project="demo-agent", source_path=refined.target, promoted_by="operator"
            )
            # the newline is collapsed, so the injected text stays inside the
            # refine_notes value and never becomes a parseable updated_at key
            # that would poison temporal ranking
            from arvyx_control.writes import _frontmatter

            frontmatter = _frontmatter((vault / promoted.target).read_text(encoding="utf-8"))
            self.assertNotEqual(frontmatter.get("updated_at"), "2099-01-01T00:00:00Z")
            self.assertNotIn("updated_at", frontmatter)

    def test_refine_notes_redacts_secret_shapes(self) -> None:
        from arvyx_control.writes import refine_memory, suggest_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            suggestion = suggest_memory(
                vault=vault, project="demo-agent", title="Y", content="body", author="demobot"
            )
            token = "AKIA" + "A" * 16
            before = (vault / suggestion.path).read_bytes()
            with self.assertRaisesRegex(ValueError, "secret-shaped"):
                refine_memory(vault=vault, project="demo-agent", source_path=suggestion.path,
                              refined_by="vesper", notes=f"context {token} end")
            self.assertEqual((vault / suggestion.path).read_bytes(), before)
            self.assertFalse((vault / "projects/demo-agent/refining").exists())

    def test_refine_imported_doc_with_unterminated_frontmatter(self) -> None:
        from arvyx_control.writes import _frontmatter, refine_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            imported = vault / "projects" / "demo-agent" / "imported"
            imported.mkdir(parents=True, exist_ok=True)
            # opens with --- but has no closing fence (a malformed import)
            (imported / "bad.md").write_text("---\nnot really frontmatter\nmore body lines\n", encoding="utf-8")
            result = refine_memory(
                vault=vault,
                project="demo-agent",
                source_path="imported/bad.md",
                refined_by="vesper",
                content="# Clean\n\nrewritten body",
            )
            doc = (vault / result.target).read_text(encoding="utf-8")
            # the malformed content is not swallowed into a giant frontmatter block
            self.assertNotIn("not really frontmatter", doc)
            self.assertIn("rewritten body", doc)
            frontmatter = _frontmatter(doc)
            self.assertEqual(__import__("json").loads(frontmatter["refined_by"]), "vesper")

    def test_refine_refuses_curated_lane(self) -> None:
        from arvyx_control.writes import refine_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            with self.assertRaises(ValueError):
                refine_memory(
                    vault=vault,
                    project="demo-agent",
                    source_path="projects/demo-agent/STATUS.md",
                    refined_by="vesper",
                )

    def test_refine_scope_is_isolated_from_curate(self) -> None:
        from arvyx_control.auth import SCOPE_MEMORY_REFINE, tools_for_scopes
        from arvyx_control.mcp import tools_for_profile

        granted = tools_for_scopes(frozenset({SCOPE_MEMORY_REFINE}))
        self.assertEqual(granted, {"memory.refine", "memory.refining_list"})
        self.assertNotIn("memory.promote", granted)
        # refining is a curation-adjacent role: not in the stdio agent profile
        self.assertNotIn("memory.refine", set(tools_for_profile("agent")))
        self.assertIn("memory.refine", set(tools_for_profile("operator")))

    def test_mcp_refine_binds_actor_over_claim(self) -> None:
        from arvyx_control.mcp import TOOL_NAMES, handle_request
        from arvyx_control.writes import suggest_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            suggestion = suggest_memory(
                vault=vault,
                project="demo-agent",
                title="Raw idea",
                content="The relay quorum needs three nodes.",
                author="demobot",
            )
            from arvyx_control.replica_authority import authority_context
            from arvyx_control.mcp import handle_request as dispatch
            def handle_request(payload, **kwargs):
                payload['idempotency_key'] = 'hardening-fixture-key-'+str(payload.get('id'))
                state=vault/'control-events.jsonl'
                with authority_context(vault,state):return dispatch(payload,state=state,**kwargs)
            response = handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "memory.refine",
                        "arguments": {
                            "project": "demo-agent",
                            "source_path": suggestion.path,
                            "refined_by": "someone-else",
                        },
                    },
                },
                vault=vault,
                allowed_tools=set(TOOL_NAMES),
                actor="vesper",
            )
            structured = response["result"]["structuredContent"]
            self.assertEqual(structured["refined_by"], "vesper")
            self.assertTrue(structured["target"].startswith("projects/demo-agent/refining/"))


class VaultLockConcurrencyTests(unittest.TestCase):
    def test_lock_does_not_write_a_racy_sentinel_byte(self) -> None:
        from arvyx_control.locks import exclusive_lock

        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "fresh.lock"
            with exclusive_lock(lock_path):
                pass
            self.assertEqual(lock_path.read_bytes(), b"")

    def test_vault_lock_is_mutually_exclusive(self) -> None:
        import threading
        import time

        from arvyx_control.locks import vault_lock

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            vault.mkdir()
            order: list[str] = []

            def worker(name: str) -> None:
                with vault_lock(vault):
                    order.append(f"{name}-enter")
                    time.sleep(0.05)
                    order.append(f"{name}-exit")

            threads = [threading.Thread(target=worker, args=(n,)) for n in ("a", "b")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            # critical sections never interleave: each enter is followed by its own exit
            self.assertIn(order, (["a-enter", "a-exit", "b-enter", "b-exit"], ["b-enter", "b-exit", "a-enter", "a-exit"]))

    def test_concurrent_reject_and_refine_land_in_exactly_one_lane(self) -> None:
        import threading

        from arvyx_control.writes import refine_memory, reject_memory, suggest_memory

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            for i in range(10):
                source = suggest_memory(
                    vault=vault, project="demo-agent", title=f"item{i}", content="body text", author="demobot"
                ).path
                stem = Path(source).stem
                barrier = threading.Barrier(2)

                def do_refine() -> None:
                    barrier.wait()
                    try:
                        refine_memory(vault=vault, project="demo-agent", source_path=source, refined_by="vesper")
                    except (FileNotFoundError, ValueError):
                        pass

                def do_reject() -> None:
                    barrier.wait()
                    try:
                        reject_memory(vault=vault, project="demo-agent", source_path=source, rejected_by="operator")
                    except (FileNotFoundError, ValueError):
                        pass

                threads = [threading.Thread(target=do_refine), threading.Thread(target=do_reject)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()

                in_pending = (vault / source).exists()
                in_refining = (vault / "projects" / "demo-agent" / "refining" / f"{stem}.md").exists()
                in_archive = (vault / "projects" / "demo-agent" / "archive" / f"{stem}.md").exists()
                self.assertFalse(in_pending, f"iter {i}: source left in pending")
                # exactly one lane — never both (the double-lane race the lock prevents)
                self.assertTrue(in_refining ^ in_archive, f"iter {i}: refining={in_refining} archive={in_archive}")


class AgentIdentityTests(unittest.TestCase):
    def _serve(self, vault, state, **kwargs):
        import threading
        from http.server import ThreadingHTTPServer

        from arvyx_control.api import make_handler

        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(vault=vault, state=state, **kwargs))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, f"http://127.0.0.1:{server.server_port}"

    def _request(self, url, method="GET", body=None, token=None):
        import json as json_module
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen

        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if method not in {"GET", "HEAD", "OPTIONS"} and token:
            headers["Idempotency-Key"] = f"test-{os.urandom(16).hex()}"
        data = json_module.dumps(body).encode("utf-8") if body is not None else None
        request = Request(url, data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json_module.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            return exc.code, json_module.loads(exc.read().decode("utf-8"))

    def test_issue_resolve_and_scope_enforcement(self) -> None:
        from arvyx_control.auth import issue_token, resolve_identity, revoke_token

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            issued = issue_token(vault, "demobot", scopes=["memory.read", "memory.suggest"])
            self.assertTrue(issued.token.startswith("arv_demobot_"))
            stored = (vault / issued.path).read_text(encoding="utf-8")
            self.assertNotIn(issued.token, stored)

            identity = resolve_identity(vault, f"Bearer {issued.token}")
            self.assertIsNotNone(identity)
            self.assertEqual(identity.agent_id, "demobot")
            self.assertIn("memory.suggest", identity.scopes)
            self.assertNotIn("control.write", identity.scopes)

            self.assertIsNone(resolve_identity(vault, "Bearer invalid"))
            revoke_token(vault, "demobot")
            self.assertIsNone(resolve_identity(vault, f"Bearer {issued.token}"))

    def test_unauthenticated_mutations_are_denied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            server, thread, base = self._serve(vault, state)
            try:
                status, body = self._request(f"{base}/tasks", "POST", {"title": "nope"})
                self.assertEqual(status, 401)
                status, body = self._request(
                    f"{base}/memory/recall",
                    "POST",
                    {"question": "what did we decide about safe mcp bridge", "project": "demo-agent"},
                )
                self.assertEqual(status, 200)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_agent_token_scopes_and_actor_binding_over_http(self) -> None:
        from arvyx_control.auth import issue_token

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            agent = issue_token(vault, "demobot", scopes=["memory.read", "memory.suggest", "control.write"])
            server, thread, base = self._serve(vault, state, mcp_profile="operator")
            try:
                # scope enforcement: demobot cannot promote
                status, body = self._request(
                    f"{base}/memory/promote",
                    "POST",
                    {"project": "demo-agent", "source_path": "pending/x.md", "promoted_by": "demobot"},
                    token=agent.token,
                )
                self.assertEqual(status, 403)

                # actor binding: claimed requester is overridden by identity
                status, body = self._request(
                    f"{base}/approvals/request",
                    "POST",
                    {"command": "arvyx recall demo-agent", "requester": "someone-else"},
                    token=agent.token,
                )
                self.assertEqual(status, 201)
                self.assertEqual(body["body"]["approval"]["requester"], "demobot")
                approval_id = body["body"]["approval"]["id"]

                # self-approval is now enforceable: demobot cannot approve
                # its own request even by claiming another name
                status, body = self._request(
                    f"{base}/approvals/{approval_id}/approve",
                    "POST",
                    {"approver": "operator"},
                    token=agent.token,
                )
                self.assertEqual(status, 403)
                self.assertIn("operator identity required", body["body"]["error"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_shared_secret_still_grants_operator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            server, thread, base = self._serve(vault, state, bearer_secret="demo-secret")
            try:
                status, _ = self._request(f"{base}/tasks", "POST", {"title": "op task", "owner": "demobot"}, token="demo-secret")
                self.assertEqual(status, 201)
                status, _ = self._request(f"{base}/tasks", "POST", {"title": "nope"}, token="wrong")
                self.assertEqual(status, 401)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


class AuditLogTests(unittest.TestCase):
    def test_preauth_denial_audit_has_a_hard_per_minute_cardinality_cap(self) -> None:
        from arvyx_control import api

        api._DENIAL_AUDIT_BUCKETS.clear()
        with mock.patch("arvyx_control.api.time.monotonic", return_value=60.0):
            accepted = sum(api._claim_denial_audit_slot(f"/probe/{index}", 401) for index in range(256))
            repeated = api._claim_denial_audit_slot("/probe/255", 401)
        self.assertEqual(accepted, 1)  # All unknown routes share one bounded denial bucket.
        self.assertFalse(repeated)
        with mock.patch("arvyx_control.api.time.monotonic", return_value=120.0):
            self.assertTrue(api._claim_denial_audit_slot("/probe/new-minute", 401))

    def test_chain_appends_and_verifies(self) -> None:
        import json as json_module

        from arvyx_control.audit_log import append_audit, verify_chain

        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            with authority_context(Path(tmp) / "authority-vault"):
                append_audit(log, {"surface": "api", "route": "/tasks", "decision": "allowed"})
            with authority_context(Path(tmp) / "authority-vault"):
                append_audit(log, {"surface": "api", "route": "/tasks", "decision": "denied"})
            result = verify_chain(log)
            self.assertTrue(result.ok)
            self.assertEqual(result.events, 2)

            # tamper with the first record: chain must break there
            lines = log.read_text(encoding="utf-8").splitlines()
            record = json_module.loads(lines[0])
            record["decision"] = "denied"
            lines[0] = json_module.dumps(record, sort_keys=True)
            log.write_text(chr(10).join(lines) + chr(10), encoding="utf-8")
            broken = verify_chain(log)
            self.assertFalse(broken.ok)
            self.assertEqual(broken.first_break_line, 1)

    def test_deleting_a_line_breaks_the_chain(self) -> None:
        from arvyx_control.audit_log import append_audit, verify_chain

        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            for index in range(3):
                with authority_context(Path(tmp) / "authority-vault"):
                    append_audit(log, {"surface": "api", "route": f"/r{index}", "decision": "allowed"})
            lines = log.read_text(encoding="utf-8").splitlines()
            del lines[1]
            log.write_text(chr(10).join(lines) + chr(10), encoding="utf-8")
            self.assertFalse(verify_chain(log).ok)

    def test_chain_survives_record_larger_than_tail(self) -> None:
        from arvyx_control.audit_log import _TAIL_BYTES, append_audit, verify_chain

        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            with authority_context(Path(tmp) / "authority-vault"):
                append_audit(log, {"surface": "api", "route": "/x", "decision": "allowed"})
            # a record whose serialized line exceeds the tail-read window must
            # still chain: the next append reads back its real hash, not GENESIS
            with authority_context(Path(tmp) / "authority-vault"):
                append_audit(log, {"surface": "api", "route": "/big", "blob": "z" * (_TAIL_BYTES + 4096)})
            with authority_context(Path(tmp) / "authority-vault"):
                append_audit(log, {"surface": "api", "route": "/y", "decision": "allowed"})
            result = verify_chain(log)
            self.assertTrue(result.ok)
            self.assertEqual(result.events, 3)

    def test_audit_write_failure_fails_closed_on_mutation_but_not_reads(self) -> None:
        from arvyx_control.api import handle_api_request

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            blocker = Path(tmp) / "blocker"
            blocker.write_text("x", encoding="utf-8")  # a FILE, so mkdir of its child parent fails
            bad_log = blocker / "audit.jsonl"

            # a mutation refuses (503) when its audit record cannot be written
            mutation = handle_api_request(
                "POST", "/tasks", {"title": "x"}, vault=vault, state=state, audit_log=bad_log,
                allow_unauthenticated_demo=True,
            )
            self.assertEqual(mutation.status, 503)
            self.assertFalse(state.exists(), "failed audit intent must prevent the mutation")
            # a read still succeeds despite the same audit-write failure
            read = handle_api_request(
                "POST", "/memory/recall", {"question": "safe mcp bridge", "project": "demo-agent"},
                vault=vault, state=state, audit_log=bad_log, allow_unauthenticated_demo=True,
            )
            self.assertEqual(read.status, 200)

    def test_mcp_write_requires_audit_intent_but_mcp_read_does_not(self) -> None:
        from arvyx_control.api import handle_api_request

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            blocker = Path(tmp) / "blocker"
            blocker.write_text("x", encoding="utf-8")
            bad_log = blocker / "audit.jsonl"
            write_body = {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "control.task_create", "arguments": {"title": "must not land"}},
            }
            read_body = {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "memory.recall", "arguments": {"question": "safe bridge"}},
            }

            write = handle_api_request(
                "POST", "/mcp", write_body, vault=vault, state=state, audit_log=bad_log,
                allow_unauthenticated_demo=True, mcp_profile="operator",
            )
            read = handle_api_request(
                "POST", "/mcp", read_body, vault=vault, state=state, audit_log=bad_log,
                allow_unauthenticated_demo=True, mcp_profile="operator",
            )

            self.assertEqual(write.status, 503)
            self.assertFalse(state.exists())
            self.assertEqual(read.status, 200)

    def test_api_writes_audit_records_for_allowed_and_denied(self) -> None:
        import json as json_module

        from arvyx_control.api import handle_api_request
        from arvyx_control.audit_log import verify_chain

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            log = Path(tmp) / "audit.jsonl"

            allowed = handle_api_request(
                "POST",
                "/memory/recall",
                {"question": "what did we decide about safe mcp bridge", "project": "demo-agent"},
                vault=vault,
                state=state,
                audit_log=log,
            )
            denied = handle_api_request(
                "POST",
                "/tasks",
                {"title": "nope"},
                vault=vault,
                state=state,
                audit_log=log,
            )
            self.assertEqual(allowed.status, 200)
            self.assertEqual(denied.status, 401)

            records = [json_module.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            decisions = [(record["route"], record["decision"]) for record in records]
            self.assertIn(("/memory/recall", "allowed"), decisions)
            self.assertIn(("/tasks", "denied"), decisions)
            self.assertTrue(verify_chain(log).ok)

    def test_completion_audit_failure_withholds_success_and_retry_does_not_repeat_mutation(self) -> None:
        from arvyx_control import api as api_module
        from arvyx_control.api import handle_api_request
        from arvyx_control.audit_log import append_audit_once as real_append_once
        from arvyx_control.audit_log import pending_operations
        from arvyx_control.control import list_tasks

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            with authority_context(vault, state):
                log = Path(tmp) / "audit.jsonl"

                def flaky_append(path: Path, event: dict[str, object]) -> dict[str, object]:
                    if event.get("phase") == "outcome":
                        raise OSError("synthetic completion failure")
                    return real_append_once(path, event)

                with mock.patch.object(api_module, "append_audit_once", side_effect=flaky_append):
                    response = handle_api_request(
                        "POST",
                        "/tasks",
                        {"title": "exactly once", "owner": "demobot"},
                        vault=vault,
                        state=state,
                        audit_log=log,
                        allow_unauthenticated_demo=True,
                        idempotency_key="-".join(("completion", "failure", "0001")),
                    )

                self.assertEqual(response.status, 503)
                self.assertEqual(response.body["error"], "audit_completion_pending")
                self.assertEqual(len(list_tasks(state).tasks), 1)
                self.assertEqual(pending_operations(log), 1)

                retry = handle_api_request(
                    "POST",
                    "/tasks",
                    {"title": "exactly once", "owner": "demobot"},
                    vault=vault,
                    state=state,
                    audit_log=log,
                    allow_unauthenticated_demo=True,
                    idempotency_key="-".join(("completion", "failure", "0001")),
                )
                self.assertEqual(retry.status, 409)
                self.assertEqual(retry.body["error"], "operation_completed_no_replay")
                self.assertEqual(len(list_tasks(state).tasks), 1)
                self.assertEqual(pending_operations(log), 0)

    def test_invalid_secret_reference_is_bounded_in_audit(self) -> None:
        from arvyx_control.api import handle_api_request

        supplied = "literal-sensitive-value-that-must-not-land"
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            log = Path(tmp) / "audit.jsonl"
            response = handle_api_request(
                "POST",
                "/secret/resolve",
                {"ref": supplied},
                vault=vault,
                state=state,
                audit_log=log,
            )
            self.assertEqual(response.status, 401)
            audit_text = log.read_text(encoding="utf-8")
            self.assertNotIn(supplied, audit_text)
            self.assertIn("invalid-ref:sha256:", audit_text)


class ControlLogRobustnessTests(unittest.TestCase):
    def test_read_events_fails_closed_on_torn_or_mid_log_corruption(self) -> None:
        from arvyx_control.control import create_task, read_events

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                create_task(state=state, title="one", owner="demobot")
                good = state.read_text(encoding="utf-8").splitlines()[0]

                # a torn trailing transition must not be silently discarded
                with state.open("a", encoding="utf-8") as handle:
                    handle.write('{"id":"partial","type":"task.crea')  # truncated, no newline
                with self.assertRaises(ValueError):
                    read_events(state)

                # but a corrupt line before the end is real corruption and must surface
                state.write_text("NOT JSON\n" + good + "\n", encoding="utf-8")
                with self.assertRaises(ValueError):
                    read_events(state)


class PersistentMcpSessionTests(unittest.TestCase):
    def test_full_client_session_over_one_process(self) -> None:
        import json as json_module
        import os as os_module
        import subprocess
        import sys as sys_module

        root = Path(__file__).resolve().parents[3]
        env = os_module.environ.copy()
        env["PYTHONPATH"] = str(root / "packages" / "arvctl" / "src")
        process = subprocess.Popen(
            [
                sys_module.executable,
                "-m",
                "arvyx_control.cli",
                "mcp",
                "--vault",
                str(root / "fixtures" / "synthetic-vault"),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            cwd=root,
        )
        try:
            def send(payload):
                process.stdin.write(json_module.dumps(payload) + chr(10))
                process.stdin.flush()

            def read_response():
                line = process.stdout.readline()
                self.assertTrue(line, "server closed the stream early")
                return json_module.loads(line)

            send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            init = read_response()
            self.assertEqual(init["result"]["protocolVersion"], "2024-11-05")

            # notification: no response expected, session must survive
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})

            send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            tools = read_response()
            names = [tool["name"] for tool in tools["result"]["tools"]]
            self.assertIn("memory.recall", names)

            send(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "memory.recall",
                        "arguments": {
                            "question": "what did we decide about safe mcp bridge",
                            "project": "demo-agent",
                        },
                    },
                }
            )
            recall_response = read_response()
            self.assertTrue(recall_response["result"]["structuredContent"]["answer"])

            process.stdin.close()
            self.assertEqual(process.wait(timeout=10), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            # close the pipe handles so they don't leak (ResourceWarning);
            # with text=True these are locale-encoded TextIOWrappers
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()


class SsrfGuardTests(unittest.TestCase):
    """Every outbound urlopen must reject non-http(s) schemes so a
    misconfigured file:// / gopher:// endpoint cannot read local files."""

    def test_replica_source_rejects_non_http_scheme(self) -> None:
        from arvyx_control.replica import _get_json

        for url in ("file:///etc/passwd", "gopher://host/x", "ftp://host/x"):
            with self.assertRaises(ValueError):
                _get_json(url, token=None, timeout=1)

    def test_health_host_rejects_non_http_scheme(self) -> None:
        from urllib.request import Request

        from arvyx_control.health import _request_json

        with self.assertRaises(ValueError):
            _request_json(Request("file:///etc/passwd"), 1)

    def test_dogfood_targets_reject_non_http_scheme(self) -> None:
        from arvyx_control.dogfood import _get_text, _post_json

        with self.assertRaises(ValueError):
            _get_text("file:///etc/passwd")
        with self.assertRaises(ValueError):
            _post_json("gopher://host/x", {})

    def test_embeddings_endpoint_rejects_non_http_scheme(self) -> None:
        from arvyx_control.embeddings import EmbeddingConfig, EmbeddingError, _embed_batch

        # Invalid endpoints are refused at configuration construction, before
        # a batch can reach the transport boundary.
        with self.assertRaises(EmbeddingError):
            config = EmbeddingConfig(
                provider="http",
                url="file:///etc/passwd",
                model="m",
                api_key_env=None,
                timeout_seconds=1,
                batch_size=1,
            )
            _embed_batch(config, ["x"])

    def test_bridge_target_rejects_non_http_scheme(self) -> None:
        from safe_mcp_bridge.cli import BridgeError, _post_json

        config = {
            "target": {"url": "file:///etc/passwd"},
            "policy": {"mode": "allowlist", "allow_tools": ["memory.recall"]},
        }
        with self.assertRaises(BridgeError):
            _post_json(config, {"jsonrpc": "2.0", "id": 1, "method": "ping"})


class BridgeResilienceTests(unittest.TestCase):
    CONFIG = {"target": {"url": "http://x"}, "policy": {"mode": "allowlist", "allow_tools": ["memory.recall"]}}

    def test_upstream_error_becomes_a_json_rpc_error_not_a_crash(self) -> None:
        from unittest import mock

        import safe_mcp_bridge.cli as bridge

        with mock.patch.object(bridge, "_post_json", side_effect=bridge.BridgeError("upstream HTTP 500")):
            response = bridge._handle_line(self.CONFIG, '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
            self.assertEqual(response["error"]["code"], -32000)
            # a notification whose upstream fails emits nothing (and never crashes)
            self.assertIsNone(bridge._handle_line(self.CONFIG, '{"jsonrpc":"2.0","method":"notifications/initialized"}'))

    def test_malformed_tools_list_result_is_rejected(self) -> None:
        from unittest import mock

        import safe_mcp_bridge.cli as bridge

        with mock.patch.object(bridge, "_post_json", return_value={"jsonrpc": "2.0", "id": 1, "result": "not-a-dict"}):
            response = bridge._handle_line(self.CONFIG, '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
            self.assertEqual(response["error"]["code"], -32000)
        with mock.patch.object(bridge, "_post_json", return_value={"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "upstream error"}}):
            response = bridge._handle_line(self.CONFIG, '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
            self.assertNotIn("result", response)  # an error response is not rewritten into result+error

    def test_redaction_scrubs_secret_shaped_dict_keys(self) -> None:
        import safe_mcp_bridge.cli as bridge

        token = "ghp_" + "a" * 24
        redacted, count = bridge._redact_shapes({token: {"v": "sk-" + "b" * 24}})
        self.assertGreaterEqual(count, 1)
        self.assertNotIn(token, str(redacted))


class EmbeddingResponseTests(unittest.TestCase):
    def test_malformed_vector_raises_embedding_error(self) -> None:
        from arvyx_control.embeddings import EmbeddingError, _vectors_from_response

        for bad in ([None], ["x"], [float("nan")], [float("inf")]):
            with self.assertRaises(EmbeddingError):
                _vectors_from_response({"data": [{"embedding": bad}]}, expected=1)

    def test_vectors_are_ordered_by_index(self) -> None:
        from arvyx_control.embeddings import _vectors_from_response

        response = {"data": [{"index": 1, "embedding": [9.0]}, {"index": 0, "embedding": [1.0]}]}
        self.assertEqual(_vectors_from_response(response, expected=2), [[1.0], [9.0]])


class AuthScopeToleranceTests(unittest.TestCase):
    def test_unknown_scope_in_token_file_is_dropped_not_fatal(self) -> None:
        import json as json_module

        from arvyx_control.auth import issue_token, resolve_identity

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            issued = issue_token(vault, "demobot", scopes=["memory.read"])
            token_file = vault / "registry" / "tokens" / "demobot.json"
            record = json_module.loads(token_file.read_text(encoding="utf-8"))
            record["scopes"] = ["memory.read", "since.renamed.scope"]
            token_file.write_text(json_module.dumps(record), encoding="utf-8")

            identity = resolve_identity(vault, f"Bearer {issued.token}")  # must not raise
            self.assertIsNotNone(identity)
            self.assertIn("memory.read", identity.scopes)
            self.assertNotIn("since.renamed.scope", identity.scopes)


class ImporterHardeningTests(unittest.TestCase):
    def test_secret_shaped_filename_is_skipped(self) -> None:
        from arvyx_control.importers import import_markdown

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            source = Path(tmp) / ("ghp_" + "a" * 24 + ".md")
            source.write_text("clean body\n", encoding="utf-8")
            result = import_markdown(vault=vault, source=source, project="demo-agent")
            self.assertEqual(result.imported, [])
            self.assertEqual(len(result.skipped), 1)

    def test_import_markdown_rejects_symlink_source_file(self) -> None:
        from arvyx_control.importers import import_markdown

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            outside = Path(tmp) / "outside.md"
            outside.write_text("non-secret host note\n", encoding="utf-8")
            source = Path(tmp) / "linked.md"
            source.symlink_to(outside)
            with self.assertRaises(ValueError):
                import_markdown(vault=vault, source=source, project="demo-agent")


class IndexCacheContainmentTests(unittest.TestCase):
    def test_poisoned_chunk_path_is_rebuilt_from_scanned_source(self) -> None:
        from arvyx_control.index import INDEX_RELATIVE, chunk_text, load_index

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            source = vault / "projects" / "demo" / "STATUS.md"
            source.parent.mkdir(parents=True)
            source.write_text("# Status\nsafe content\n", encoding="utf-8")
            load_index(vault)
            cache_path = vault / INDEX_RELATIVE
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
            cache["files"]["projects/demo/STATUS.md"]["chunks"][0]["relative_path"] = "../../outside.md"
            cache_path.write_text(json.dumps(cache), encoding="utf-8")

            rebuilt = load_index(vault)

            self.assertEqual([item.relative_path for item in rebuilt], ["projects/demo/STATUS.md"])
            self.assertIn("safe content", chunk_text(vault, rebuilt[0]))


class AuthSecretFileTests(unittest.TestCase):
    def test_auth_secret_can_be_loaded_from_file(self) -> None:
        from arvyx_control.cli import _credential_value

        with tempfile.TemporaryDirectory() as tmp:
            secret_file = Path(tmp) / "control-secret"
            credential = "synthetic-file-secret-with-32-bytes"
            secret_file.write_bytes(credential.encode("ascii") + b"\n")
            self.assertEqual(
                _credential_value(auth_env=None, auth_file=secret_file),
                credential,
            )

    def test_empty_or_oversized_auth_secret_file_is_rejected(self) -> None:
        from arvyx_control.cli import _credential_value

        with tempfile.TemporaryDirectory() as tmp:
            secret_file = Path(tmp) / "control-secret"
            for value in ("\n", "x" * 4097):
                with self.subTest(length=len(value)):
                    secret_file.write_text(value, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        _credential_value(auth_env=None, auth_file=secret_file)


class AuditPrivateNameExemptionTests(unittest.TestCase):
    """audit.py applies the same policy as scripts/private_context_scan.py:
    private names are exempt only in manifest private-only files, secret
    shapes are scanned everywhere, and an unusable manifest fails closed."""

    TERM = "private-agent"

    def _check(self, files: dict[str, str], manifest: str | None):
        from arvyx_control.audit import _private_context_check

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            for name, text in files.items():
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            denylist = repo / ".arvyx" / "private-denylist.txt"
            denylist.parent.mkdir(parents=True)
            denylist.write_text(self.TERM + "\n", encoding="utf-8")
            if manifest is not None:
                (repo / "config").mkdir(exist_ok=True)
                (repo / "config" / "public-release-paths.json").write_text(manifest, encoding="utf-8")
            with mock.patch.dict(os.environ, {DENYLIST_ENV: str(denylist)}):
                return _private_context_check(repo)

    @staticmethod
    def _manifest() -> str:
        return json.dumps(
            {
                "version": 1,
                "paths": {
                    "config/public-release-paths.json": "private-only",
                    "docs/private.md": "private-only",
                    "docs/public.md": "reimplemented-clean-room",
                },
            }
        )

    def test_private_only_file_with_private_name_is_not_a_finding(self) -> None:
        result = self._check(
            {"docs/private.md": f"PRIVATE: DO NOT PUBLISH.\nowned by {self.TERM}\n", "docs/public.md": "clean\n"},
            self._manifest(),
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.findings, [])
        self.assertIn("private_denylist_loaded=true", result.evidence)
        self.assertIn("private_name_exempt_private_only=2", result.evidence)
        self.assertIn("release_manifest_loaded=true", result.evidence)

    def test_clean_room_file_with_private_name_is_a_finding(self) -> None:
        result = self._check(
            {"docs/private.md": "PRIVATE: DO NOT PUBLISH.\n", "docs/public.md": f"by {self.TERM.upper()}\n"},
            self._manifest(),
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.findings, ["docs/public.md:1"])

    def test_private_only_file_with_secret_shape_is_still_a_finding(self) -> None:
        fixture_shape = "ghp_" + "a" * 24
        result = self._check(
            {"docs/private.md": f"PRIVATE: DO NOT PUBLISH.\ntoken: {fixture_shape}\n", "docs/public.md": "clean\n"},
            self._manifest(),
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.findings, ["docs/private.md:2"])

    def test_missing_or_malformed_manifest_name_scans_every_file(self) -> None:
        for label, manifest in (("missing", None), ("malformed", "{"), ("wrong-version", '{"version": 2, "paths": {}}')):
            with self.subTest(label):
                result = self._check(
                    {"docs/private.md": f"PRIVATE: DO NOT PUBLISH.\nowned by {self.TERM}\n"},
                    manifest,
                )
                self.assertFalse(result.ok)
                self.assertIn("docs/private.md:2", result.findings)
                self.assertIn("private_name_exempt_private_only=0", result.evidence)
                self.assertIn("release_manifest_loaded=false", result.evidence)

    def test_file_absent_from_manifest_is_name_scanned(self) -> None:
        result = self._check(
            {"docs/private.md": "PRIVATE: DO NOT PUBLISH.\n", "notes/draft.md": f"draft by {self.TERM}\n"},
            self._manifest(),
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.findings, ["notes/draft.md:1"])


class ReviewFindingFixTests(unittest.TestCase):
    """Each 2026-09-13 independent-review finding, pinned to a test.

    The reviews agreed on three real defects: a receipt binds the committed tree
    while scans read the working tree, the pinned operator-held signer made the
    "hand-authored files remain blocked" claim false while rotation was prose
    only, and the release workflow could not accept the current prerelease
    version at all.
    """

    ROOT = Path(__file__).resolve().parents[3]

    # --- dirty worktree -----------------------------------------------------

    def _temp_git_repo(self, tmp: str) -> Path:
        import subprocess

        repo = Path(tmp) / "repo"
        repo.mkdir()

        def git(*args: str) -> None:
            subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)

        subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
        git("config", "user.email", "t@example")
        git("config", "user.name", "t")
        (repo / "tracked.txt").write_text("one\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "init")
        return repo

    def test_dirty_worktree_blocks_the_public_release_verdict(self) -> None:
        from arvyx_control.attestation import worktree_dirty_paths
        from arvyx_control.release_candidate import _worktree_blockers

        with tempfile.TemporaryDirectory() as tmp:
            repo = self._temp_git_repo(tmp)
            self.assertEqual(worktree_dirty_paths(repo), [])
            self.assertEqual(
                _worktree_blockers({"worktree": {"clean": True, "dirty_count": 0, "dirty_paths": []}}),
                [],
            )
            (repo / "tracked.txt").write_text("two\n", encoding="utf-8")
            dirty = worktree_dirty_paths(repo)
            self.assertIsNotNone(dirty)
            self.assertEqual(len(dirty), 1)
            blockers = _worktree_blockers(
                {"worktree": {"clean": False, "dirty_count": len(dirty), "dirty_paths": dirty}}
            )

        self.assertEqual(len(blockers), 1)
        self.assertIn("worktree is not clean", blockers[0])

    def test_unresolvable_worktree_state_fails_closed(self) -> None:
        from arvyx_control.release_candidate import _worktree_blockers

        # git unavailable / not a checkout: "unknown" must not read as clean.
        self.assertTrue(_worktree_blockers({"worktree": {"clean": None}}))
        self.assertTrue(_worktree_blockers({}))

    def test_evidence_bundle_reports_worktree_state(self) -> None:
        from arvyx_control.attestation import worktree_dirty_paths
        from arvyx_control.evidence import _worktree_report

        report = _worktree_report(self.ROOT)
        dirty = worktree_dirty_paths(self.ROOT)
        self.assertIsNotNone(dirty)
        self.assertEqual(report["clean"], not dirty)
        self.assertEqual(report["dirty_count"], len(dirty))

    # --- model-review custody ----------------------------------------------

    def test_model_review_receipt_must_declare_custody(self) -> None:
        import json

        from arvyx_control.attestation import MODEL_REVIEW_CUSTODY, verify_model_review_attestation

        with tempfile.TemporaryDirectory() as tmp:
            repo = self._temp_git_repo(tmp)
            report_dir = repo / ".arvyx" / "model-reviews"
            report_dir.mkdir(parents=True)
            report = report_dir / "r.md"
            report.write_text("## Verdict\n\napprove\n", encoding="utf-8")
            import hashlib
            import subprocess

            tree = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], text=True, capture_output=True, check=True
            ).stdout.strip()
            payload = {
                "schema_version": 1,
                "subject": "release-gate",
                "status": "complete",
                "artifact_git_tree": tree,
                "policy_version": "multi-model-review-v1",
                "reviews": [
                    {
                        "reviewer_id": f"{provider}/m1",
                        "provider": provider,
                        "model": "m1",
                        "verdict": "approve",
                        "reviewed_at": "2026-09-13T00:00:00Z",
                        "scope": ["release diff"],
                        "report_path": report.relative_to(repo).as_posix(),
                        "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
                    }
                    for provider in ("prov-a", "prov-b")
                ],
                "synthesis": {
                    "decision": "approve",
                    "synthesizer": "orchestrator",
                    "synthesized_at": "2026-09-13T00:00:00Z",
                    "agreements": [],
                    "disagreements": [],
                    "resolution": "approved",
                },
            }
            ok_without, _models, error_without = verify_model_review_attestation(
                payload, repo=repo, subject="release-gate"
            )
            payload["custody"] = MODEL_REVIEW_CUSTODY
            ok_with, _models2, error_with = verify_model_review_attestation(
                payload, repo=repo, subject="release-gate"
            )

        self.assertFalse(ok_without)
        self.assertIn("custody", error_without or "")
        self.assertTrue(ok_with, error_with)

    def test_receipt_verdict_must_match_the_report_body(self) -> None:
        """A hash-bound report that says `block` may not ride in as `approve`.

        The envelope verdict is operator JSON; the report body is the reviewer's
        own words. They must agree, and a report that states no verdict fails
        closed.
        """
        import hashlib
        import subprocess

        from arvyx_control.attestation import MODEL_REVIEW_CUSTODY, verify_model_review_attestation

        def payload_for(repo: Path, report: Path, verdict: str) -> dict[str, object]:
            return {
                "schema_version": 1,
                "subject": "release-gate",
                "status": "complete",
                "artifact_git_tree": subprocess.run(
                    ["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"],
                    text=True,
                    capture_output=True,
                    check=True,
                ).stdout.strip(),
                "policy_version": "multi-model-review-v1",
                "custody": MODEL_REVIEW_CUSTODY,
                "reviews": [
                    {
                        "reviewer_id": f"{provider}/m1",
                        "provider": provider,
                        "model": "m1",
                        "verdict": verdict,
                        "reviewed_at": "2026-09-13T00:00:00Z",
                        "scope": ["release diff"],
                        "report_path": report.relative_to(repo).as_posix(),
                        "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
                    }
                    for provider in ("prov-a", "prov-b")
                ],
                "synthesis": {
                    "decision": "approve",
                    "synthesizer": "orchestrator",
                    "synthesized_at": "2026-09-13T00:00:00Z",
                    "agreements": [],
                    "disagreements": [],
                    "resolution": "approved",
                },
            }

        with tempfile.TemporaryDirectory() as tmp:
            repo = self._temp_git_repo(tmp)
            report_dir = repo / ".arvyx" / "model-reviews"
            report_dir.mkdir(parents=True)
            report = report_dir / "r.md"
            report.write_text("## Verdict\n\nblock\n\nThe tree is not releasable.\n", encoding="utf-8")
            blocking_body = payload_for(repo, report, "approve")
            ok_block, _models, error_block = verify_model_review_attestation(
                blocking_body, repo=repo, subject="release-gate"
            )
            report.write_text("no verdict section here\n", encoding="utf-8")
            silent_body = payload_for(repo, report, "approve")
            ok_silent, _models2, error_silent = verify_model_review_attestation(
                silent_body, repo=repo, subject="release-gate"
            )
            report.write_text("## Verdict\n\napprove-with-findings\n", encoding="utf-8")
            agreeing = payload_for(repo, report, "approve-with-findings")
            ok_agree, _models3, error_agree = verify_model_review_attestation(
                agreeing, repo=repo, subject="release-gate"
            )

        self.assertFalse(ok_block)
        self.assertIn("states 'block'", error_block or "")
        self.assertFalse(ok_silent)
        self.assertIn("does not state a verdict", error_silent or "")
        self.assertTrue(ok_agree, error_agree)

    # --- MCP client evidence -----------------------------------------------

    def _mcp_payload(self, **overrides: object) -> dict[str, object]:
        from datetime import UTC, datetime

        payload: dict[str, object] = {
            "schema_version": 1,
            "client": "codex",
            "checked_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "git_head": "0" * 40,
            "git_tree": "1" * 40,
            "transport": "stdio",
            "command": "python -m arvyx_control.cli mcp",
            "result": {
                "tools_list_ok": True,
                "recall_ok": True,
                "sources_returned": True,
                "private_paths_leaked": False,
            },
        }
        payload.update(overrides)
        return payload

    def _validate(self, payload: dict[str, object], tmp: str, **kwargs: object) -> dict[str, object]:
        import json

        from arvyx_control.mcp_client_evidence import validate_mcp_client_evidence

        path = Path(tmp) / "evidence.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return validate_mcp_client_evidence(path, **kwargs)

    def test_mcp_evidence_must_name_the_tree_not_only_the_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = self._mcp_payload(git_tree=None)
            missing.pop("git_tree")
            result_missing = self._validate(missing, tmp, expected_git_tree="1" * 40)
            mismatched = self._validate(self._mcp_payload(), tmp, expected_git_tree="2" * 40)
            matched = self._validate(self._mcp_payload(), tmp, expected_git_tree="1" * 40)

        self.assertFalse(result_missing["ok"])
        self.assertTrue(any("git_tree is required" in item for item in result_missing["errors"]))
        self.assertFalse(mismatched["ok"])
        self.assertTrue(any("git_tree must match" in item for item in mismatched["errors"]))
        self.assertTrue(matched["ok"], matched["errors"])

    def test_mcp_evidence_private_markers_cover_operator_paths(self) -> None:
        for marker in ("/root/", "C:" + "\\", "Authorization:", "password"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as tmp:
                payload = self._mcp_payload()
                payload["command"] = f"python -m arvyx_control.cli mcp {marker}"
                result = self._validate(payload, tmp)
                self.assertFalse(result["ok"])
                self.assertTrue(any("private marker found" in item for item in result["errors"]))


if __name__ == "__main__":
    unittest.main()
