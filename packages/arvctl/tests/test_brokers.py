from __future__ import annotations

from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import uuid
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from arvyx_control.api import handle_api_request, make_handler
from arvyx_control.auth import issue_token
from arvyx_control.brokers import (
    BrokerError,
    find_secret_refs,
    is_secret_ref,
    resolve_ref,
)
from arvyx_control.cli import main
from arvyx_control import mcp as mcp_module
from arvyx_control.mcp import handle_json_line
from arvyx_control.security import contains_literal_secret, redact_secrets
from arvyx_control.vault import init_vault
from arvyx_control.writes import suggest_memory


def _write_config(repo: Path, brokers: dict) -> None:
    (repo / ".arvyx").mkdir(parents=True, exist_ok=True)
    (repo / ".arvyx" / "secret-brokers.json").write_text(
        json.dumps({"brokers": brokers}), encoding="utf-8"
    )


class RefDetectionTests(unittest.TestCase):
    def test_is_secret_ref(self) -> None:
        self.assertTrue(is_secret_ref("secret://railway/DATABASE_URL"))
        self.assertFalse(is_secret_ref("postgres://user:pw@host/db"))
        self.assertFalse(is_secret_ref("just some text"))

    def test_find_refs_dedupes(self) -> None:
        text = "creds at secret://op/DEMO-DB and again secret://op/DEMO-DB plus secret://env/TOKEN"
        refs = [r.uri for r in find_secret_refs(text)]
        self.assertEqual(refs, ["secret://op/DEMO-DB", "secret://env/TOKEN"])

    def test_refs_survive_redaction_but_literals_do_not(self) -> None:
        text = "db = secret://railway/DATABASE_URL ; leaked token=ghp_" + "a" * 24
        redacted = redact_secrets(text)
        self.assertIn("secret://railway/DATABASE_URL", redacted)
        self.assertIn("[REDACTED-SECRET]", redacted)
        self.assertNotIn("ghp_" + "a" * 24, redacted)

    def test_literal_secret_detection_ignores_refs(self) -> None:
        self.assertFalse(contains_literal_secret("pointer: secret://op/thing/field"))
        self.assertTrue(contains_literal_secret("password = hunter2hunter2"))

    def test_secret_shaped_material_cannot_hide_inside_a_reference(self) -> None:
        marker = "ghp_" + "a" * 24
        malicious_ref = f"secret://op/{marker}"
        self.assertFalse(is_secret_ref(malicious_ref))
        self.assertEqual(find_secret_refs(malicious_ref), [])
        self.assertTrue(contains_literal_secret(malicious_ref))
        redacted = redact_secrets(malicious_ref)
        self.assertNotIn(marker, redacted)
        self.assertIn("[REDACTED-SECRET]", redacted)


class ProviderResolutionTests(unittest.TestCase):
    def test_envfile_removes_only_one_matching_outer_quote_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            envfile = repo / 'synthetic.env'
            _write_config(repo, {'local': {'provider': 'envfile', 'path': str(envfile)}})
            cases = [('"abc\'"', "abc'"), ("'abc\"'", 'abc"'),
                     ('"\'abc\'"', "'abc'"), ('abc\'', "abc'"),
                     ('"abc', '"abc'), ('""', '')]
            for encoded, expected in cases:
                with self.subTest(encoded=encoded):
                    envfile.write_text('DB=' + encoded + '\n', encoding='utf-8')
                    if expected:
                        self.assertEqual(resolve_ref('secret://local/DB', repo=repo).value, expected)
                    else:
                        with self.assertRaises(BrokerError):
                            resolve_ref('secret://local/DB', repo=repo)

    def test_env_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write_config(repo, {"env": {"provider": "env", "prefix": "ARVTEST_"}})
            with mock.patch.dict(os.environ, {"ARVTEST_DB": "s3cr3t-value"}):
                result = resolve_ref("secret://env/DB", repo=repo)
            self.assertEqual(result.value, "s3cr3t-value")
            self.assertEqual(result.provider, "env")

    def test_envfile_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            envfile = repo / "railway.env"
            envfile.write_text("# comment\nDATABASE_URL='postgres://u:p@h/db'\nOTHER=x\n", encoding="utf-8")
            _write_config(repo, {"railway": {"provider": "envfile", "path": str(envfile)}})
            result = resolve_ref("secret://railway/DATABASE_URL", repo=repo)
            self.assertEqual(result.value, "postgres://u:p@h/db")

    def test_file_provider_contains_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            base = repo / "secrets"
            base.mkdir()
            (base / "project-a.env").write_text("supabase-key-value", encoding="utf-8")
            _write_config(repo, {"files": {"provider": "file", "base": str(base)}})
            self.assertEqual(resolve_ref("secret://files/project-a.env", repo=repo).value, "supabase-key-value")
            with self.assertRaises(BrokerError):
                resolve_ref("secret://files/../../etc/passwd", repo=repo)

    @unittest.skipUnless(os.name == 'posix', 'the owned-command broker supervises with POSIX process groups and is POSIX-only')
    def test_command_provider_no_shell_injection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            # a fake "op read" that echoes op://<path>; {path} is a single argv element
            _write_config(
                repo,
                {"op": {"provider": "command", "command": [sys.executable, "-c", "import sys;print('resolved:'+sys.argv[1])", "{path}"]}},
            )
            result = resolve_ref("secret://op/Example/DEMO-DB/credential", repo=repo)
            self.assertEqual(result.value, "resolved:Example/DEMO-DB/credential")

    def test_unknown_broker_and_bad_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write_config(repo, {"env": {"provider": "env"}})
            with self.assertRaises(BrokerError):
                resolve_ref("secret://nope/X", repo=repo)
            with self.assertRaises(BrokerError):
                resolve_ref("not-a-ref", repo=repo)

    def test_error_never_contains_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _write_config(
                repo,
                {"op": {"provider": "command", "command": ["python", "-c", "import sys;sys.stderr.write('leak-guard-value');sys.exit(3)", "{path}"]}},
            )
            with self.assertRaises(BrokerError) as caught:
                resolve_ref("secret://op/x", repo=repo)
            self.assertNotIn("leak-guard-value", str(caught.exception))


class BrokerHttpScopeTests(unittest.TestCase):
    def _serve(self, vault, state, **kwargs):
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(vault=vault, state=state, **kwargs))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, f"http://127.0.0.1:{server.server_port}"

    def _post(self, url, body, token):
        data = json.dumps(body).encode("utf-8")
        req = Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": f"test-{uuid.uuid4().hex}",
            },
            method="POST",
        )
        try:
            with urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_resolve_requires_scope_and_audits_ref_not_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            audit = Path(tmp) / "audit.jsonl"
            _write_config(vault, {"env": {"provider": "env", "prefix": "ARVHTTP_"}})

            allowed = issue_token(vault, "demobot", scopes=["secret.resolve"]).token
            denied = issue_token(vault, "vesper", scopes=["memory.read"]).token

            server, thread, base = self._serve(vault, state, mcp_profile="operator", audit_log=audit)
            try:
                with mock.patch.dict(os.environ, {"ARVHTTP_DB": "topsecret-http"}):
                    status, body = self._post(f"{base}/secret/resolve", {"ref": "secret://env/DB"}, allowed)
                    self.assertEqual(status, 200)
                    self.assertEqual(body["body"]["value"], "topsecret-http")

                    status2, _ = self._post(f"{base}/secret/resolve", {"ref": "secret://env/DB"}, denied)
                    self.assertEqual(status2, 403)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            audit_text = audit.read_text(encoding="utf-8")
            self.assertIn("secret://env/DB", audit_text)      # ref is logged
            self.assertNotIn("topsecret-http", audit_text)    # value is never logged

    def test_resolve_fails_closed_when_audit_log_is_unwritable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            blocker = Path(tmp) / "blocker"
            blocker.write_text("x", encoding="utf-8")
            bad_log = blocker / "audit.jsonl"
            _write_config(vault, {"env": {"provider": "env", "prefix": "ARVHTTP_"}})
            token = issue_token(vault, "demobot", scopes=["secret.resolve"]).token

            with mock.patch.dict(os.environ, {"ARVHTTP_DB": "topsecret-http"}):
                direct = handle_api_request(
                    "POST",
                    "/secret/resolve",
                    {"ref": "secret://env/DB"},
                    vault=vault,
                    state=state,
                    audit_log=bad_log,
                    authorization=f"Bearer {token}",
                    idempotency_key="direct-audit-failure-0001",
                )
                via_mcp = handle_api_request(
                    "POST",
                    "/mcp",
                    {
                        "jsonrpc": "2.0",
                        "id": "secret",
                        "method": "tools/call",
                        "params": {"name": "secret.resolve", "arguments": {"ref": "secret://env/DB"}},
                    },
                    vault=vault,
                    state=state,
                    audit_log=bad_log,
                    authorization=f"Bearer {token}",
                    mcp_profile="operator",
                    idempotency_key="mcp-audit-failure-000001",
                )

            self.assertEqual(direct.status, 503)
            self.assertEqual(via_mcp.status, 503)
            self.assertNotIn("topsecret-http", json.dumps(direct.body))
            self.assertNotIn("topsecret-http", json.dumps(via_mcp.body))

    def test_failed_mcp_secret_resolve_audits_error_decision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            audit = Path(tmp) / "audit.jsonl"
            _write_config(vault, {"env": {"provider": "env", "prefix": "ARVHTTP_"}})
            token = issue_token(vault, "demobot", scopes=["secret.resolve"]).token

            response = handle_api_request(
                "POST",
                "/mcp",
                {
                    "jsonrpc": "2.0",
                    "id": "secret",
                    "method": "tools/call",
                    "params": {"name": "secret.resolve", "arguments": {"ref": "secret://missing/DB"}},
                },
                vault=vault,
                state=state,
                audit_log=audit,
                authorization=f"Bearer {token}",
                mcp_profile="operator",
                idempotency_key="failed-mcp-secret-000001",
            )

            self.assertEqual(response.status, 200)
            self.assertIn("error", response.body)
            event = json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])
            self.assertEqual(event["decision"], "error")
            self.assertEqual(event["secret_ref"], "secret://missing/DB")

    def test_suggest_allows_ref_but_refuses_literal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            ok = suggest_memory(
                vault=vault,
                project="demo-agent",
                title="RVN database",
                content="Connection lives at secret://railway/DATABASE_URL - resolve at runtime.",
                author="demobot",
            )
            self.assertTrue(ok.path)
            with self.assertRaises(ValueError):
                suggest_memory(
                    vault=vault,
                    project="demo-agent",
                    title="leak",
                    content="password = hunter2hunter2",
                    author="demobot",
                )

    def test_stdio_mcp_secret_resolve_audits_ref_not_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            audit = Path(tmp) / "audit.jsonl"
            _write_config(vault, {"env": {"provider": "env", "prefix": "ARVSTDIO_"}})
            request = {
                "jsonrpc": "2.0",
                "id": "secret",
                "method": "tools/call",
                "params": {
                    "name": "secret.resolve",
                    "arguments": {
                        "ref": "secret://env/DB",
                        "idempotency_key": "-".join(("stdio", "secret", "resolve", "0001")),
                    },
                },
            }

            with mock.patch.dict(os.environ, {"ARVSTDIO_DB": "topsecret-stdio"}):
                response = handle_json_line(
                    json.dumps(request),
                    vault=vault,
                    allowed_tools={"secret.resolve"},
                    secret_audit_log=audit,
                    require_secret_audit=True,
                )

            self.assertIsNotNone(response)
            payload = json.loads(str(response))
            self.assertEqual(payload["result"]["structuredContent"]["value"], "topsecret-stdio")
            audit_text = audit.read_text(encoding="utf-8")
            self.assertIn("secret://env/DB", audit_text)
            self.assertNotIn("topsecret-stdio", audit_text)

    def test_stdio_secret_outcome_failure_withholds_value_and_retry_does_not_recall_broker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            audit = Path(tmp) / "audit.jsonl"
            _write_config(vault, {"env": {"provider": "env", "prefix": "ARVSTDIO_"}})
            request = {
                "jsonrpc": "2.0",
                "id": "secret",
                "method": "tools/call",
                "params": {
                    "name": "secret.resolve",
                    "arguments": {
                        "ref": "secret://env/DB",
                        "idempotency_key": "-".join(("stdio", "secret", "failure", "0001")),
                    },
                },
            }
            real_append = mcp_module.append_audit_once

            def fail_outcome(path, event):
                if event.get("phase") == "outcome":
                    raise OSError("synthetic stdio outcome failure")
                return real_append(path, event)

            with mock.patch.dict(os.environ, {"ARVSTDIO_DB": "topsecret-stdio"}), mock.patch.object(
                mcp_module, "append_audit_once", side_effect=fail_outcome
            ):
                first = handle_json_line(
                    json.dumps(request), vault=vault, allowed_tools={"secret.resolve"},
                    secret_audit_log=audit, require_secret_audit=True,
                )
            self.assertIsNotNone(first)
            self.assertIn("error", json.loads(str(first)))
            self.assertNotIn("topsecret-stdio", str(first))

            with mock.patch.object(mcp_module, "resolve_ref", side_effect=AssertionError("broker repeated")):
                retry = handle_json_line(
                    json.dumps(request), vault=vault, allowed_tools={"secret.resolve"},
                    secret_audit_log=audit, require_secret_audit=True,
                )
            self.assertIsNotNone(retry)
            self.assertIn("error", json.loads(str(retry)))
            self.assertNotIn("topsecret-stdio", str(retry))

    def test_stdio_mcp_secret_resolve_fails_closed_without_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            _write_config(vault, {"env": {"provider": "env", "prefix": "ARVSTDIO_"}})
            request = {
                "jsonrpc": "2.0",
                "id": "secret",
                "method": "tools/call",
                "params": {"name": "secret.resolve", "arguments": {"ref": "secret://env/DB"}},
            }

            with mock.patch.dict(os.environ, {"ARVSTDIO_DB": "topsecret-stdio"}):
                response = handle_json_line(
                    json.dumps(request),
                    vault=vault,
                    allowed_tools={"secret.resolve"},
                    require_secret_audit=True,
                )

            self.assertIsNotNone(response)
            payload = json.loads(str(response))
            self.assertIn("error", payload)
            self.assertNotIn("topsecret-stdio", response or "")

    def test_cli_secret_resolve_fails_closed_when_audit_log_is_unwritable(self) -> None:
        from contextlib import redirect_stdout
        from io import StringIO

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            blocker = Path(tmp) / "blocker"
            blocker.write_text("x", encoding="utf-8")
            bad_log = blocker / "audit.jsonl"
            _write_config(repo, {"env": {"provider": "env", "prefix": "ARVCLI_"}})
            out = StringIO()
            with mock.patch.dict(os.environ, {"ARVCLI_DB": "topsecret-cli"}):
                with redirect_stdout(out):
                    code = main(
                        ["--authority-vault", str(Path(tmp) / "authority-vault"),
                            "secret",
                            "resolve",
                            "secret://env/DB",
                            "--repo",
                            str(repo),
                            "--audit-log",
                            str(bad_log),
                        ]
                    )

            self.assertEqual(code, 1)
            self.assertNotIn("topsecret-cli", out.getvalue())

    def test_cli_secret_resolve_audits_before_printing_value(self) -> None:
        from contextlib import redirect_stdout
        from io import StringIO

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            audit = Path(tmp) / "audit.jsonl"
            _write_config(repo, {"env": {"provider": "env", "prefix": "ARVCLI_"}})
            out = StringIO()
            with mock.patch.dict(os.environ, {"ARVCLI_DB": "topsecret-cli"}):
                with redirect_stdout(out):
                    code = main(
                        ["--authority-vault", str(Path(tmp) / "authority-vault"),
                            "secret",
                            "resolve",
                            "secret://env/DB",
                            "--repo",
                            str(repo),
                            "--audit-log",
                            str(audit),
                        ]
                    )

            self.assertEqual(code, 0)
            self.assertEqual(out.getvalue().strip(), "topsecret-cli")
            audit_text = audit.read_text(encoding="utf-8")
            self.assertIn("secret://env/DB", audit_text)
            self.assertNotIn("topsecret-cli", audit_text)


if __name__ == "__main__":
    unittest.main()
