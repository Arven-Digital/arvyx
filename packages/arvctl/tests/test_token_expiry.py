from __future__ import annotations

import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from arvyx_control.replica_authority import authority_context
from arvyx_control.agent_delivery import AgentRoute
from arvyx_control.auth import (
    TOKENS_DIR,
    expiring_tokens,
    issue_token,
    list_tokens,
    renew_token,
    resolve_identity,
    revoke_token,
)
from arvyx_control.cli import main as cli_main
from arvyx_control.control import list_thread_inbox
from arvyx_control.vault import init_vault
from arvyx_control.watchdog import _token_expiry_title, run_watchdog

UTC = timezone.utc
ROUTES = {"amir": AgentRoute("amir", "hermes-webhook", "WD_URL", "WD_SECRET")}
ENV_OK = {"WD_URL": "https://runtime.invalid/hook", "WD_SECRET": "secret-material"}


class TokenExpiryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.vault = self.root / "vault"
        init_vault(self.vault)
        self.state = self.root / "events.jsonl"
        self.enterContext(authority_context(self.vault, self.state))

    def _record(self, agent: str, slot: str) -> dict[str, object]:
        return next(
            record.to_dict() for record in list_tokens(self.vault).tokens
            if record.agent_id == agent and record.slot == slot
        )

    def test_reports_expired_and_soon_expiring_live_tokens_only(self) -> None:
        issue_token(self.vault, "demobot", scopes=["memory.read"], ttl_days=30, slot="presence")
        issue_token(self.vault, "demobot", scopes=["secret.inspect"], ttl_days=3, slot="provider")
        issue_token(self.vault, "vesper", scopes=["memory.read"], ttl_days=1, slot="gone")
        revoke_token(self.vault, "vesper", slot="gone")
        now = datetime.now(UTC)

        soon = expiring_tokens(self.vault, now=now)
        self.assertEqual([(t["agent_id"], t["slot"], t["expired"]) for t in soon], [("demobot", "provider", False)])

        later = expiring_tokens(self.vault, now=now + timedelta(days=26))
        self.assertEqual(
            [(t["agent_id"], t["slot"], t["expired"]) for t in later],
            [("demobot", "provider", True), ("demobot", "presence", False)],
        )
        for token in later:  # metadata only
            self.assertEqual(set(token), {"agent_id", "slot", "expires_at", "expired"})

    def test_renew_keeps_scopes_and_retires_the_old_token(self) -> None:
        old = issue_token(self.vault, "demobot", scopes=["secret.inspect"], ttl_days=1, slot="provider").token
        renewed = renew_token(self.vault, "demobot", slot="provider", ttl_days=30)

        self.assertEqual(renewed.scopes, ["secret.inspect"])
        self.assertNotEqual(renewed.token, old)
        self.assertIsNone(resolve_identity(self.vault, f"Bearer {old}"))
        identity = resolve_identity(self.vault, f"Bearer {renewed.token}")
        self.assertIsNotNone(identity)
        self.assertEqual(identity.scopes, frozenset({"secret.inspect"}))
        expires = datetime.fromisoformat(str(self._record("demobot", "provider")["expires_at"]).replace("Z", "+00:00"))
        self.assertGreater(expires - datetime.now(UTC), timedelta(days=29))

    def test_renew_refuses_a_revoked_or_missing_slot(self) -> None:
        issue_token(self.vault, "demobot", scopes=["memory.read"], slot="old")
        revoke_token(self.vault, "demobot", slot="old")
        with self.assertRaisesRegex(ValueError, "revoked"):
            renew_token(self.vault, "demobot", slot="old")
        with self.assertRaisesRegex(ValueError, "no token slot"):
            renew_token(self.vault, "demobot", slot="never-issued")

    def test_cli_renew_puts_only_the_token_on_stdout(self) -> None:
        issue_token(self.vault, "demobot", scopes=["memory.read"], ttl_days=2, slot="presence")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli_main(["auth", "renew", "demobot", "--slot", "presence", "--vault", str(self.vault)])
        self.assertEqual(code, 0)
        token = out.getvalue()
        self.assertRegex(token, r"^arv_demobot_[0-9a-f]{40}$")
        meta = json.loads(err.getvalue())
        self.assertEqual(meta["renewed"], "demobot/presence")
        self.assertNotIn(token, err.getvalue())
        self.assertIsNotNone(resolve_identity(self.vault, f"Bearer {token}"))

    def _tick(self, now: datetime, **kwargs: object) -> dict[str, object]:
        return run_watchdog(
            self.state, routes=ROUTES, environ=ENV_OK, now=now, vault=self.vault,
            token_expiry_target="amir", **kwargs,
        )

    def _warnings(self) -> list[str]:
        return [
            thread.title for thread in list_thread_inbox(state=self.state, target="amir").threads
            if thread.title.startswith("watchdog token expiry:")
        ]

    def test_watchdog_warns_the_target_once_per_expiry_and_again_after_renewal(self) -> None:
        issue_token(self.vault, "demobot", scopes=["memory.read"], ttl_days=5, slot="presence")
        now = datetime.now(UTC)

        first = self._tick(now)
        self.assertIn("tokens_expiring", first["attention"])
        self.assertEqual(first["counts"]["tokens_warned"], 1)
        self.assertEqual(len(self._warnings()), 1)
        self.assertNotIn("arv_", json.dumps(first))

        second = self._tick(now + timedelta(minutes=1))
        self.assertIn("tokens_expiring", second["attention"])
        self.assertEqual(second["counts"]["tokens_warned"], 0)
        self.assertEqual(len(self._warnings()), 1)

        renew_token(self.vault, "demobot", slot="presence", ttl_days=30)
        calm = self._tick(now + timedelta(minutes=2))
        self.assertNotIn("tokens_expiring", calm["attention"])
        cycle = self._tick(now + timedelta(days=24))
        self.assertEqual(cycle["counts"]["tokens_warned"], 1)
        self.assertEqual(len(self._warnings()), 2)

    def test_watchdog_without_vault_or_with_no_escalate_posts_nothing(self) -> None:
        issue_token(self.vault, "demobot", scopes=["memory.read"], ttl_days=1, slot="presence")
        now = datetime.now(UTC)
        report = run_watchdog(self.state, routes=ROUTES, environ=ENV_OK, now=now)
        self.assertNotIn("tokens_expiring", report["attention"])
        muted = self._tick(now, escalate=False)
        self.assertIn("tokens_expiring", muted["attention"])
        self.assertEqual(self._warnings(), [])

    # -- a registry that cannot be read must be reported, never fatal -------------

    def _write_raw_record(self, filename: str, payload: object) -> None:
        directory = self.vault / TOKENS_DIR
        directory.mkdir(parents=True, exist_ok=True)
        (directory / filename).write_text(json.dumps(payload), encoding="utf-8")

    def test_records_that_cannot_be_compared_are_reported_not_raised(self) -> None:
        """A timezone-less or non-object record must not abort the sweep."""
        self._write_raw_record("naive.json", {
            "agent_id": "keeper", "slot": "provider", "scopes": ["memory.read"],
            "expires_at": "2026-09-26T00:00:00", "revoked": False,
        })
        self._write_raw_record("notanobject.json", ["not", "an", "object"])
        self._write_raw_record("noexpiry.json", {
            "agent_id": "keeper", "slot": "job", "scopes": ["memory.read"],
            "expires_at": None, "revoked": False,
        })
        self._write_raw_record("nullscopes.json", {
            "agent_id": "vesper", "slot": "gone", "scopes": None,
            "expires_at": "2030-01-01T00:00:00Z", "revoked": False,
        })

        records = list_tokens(self.vault).tokens
        self.assertEqual(len(records), 3)  # the non-object file is skipped, not fatal
        self.assertEqual(
            next(r.expires_at for r in records if r.slot == "job"), "",
            "a null expiry must read as 'never expires', not the literal 'None'",
        )
        self.assertEqual(next(r.scopes for r in records if r.slot == "gone"), [])

        found = expiring_tokens(self.vault, now=datetime(2026, 9, 25, tzinfo=UTC))
        self.assertEqual([(t["slot"], t["malformed"]) for t in found], [("provider", True)])
        self.assertTrue(found[0]["expired"], "an unreadable expiry must be surfaced, not hidden")

    def test_watchdog_tick_survives_a_record_it_cannot_compare(self) -> None:
        self._write_raw_record("naive.json", {
            "agent_id": "keeper", "slot": "provider", "scopes": ["memory.read"],
            "expires_at": "2026-09-26T00:00:00", "revoked": False,
        })
        report = self._tick(datetime(2026, 9, 25, tzinfo=UTC))
        self.assertIn("tokens_expiring", report["attention"])
        self.assertEqual(report["token_expiry_error"], "")
        self.assertTrue(report["tick_recorded"], "the tick must still complete and be recorded")

    def test_watchdog_reports_a_registry_failure_instead_of_dying(self) -> None:
        issue_token(self.vault, "demobot", scopes=["memory.read"], ttl_days=5, slot="presence")
        with mock.patch("arvyx_control.watchdog.expiring_tokens", side_effect=OSError("registry unreadable")):
            report = self._tick(datetime.now(UTC))
        self.assertEqual(report["token_expiry_error"], "OSError")
        self.assertIn("token_expiry_check_failed", report["attention"])
        # An unreadable registry is not the same claim as "nothing is expiring".
        self.assertNotIn("tokens_expiring", report["attention"])
        self.assertTrue(report["tick_recorded"])
        self.assertEqual(self._warnings(), [])

    def test_expiry_title_matches_the_stripped_title_post_thread_stores(self) -> None:
        self.assertEqual(
            _token_expiry_title({"agent_id": "keeper", "slot": "provider",
                                 "expires_at": " 2026-10-19T00:00:00Z "}),
            "watchdog token expiry: keeper/provider 2026-10-19T00:00:00Z",
        )


if __name__ == "__main__":
    unittest.main()
