from __future__ import annotations

from contextlib import closing, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.replica_authority import authority_context
from arvyx_control.cli import main
from arvyx_control.control import (
    acknowledge_thread,
    complete_thread,
    list_pending_threads,
    list_thread_inbox,
    post_thread,
    post_thread_message,
    read_all_threads,
    read_events,
    read_thread,
)
from arvyx_control.store import sync_sqlite


class ThreadLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "events.jsonl"
        self.vault = Path(self._tmp.name) / "vault"
        self.vault.mkdir()
        self.enterContext(authority_context(self.vault, self.state))

    def test_ask_appears_in_target_pending_inbox(self) -> None:
        result = post_thread(
            state=self.state,
            title="Daily health check",
            body="Run synthetic checks.",
            thread_type="ask",
            actor="demobot",
            target="vesper",
            channel="demo-agent",
        )
        pending = list_pending_threads(state=self.state, target="vesper")
        self.assertEqual([thread.id for thread in pending.threads], [result.thread.id])
        self.assertTrue(pending.threads[0].pending)
        self.assertTrue(pending.threads[0].unread)
        inbox = list_thread_inbox(state=self.state, target="vesper")
        self.assertEqual([thread.id for thread in inbox.threads], [result.thread.id])
        # not in anyone else's inbox or pending list
        self.assertEqual(list_pending_threads(state=self.state, target="demobot").threads, [])
        self.assertEqual(list_thread_inbox(state=self.state, target="demobot").threads, [])

    def test_actionable_threads_require_a_concrete_target(self) -> None:
        for thread_type in ("ask", "handoff", "blocker"):
            with self.subTest(thread_type=thread_type):
                with self.assertRaisesRegex(ValueError, "concrete agent target"):
                    post_thread(
                        state=self.state,
                        title=f"Invalid {thread_type} broadcast",
                        thread_type=thread_type,
                        actor="odin",
                        target="all",
                    )

    def test_status_and_update_may_use_global_pull_only_target(self) -> None:
        for thread_type in ("status", "update"):
            with self.subTest(thread_type=thread_type):
                created = post_thread(
                    state=self.state,
                    title=f"Global {thread_type}",
                    thread_type=thread_type,
                    actor="odin",
                    target="all",
                )
                self.assertEqual(created.thread.target, "all")
                self.assertFalse(created.thread.pending)

    def test_global_broadcast_appears_in_every_agent_inbox(self) -> None:
        created = post_thread(
            state=self.state,
            title="Fleet-wide status",
            thread_type="status",
            actor="odin",
            target="all",
        )
        for agent in ("amir", "esme", "kiran", "odin"):
            with self.subTest(agent=agent):
                inbox = list_thread_inbox(state=self.state, target=agent)
                self.assertIn(created.thread.id, {thread.id for thread in inbox.threads})
                projected = next(thread for thread in inbox.threads if thread.id == created.thread.id)
                self.assertFalse(projected.unread)

    def test_broadcast_reply_is_idempotent_linear_and_keeps_parent_read(self) -> None:
        created = post_thread(
            state=self.state,
            title="Fleet-wide status",
            thread_type="status",
            actor="odin",
            target="all",
        )
        first = post_thread_message(
            self.state,
            created.thread.id,
            "Amir received.",
            actor="amir",
            idempotency_key="outbox-broadcast-amir-0001",
        )
        repeated = post_thread_message(
            self.state,
            created.thread.id,
            "Amir received.",
            actor="amir",
            idempotency_key="outbox-broadcast-amir-0001",
        )
        projected = next(
            thread for thread in list_thread_inbox(self.state, target="amir").threads
            if thread.id == created.thread.id
        )
        reply_events = [event for event in read_events(self.state) if event.type == "thread.message.posted"]
        self.assertEqual(first.event.id, repeated.event.id)
        self.assertEqual(len(reply_events), 1)
        self.assertNotIn("messages", reply_events[0].payload)
        self.assertEqual([message.actor for message in projected.messages], ["amir"])
        self.assertFalse(projected.unread)
        self.assertIsInstance(hash(projected), int)
        with self.assertRaisesRegex(ValueError, "non-actionable thread cannot be acknowledged"):
            acknowledge_thread(self.state, created.thread.id, actor="operator")
        with self.assertRaisesRegex(ValueError, "non-actionable thread cannot be completed"):
            complete_thread(self.state, created.thread.id, actor="operator")

    def test_thread_actor_must_be_concrete(self) -> None:
        with self.assertRaisesRegex(ValueError, "concrete actor"):
            post_thread(
                state=self.state,
                title="Invalid global actor",
                thread_type="ask",
                actor=" ALL ",
                target="vesper",
            )
        self.assertFalse(self.state.exists())

    def test_ack_keeps_thread_pending(self) -> None:
        created = post_thread(state=self.state, title="Fix the relay", thread_type="ask", target="vesper", actor="demobot")
        acked = acknowledge_thread(state=self.state, thread_id=created.thread.id, actor="vesper", text="Taking this.")
        self.assertEqual(acked.thread.status, "acked")
        self.assertEqual(acked.thread.acked_by, "vesper")
        self.assertNotEqual(acked.thread.acked_at, "")
        self.assertTrue(acked.thread.pending)
        pending = list_pending_threads(state=self.state, target="vesper")
        self.assertEqual([thread.id for thread in pending.threads], [created.thread.id])
        self.assertEqual(pending.threads[0].status, "acked")

    def test_done_removes_thread_from_pending(self) -> None:
        created = post_thread(state=self.state, title="Ship the fix", thread_type="ask", target="vesper", actor="demobot")
        acknowledge_thread(state=self.state, thread_id=created.thread.id, actor="vesper")
        done = complete_thread(state=self.state, thread_id=created.thread.id, actor="vesper", text="Done with receipts.")
        self.assertEqual(done.thread.status, "done")
        self.assertFalse(done.thread.pending)
        self.assertEqual(list_pending_threads(state=self.state, target="vesper").threads, [])
        # still visible in the inbox history
        inbox = list_thread_inbox(state=self.state, target="vesper")
        self.assertEqual([thread.id for thread in inbox.threads], [created.thread.id])

    def test_completion_contract_requires_exact_artifact_evidence(self) -> None:
        created = post_thread(
            state=self.state,
            title="Update canonical user memory",
            thread_type="ask",
            target="vesper",
            completion_artifact="/home/vesper/.hermes/memories/USER.md",
            completion_anchor="0bserverx", actor="demobot")

        with self.assertRaisesRegex(ValueError, "completion evidence is required"):
            complete_thread(state=self.state, thread_id=created.thread.id, actor="vesper")
        with self.assertRaisesRegex(ValueError, "artifact does not match"):
            complete_thread(
                state=self.state,
                thread_id=created.thread.id,
                actor="vesper",
                evidence_artifact="agents/vesper/raw/2026-08-20/note.md",
                evidence_anchor="0bserverx",
                evidence_method="direct-read",
            )
        with self.assertRaisesRegex(ValueError, "anchor does not match"):
            complete_thread(
                state=self.state,
                thread_id=created.thread.id,
                actor="vesper",
                evidence_artifact="/home/vesper/.hermes/memories/USER.md",
                evidence_anchor="wrong-anchor",
                evidence_method="direct-read",
            )

        done = complete_thread(
            state=self.state,
            thread_id=created.thread.id,
            actor="vesper",
            evidence_artifact="/home/vesper/.hermes/memories/USER.md",
            evidence_anchor="0bserverx",
            evidence_method="direct-read",
        )
        self.assertEqual(done.thread.status, "done")
        self.assertEqual(done.thread.completion_artifact, "/home/vesper/.hermes/memories/USER.md")
        self.assertEqual(done.thread.completion_anchor, "0bserverx")
        self.assertEqual(done.thread.evidence_artifact, "/home/vesper/.hermes/memories/USER.md")
        self.assertEqual(done.thread.evidence_anchor, "0bserverx")
        self.assertEqual(done.thread.evidence_method, "direct-read")
        projected = list_thread_inbox(state=self.state, target="vesper").threads[0]
        self.assertEqual(projected.to_dict(), done.thread.to_dict())

    def test_completion_mismatch_explains_literal_contract_without_recording_done(self) -> None:
        artifact = "Message delivered to the target own session"
        anchor = "telegram_own_session_message_id"
        created = post_thread(
            state=self.state, title="Synthetic own-session receipt", target="vesper",
            completion_artifact=artifact, completion_anchor=anchor, actor="demobot")
        acknowledge_thread(self.state, created.thread.id, actor="vesper")
        before = self.state.read_bytes()
        for field, supplied in (
            ("artifact", {"evidence_artifact": "telegram://example/123", "evidence_anchor": anchor}),
            ("anchor", {"evidence_artifact": artifact, "evidence_anchor": "123"}),
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValueError) as caught:
                    complete_thread(
                        self.state, created.thread.id, actor="vesper",
                        evidence_method="api-readback", **supplied,
                    )
                error = str(caught.exception)
                self.assertIn(f"{field} does not match", error)
                self.assertIn(f"evidence_{field} must exactly equal completion_{field}", error)
                self.assertIn("literal expected values, not evidence kinds or placeholders", error)
                self.assertIn("control.thread_get", error)
                self.assertIn("report the contract blocker to the requester", error)
                self.assertIn("Do not copy an unverified value", error)
                self.assertIn("does not establish delivery", error)
                self.assertEqual(self.state.read_bytes(), before)
                pending = list_pending_threads(self.state, target="vesper").threads
                self.assertEqual([thread.id for thread in pending], [created.thread.id])
                self.assertEqual(pending[0].status, "acked")
                self.assertEqual(pending[0].evidence_anchor, "")

    def test_reply_artifact_contract_requires_target_authored_exact_anchor_message(self) -> None:
        with self.assertRaisesRegex(ValueError, "must exactly name the concrete thread target"):
            post_thread(
                state=self.state,
                title="Invalid reply contract",
                thread_type="ask",
                actor="demobot",
                target="vesper",
                completion_artifact="control thread reply authored by Vesper",
                completion_anchor="REPLY_OK",
            )
        created = post_thread(
            state=self.state,
            title="Reply evidence canary",
            body="Reply then complete.",
            thread_type="ask",
            actor="demobot",
            target="vesper",
            completion_artifact="control thread reply authored by vesper",
            completion_anchor="REPLY_OK",
        )
        kwargs = {
            "state": self.state,
            "thread_id": created.thread.id,
            "actor": "vesper",
            "evidence_artifact": "control thread reply authored by vesper",
            "evidence_anchor": "REPLY_OK",
            "evidence_method": "api-readback",
        }
        with self.assertRaisesRegex(ValueError, "target-authored exact anchor reply"):
            complete_thread(**kwargs)
        post_thread_message(
            state=self.state,
            thread_id=created.thread.id,
            actor="demobot",
            text="REPLY_OK",
        )
        with self.assertRaisesRegex(ValueError, "target-authored exact anchor reply"):
            complete_thread(**kwargs)
        post_thread_message(
            state=self.state,
            thread_id=created.thread.id,
            actor="vesper",
            text="REPLY_OK",
        )
        done = complete_thread(**kwargs)
        self.assertEqual(done.thread.status, "done")

    def test_completion_contract_validation_and_evidence_bounds(self) -> None:
        with self.assertRaisesRegex(ValueError, "actionable threads"):
            post_thread(
                state=self.state,
                title="Impossible contract",
                thread_type="status",
                target="vesper",
                completion_artifact="/tmp/result",
                completion_anchor="expected", actor="demobot")
        with self.assertRaisesRegex(ValueError, "must be provided together"):
            post_thread(
                state=self.state,
                title="Partial contract",
                target="vesper",
                completion_artifact="/tmp/result", actor="demobot")
        contracted = post_thread(
            state=self.state,
            title="Method vocabulary",
            target="vesper",
            completion_artifact="/tmp/result",
            completion_anchor="expected", actor="demobot")
        with self.assertRaisesRegex(ValueError, "evidence_method must be one of"):
            complete_thread(
                state=self.state,
                thread_id=contracted.thread.id,
                evidence_artifact="/tmp/result",
                evidence_anchor="expected",
                evidence_method="x",
            )
        legacy = post_thread(state=self.state, title="Legacy bounds", target="vesper", actor="demobot")
        with self.assertRaisesRegex(ValueError, "uncontracted thread"):
            complete_thread(
                state=self.state,
                thread_id=legacy.thread.id,
                evidence_artifact="/tmp/result",
                evidence_anchor="self-asserted",
                evidence_method="direct-read",
            )
        with self.assertRaisesRegex(ValueError, "evidence_method must not exceed 64"):
            complete_thread(
                state=self.state,
                thread_id=legacy.thread.id,
                evidence_method="x" * 65,
            )

    def test_done_works_without_ack(self) -> None:
        created = post_thread(state=self.state, title="Quick blocker", thread_type="blocker", target="vesper", actor="demobot")
        done = complete_thread(state=self.state, thread_id=created.thread.id, actor="vesper")
        self.assertEqual(done.thread.status, "done")
        self.assertFalse(done.thread.pending)

    def test_delegated_thread_can_bind_to_acked_parent_owned_by_actor(self) -> None:
        parent = post_thread(
            state=self.state, title="Restore drill", actor="odin", target="amir"
        )
        acknowledge_thread(
            state=self.state,
            thread_id=parent.thread.id,
            actor="amir",
            actor_identity_bound=True,
        )

        child = post_thread(
            state=self.state,
            title="Verify SOPS canary",
            actor="amir",
            target="kiran",
            continuation_thread_id=parent.thread.id,
            actor_identity_bound=True,
        )

        self.assertEqual(child.thread.continuation_thread_id, parent.thread.id)
        projected = list_thread_inbox(state=self.state, target="kiran").threads[0]
        self.assertEqual(projected.continuation_thread_id, parent.thread.id)

    def test_delegated_thread_rejects_foreign_or_unacked_parent(self) -> None:
        parent = post_thread(
            state=self.state, title="Restore drill", actor="odin", target="amir"
        )
        with self.assertRaisesRegex(ValueError, "acked by the child actor"):
            post_thread(
                state=self.state,
                title="Too early",
                actor="amir",
                target="kiran",
                continuation_thread_id=parent.thread.id,
                actor_identity_bound=True,
            )
        acknowledge_thread(
            state=self.state,
            thread_id=parent.thread.id,
            actor="amir",
            actor_identity_bound=True,
        )
        with self.assertRaisesRegex(ValueError, "target the child actor"):
            post_thread(
                state=self.state,
                title="Foreign parent",
                actor="esme",
                target="kiran",
                continuation_thread_id=parent.thread.id,
                actor_identity_bound=True,
            )

    def test_delegated_thread_requires_identity_binding_and_one_pending_child(self) -> None:
        unbound_parent = post_thread(
            state=self.state, title="Unbound parent", actor="odin", target="amir"
        )
        acknowledge_thread(
            state=self.state, thread_id=unbound_parent.thread.id, actor="amir"
        )
        with self.assertRaisesRegex(ValueError, "parent acknowledgement must be identity-bound"):
            post_thread(
                state=self.state,
                title="Bound child of unbound parent",
                actor="amir",
                target="kiran",
                continuation_thread_id=unbound_parent.thread.id,
                actor_identity_bound=True,
            )

        parent = post_thread(
            state=self.state, title="Restore drill", actor="odin", target="amir"
        )
        acknowledge_thread(
            state=self.state,
            thread_id=parent.thread.id,
            actor="amir",
            actor_identity_bound=True,
        )
        with self.assertRaisesRegex(ValueError, "identity-bound"):
            post_thread(
                state=self.state,
                title="Unbound child",
                actor="amir",
                target="kiran",
                continuation_thread_id=parent.thread.id,
            )
        post_thread(
            state=self.state,
            title="First child",
            actor="amir",
            target="kiran",
            continuation_thread_id=parent.thread.id,
            actor_identity_bound=True,
        )
        with self.assertRaisesRegex(ValueError, "already has a pending child"):
            post_thread(
                state=self.state,
                title="Second child",
                actor="amir",
                target="esme",
                continuation_thread_id=parent.thread.id,
                actor_identity_bound=True,
            )

    def test_read_all_skips_pending_unless_included(self) -> None:
        ask = post_thread(state=self.state, title="Actionable ask", thread_type="ask", target="vesper", actor="demobot")
        update = post_thread(state=self.state, title="FYI status", thread_type="update", target="vesper", actor="demobot")
        marked = read_all_threads(state=self.state, target="vesper")
        self.assertEqual([thread.id for thread in marked.threads], [update.thread.id])
        inbox = {thread.id: thread for thread in list_thread_inbox(state=self.state, target="vesper").threads}
        self.assertTrue(inbox[ask.thread.id].unread)
        self.assertFalse(inbox[update.thread.id].unread)
        # explicit include-pending flag reads the actionable thread too
        marked_pending = read_all_threads(state=self.state, target="vesper", include_pending=True)
        self.assertEqual([thread.id for thread in marked_pending.threads], [ask.thread.id])
        inbox = {thread.id: thread for thread in list_thread_inbox(state=self.state, target="vesper").threads}
        self.assertFalse(inbox[ask.thread.id].unread)
        # ask is read but still pending: read-all must not settle actionable work
        self.assertTrue(inbox[ask.thread.id].pending)

    def test_projection_rebuilds_state_from_event_log(self) -> None:
        created = post_thread(
            state=self.state, title="Rebuild me", body="original body", thread_type="ask", target="vesper", actor="demobot")
        post_thread_message(state=self.state, thread_id=created.thread.id, text="follow-up", actor="demobot")
        acknowledge_thread(state=self.state, thread_id=created.thread.id, actor="vesper")
        complete_thread(state=self.state, thread_id=created.thread.id, actor="vesper")
        events = read_events(self.state)
        self.assertEqual(
            [event.type for event in events],
            ["thread.created", "thread.message.posted", "thread.acknowledged", "thread.done"],
        )
        # replay the raw append-only log into a fresh state file and re-project
        replayed = Path(self._tmp.name) / "replayed.jsonl"
        replayed.write_bytes(self.state.read_bytes())
        original = list_thread_inbox(state=self.state, target="vesper").to_dict()
        rebuilt = list_thread_inbox(state=replayed, target="vesper").to_dict()
        self.assertEqual(rebuilt, original)
        thread = list_thread_inbox(state=replayed, target="vesper").threads[0]
        self.assertEqual(thread.status, "done")
        self.assertEqual(thread.body, "original body")
        self.assertNotEqual(thread.acked_at, "")
        self.assertNotEqual(thread.done_at, "")

    def test_reply_marks_thread_unread_again(self) -> None:
        created = post_thread(state=self.state, title="Status thread", thread_type="status", target="vesper", actor="demobot")
        read_thread(state=self.state, thread_id=created.thread.id)
        self.assertFalse(list_thread_inbox(state=self.state, target="vesper").threads[0].unread)
        post_thread_message(state=self.state, thread_id=created.thread.id, text="new info", actor="demobot")
        self.assertTrue(list_thread_inbox(state=self.state, target="vesper").threads[0].unread)

    def test_read_then_reply_in_same_second_stays_unread(self) -> None:
        # Regression: unread used to be derived as latest_at > read_at, but
        # timestamps are second-resolution, so a read followed by a reply in
        # the same second compared equal and the reply was silently treated
        # as read. Pin _now to one constant to force the collision on every
        # run; append order of the event log must decide, not timestamps.
        with patch("arvyx_control.control._now", return_value="2026-07-08T12:00:00Z"):
            created = post_thread(state=self.state, title="Same-second race", thread_type="ask", target="vesper", actor="demobot")
            read_thread(state=self.state, thread_id=created.thread.id)
            replied = post_thread_message(state=self.state, thread_id=created.thread.id, text="new info", actor="demobot")
            # prove the collision this test exists for is actually present
            self.assertEqual(replied.thread.latest_at, replied.thread.read_at)
            self.assertTrue(list_thread_inbox(state=self.state, target="vesper").threads[0].unread)

    def test_reply_then_read_in_same_second_is_read(self) -> None:
        # Mirror case: the read is the later log entry, so it wins the tie.
        with patch("arvyx_control.control._now", return_value="2026-07-08T12:00:00Z"):
            created = post_thread(state=self.state, title="Same-second read", thread_type="update", target="vesper", actor="demobot")
            post_thread_message(state=self.state, thread_id=created.thread.id, text="info", actor="demobot")
            read_thread(state=self.state, thread_id=created.thread.id)
            self.assertFalse(list_thread_inbox(state=self.state, target="vesper").threads[0].unread)

    def test_secret_shaped_title_body_and_text_rejected(self) -> None:
        secret = "token = ghp_0123456789abcdefghij0123456789"  # gitleaks:allow -- synthetic fixture
        with self.assertRaises(ValueError):
            post_thread(state=self.state, title=secret, target="vesper", actor="demobot")
        with self.assertRaises(ValueError):
            post_thread(state=self.state, title="safe title", body=secret, target="vesper", actor="demobot")
        created = post_thread(state=self.state, title="safe title", target="vesper", actor="demobot")
        events_before = len(read_events(self.state))
        with self.assertRaises(ValueError):
            post_thread_message(state=self.state, thread_id=created.thread.id, text=secret, actor="demobot")
        with self.assertRaises(ValueError):
            acknowledge_thread(state=self.state, thread_id=created.thread.id, text=secret)
        with self.assertRaises(ValueError):
            complete_thread(state=self.state, thread_id=created.thread.id, text=secret)
        # rejected writes must not append events
        self.assertEqual(len(read_events(self.state)), events_before)
        # sanctioned secret refs are allowed, consistent with the lint policy
        allowed = post_thread(
            state=self.state, title="Rotate credentials", body="use secret://demo/rotation/token", target="vesper", actor="demobot")
        self.assertEqual(allowed.thread.body, "use secret://demo/rotation/token")

    def test_state_transition_guards(self) -> None:
        with self.assertRaises(ValueError):
            post_thread(state=self.state, title="bad type", thread_type="carrier-pigeon", actor="demobot")
        with self.assertRaises(ValueError):
            post_thread(state=self.state, title="bad severity", severity="apocalyptic", actor="demobot")
        with self.assertRaises(ValueError):
            post_thread(state=self.state, title="   ", actor="demobot")
        for action in (acknowledge_thread, complete_thread, read_thread):
            with self.assertRaises(ValueError):
                action(state=self.state, thread_id="thread_missing")
        created = post_thread(state=self.state, title="Guard me", thread_type="ask", target="vesper", actor="demobot")
        acknowledge_thread(state=self.state, thread_id=created.thread.id)
        with self.assertRaises(ValueError):
            acknowledge_thread(state=self.state, thread_id=created.thread.id)
        complete_thread(state=self.state, thread_id=created.thread.id)
        with self.assertRaises(ValueError):
            complete_thread(state=self.state, thread_id=created.thread.id)
        with self.assertRaises(ValueError):
            acknowledge_thread(state=self.state, thread_id=created.thread.id)

    def test_store_sync_projects_threads_to_sqlite(self) -> None:
        db = Path(self._tmp.name) / "control.sqlite"
        created = post_thread(
            state=self.state,
            title="Persist thread state",
            thread_type="ask",
            target="vesper",
            completion_artifact="/home/vesper/.hermes/memories/USER.md",
            completion_anchor="0bserverx", actor="demobot")
        complete_thread(
            state=self.state,
            thread_id=created.thread.id,
            actor="vesper",
            evidence_artifact="/home/vesper/.hermes/memories/USER.md",
            evidence_anchor="0bserverx",
            evidence_method="direct-read",
        )
        result = sync_sqlite(state=self.state, db=db)
        with closing(sqlite3.connect(db)) as conn:
            row = conn.execute(
                """SELECT status, pending, completion_artifact, completion_anchor,
                          evidence_artifact, evidence_anchor, evidence_method
                   FROM threads WHERE id = ?""",
                (created.thread.id,),
            ).fetchone()
        self.assertEqual(result.threads, 1)
        self.assertEqual(result.events, 2)
        self.assertEqual(
            row,
            (
                "done", 0,
                "/home/vesper/.hermes/memories/USER.md", "0bserverx",
                "/home/vesper/.hermes/memories/USER.md", "0bserverx", "direct-read",
            ),
        )

    def test_store_sync_preserves_acked_thread_state(self) -> None:
        db = Path(self._tmp.name) / "control-acked.sqlite"
        created = post_thread(state=self.state, title="Persist ack", thread_type="ask", target="vesper", actor="demobot")
        acknowledge_thread(state=self.state, thread_id=created.thread.id, actor="vesper")
        sync_sqlite(state=self.state, db=db)
        with closing(sqlite3.connect(db)) as conn:
            row = conn.execute(
                "SELECT status, pending, unread, acked_by FROM threads WHERE id = ?",
                (created.thread.id,),
            ).fetchone()
        self.assertEqual(row, ("acked", 1, 1, "vesper"))


class ThreadCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = str(Path(self._tmp.name) / "events.jsonl")
        self.vault = Path(self._tmp.name) / "vault"
        self.vault.mkdir()
        self.enterContext(authority_context(self.vault, self.state))

    def _run(self, argv: list[str]) -> tuple[int, dict]:
        if argv[:2] == ["thread", "post"] and "--actor" not in argv:
            argv = [*argv, "--actor", "demobot"]
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = main(["--authority-vault", str(self.vault), *argv])
        output = buffer.getvalue().strip()
        return code, json.loads(output) if output else {}

    def test_cli_acceptance_shape(self) -> None:
        code, posted = self._run(
            [
                "thread",
                "post",
                "--to",
                "vesper",
                "--channel",
                "demo-agent",
                "--type",
                "ask",
                "--title",
                "Daily health check",
                "--text",
                "Run synthetic checks.",
                "--state",
                self.state,
                "--json",
            ]
        )
        self.assertEqual(code, 0)
        thread_id = posted["thread"]["id"]
        self.assertTrue(posted["thread"]["pending"])

        code, inbox = self._run(["thread", "inbox", "vesper", "--state", self.state, "--json"])
        self.assertEqual(code, 0)
        self.assertEqual([thread["id"] for thread in inbox["threads"]], [thread_id])

        code, pending = self._run(["thread", "pending", "vesper", "--state", self.state, "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(len(pending["threads"]), 1)

        code, acked = self._run(
            ["thread", "ack", thread_id, "--actor", "vesper", "--text", "Taking this.", "--state", self.state, "--json"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(acked["thread"]["status"], "acked")
        self.assertTrue(acked["thread"]["pending"])

        code, done = self._run(
            ["thread", "done", thread_id, "--actor", "vesper", "--text", "Done with receipts.", "--state", self.state, "--json"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(done["thread"]["status"], "done")
        self.assertFalse(done["thread"]["pending"])

        code, pending = self._run(["thread", "pending", "vesper", "--state", self.state, "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(pending["threads"], [])

        code, marked = self._run(["thread", "read-all", "vesper", "--state", self.state, "--json"])
        self.assertEqual(code, 0)
        self.assertEqual([thread["id"] for thread in marked["threads"]], [thread_id])

    def test_cli_rejects_secret_shaped_text(self) -> None:
        stderr = StringIO()
        buffer = StringIO()
        from contextlib import redirect_stderr

        with redirect_stdout(buffer), redirect_stderr(stderr):
            code = main(
                ["--authority-vault", str(self.vault), *[
                    "thread",
                    "post",
                    "--title",
                    "leaky",
                    "--actor",
                    "demobot",
                    "--text",
                    "password = hunter2hunter2",
                    "--state",
                    self.state,
                    "--json",
                ]]
            )
        self.assertEqual(code, 1)
        self.assertIn("secret-shaped", stderr.getvalue())

    def test_cli_completion_contract_requires_evidence_flags(self) -> None:
        artifact = "/home/vesper/.hermes/memories/USER.md"
        code, posted = self._run(
            [
                "thread", "post", "--to", "vesper", "--title", "Update canonical user memory",
                "--completion-artifact", artifact, "--completion-anchor", "0bserverx",
                "--state", self.state, "--json",
            ]
        )
        self.assertEqual(code, 0)
        thread_id = posted["thread"]["id"]
        code, done = self._run(
            [
                "thread", "done", thread_id, "--actor", "vesper",
                "--evidence-artifact", artifact, "--evidence-anchor", "0bserverx",
                "--evidence-method", "direct-read", "--state", self.state, "--json",
            ]
        )
        self.assertEqual(code, 0)
        self.assertEqual(done["thread"]["evidence_method"], "direct-read")


if __name__ == "__main__":
    unittest.main()
