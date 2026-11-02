from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
OUTBOX_DOC = ROOT / "docs" / "outbox.md"


class AgentDeliveryDocumentationContractTests(unittest.TestCase):
    def test_outbox_docs_cover_the_complete_append_only_lifecycle(self) -> None:
        source = OUTBOX_DOC.read_text(encoding="utf-8")
        for event_type in (
            "outbox.receipt",
            "outbox.cancelled",
            "outbox.dispatcher.tick",
        ):
            self.assertIn(event_type, source)

    def test_outbox_docs_explain_cancellation_and_allowlist_skip_semantics(self) -> None:
        source = OUTBOX_DOC.read_text(encoding="utf-8")
        for fragment in (
            "POST /deliveries/<delivery_id>/cancel",
            "irreversible",
            "new authoritative source event",
            "ARVYX_AGENT_INTENTIONAL_HUMAN_TARGETS",
            "checkpoint remains before that source event",
            "materialize automatically without rewind or source-event loss",
            "/etc/arvyx-v2/routes.d",
            "keep `control.env` and `agent-delivery.env` outside it",
        ):
            self.assertIn(fragment, source)


if __name__ == "__main__":
    unittest.main()
