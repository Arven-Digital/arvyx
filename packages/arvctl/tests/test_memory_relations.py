from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from arvyx_control.vault import init_vault


class MemoryRelationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.vault = Path(self._tmp.name) / "vault"
        init_vault(self.vault)
        from arvyx_control.replica_authority import authority_context
        self.state = self.vault / "control-events.jsonl"
        authority = authority_context(self.vault, self.state)
        authority.__enter__()
        self.addCleanup(authority.__exit__, None, None, None)
        self.project = "demo-agent"
        self.notes = self.vault / "projects" / self.project / "notes"
        self.notes.mkdir(parents=True, exist_ok=True)
        self.parent_relative = f"projects/{self.project}/notes/relay-policy.md"
        self.parent = self.vault / self.parent_relative
        self.parent.write_text(
            "---\nid: relay-policy\nstatus: promoted\n---\n\n# Relay policy\n\nThe relay quorum is two nodes.\n",
            encoding="utf-8",
        )

    def _quality(self, **overrides: object) -> dict[str, object]:
        quality: dict[str, object] = {
            "content_class": "durable_fact",
            "memory_class": "dynamic",
            "future_job": "Keep relay policy lineage current during review.",
            "assistant_suggestion_accepted": False,
        }
        quality.update(overrides)
        return quality

    def test_storage_listing_refuses_outside_leaf_without_metadata(self):
        from arvyx_control.writes import list_pending
        outside = Path(self._tmp.name) / 'outside.md'
        outside.write_text('---\nauthor: outside-marker\n---\n# outside-marker\n')
        pending = self.notes.parent / 'pending'
        pending.mkdir()
        (pending / 'alias.md').symlink_to(outside)
        with self.assertRaises(ValueError) as error:
            list_pending(self.vault, self.project)
        self.assertNotIn('outside-marker', str(error.exception))

    def test_storage_single_limits_and_expanding_title(self):
        from arvyx_control.writes import MAX_SUGGESTION_TITLE_CHARS, suggest_memory
        with self.assertRaises(ValueError):
            suggest_memory(self.vault, self.project, 'a' * (MAX_SUGGESTION_TITLE_CHARS + 1), 'ordinary', 'demobot')
        result = suggest_memory(self.vault, self.project, '\u0130' * 128, 'ordinary', 'demobot')
        self.assertLessEqual(len(Path(result.path).name.encode('utf-8')), 255)
        self.assertIn('\u0130' * 128, (self.vault / result.path).read_text(encoding='utf-8'))

    def test_storage_refine_source_secret_refused_without_rewrite(self):
        from arvyx_control.writes import refine_memory
        pending = self.notes.parent / 'pending'
        pending.mkdir()
        source = pending / 'synthetic.md'
        source.write_text('# Synthetic\n' + 'ghp_' + 'A' * 36)
        before = source.read_bytes()
        with self.assertRaises(ValueError):
            refine_memory(self.vault, self.project, 'pending/synthetic.md', 'demobot', content='replacement')
        self.assertEqual(source.read_bytes(), before)

    def _suggest(self, *, relation_type: str, inferred: bool = False):
        from arvyx_control.writes import suggest_memory_batch

        return suggest_memory_batch(
            vault=self.vault,
            project=self.project,
            author="demobot",
            payload={
                "memories": [
                    {
                        "title": "Revised relay policy",
                        "content": "The relay quorum is three nodes.",
                        **self._quality(),
                        "inferred": inferred,
                        "relations": [
                            {"type": relation_type, "parent_source_path": self.parent_relative}
                        ],
                    }
                ]
            },
        ).suggestions[0]

    def test_relation_schema_is_closed_capped_and_requires_curated_parents(self) -> None:
        from arvyx_control.writes import MAX_RELATIONS_PER_SUGGESTION, suggest_memory_batch

        base = {"title": "Candidate", "content": "Candidate content.", **self._quality()}
        bad_relations = [
            ([{"type": "unknown", "parent_source_path": self.parent_relative}], "type must be one of"),
            ([{"type": "extends", "parent_source_path": self.parent_relative, "extra": True}], "unknown field"),
            ([{"type": "extends"}], "parent_source_path is required"),
            ([{"type": "extends", "parent_source_path": "projects/demo-agent/pending/x.md"}], "curated notes"),
            ([{"type": "extends", "parent_source_path": "projects/other/notes/x.md"}], "current project"),
            ([{"type": "extends", "parent_source_path": self.parent_relative}] * (MAX_RELATIONS_PER_SUGGESTION + 1), "at most 20"),
            ([
                {"type": "updates", "parent_source_path": self.parent_relative},
                {"type": "extends", "parent_source_path": self.parent_relative},
            ], "duplicates an earlier parent"),
        ]
        for relations, message in bad_relations:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    suggest_memory_batch(
                        vault=self.vault,
                        project=self.project,
                        author="demobot",
                        payload={"memories": [{**base, "relations": relations}]},
                    )
        self.assertEqual(list((self.notes.parent / "pending").glob("*.md")), [])

    def test_derives_requires_explicit_inferred_true(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        for inferred in (None, False):
            memory = {
                "title": "Derived relay policy",
                "content": "A derived conclusion.",
                **self._quality(content_class="inferred"),
                "relations": [{"type": "derives", "parent_source_path": self.parent_relative}],
            }
            if inferred is not None:
                memory["inferred"] = inferred
            with self.subTest(inferred=inferred):
                with self.assertRaisesRegex(ValueError, "derives requires inferred=true"):
                    suggest_memory_batch(
                        vault=self.vault, project=self.project, author="demobot", payload={"memories": [memory]}
                    )
        result = self._suggest(relation_type="derives", inferred=True)
        self.assertTrue((self.vault / result.path).is_file())

    def test_refiner_rejects_persisted_derivation_without_inferred_true(self) -> None:
        from arvyx_control.writes import refine_memory

        pending = self.notes.parent / "pending" / "unsafe-derivation.md"
        pending.parent.mkdir(parents=True, exist_ok=True)
        pending.write_text(
            "---\nstatus: pending\ninferred: false\n"
            f"relations: [{{\"type\": \"derives\", \"parent_source_path\": \"{self.parent_relative}\"}}]\n"
            "---\n\n# Unsafe derivation\n\nConclusion.\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "derives requires inferred=true"):
            refine_memory(
                self.vault,
                self.project,
                f"projects/{self.project}/pending/unsafe-derivation.md",
                "refiner",
            )
        self.assertTrue(pending.is_file())

    def test_updates_supersedes_parent_only_when_promoted_and_history_remains_excerptable(self) -> None:
        from arvyx_control.index import load_index
        from arvyx_control.recall import excerpt, recall
        from arvyx_control.writes import promote_memory

        suggestion = self._suggest(relation_type="updates")
        self.assertIn(self.parent_relative, {chunk.relative_path for chunk in load_index(self.vault)})
        self.assertNotIn("status: superseded", self.parent.read_text(encoding="utf-8"))

        promoted = promote_memory(self.vault, self.project, suggestion.path, "operator")

        indexed = {chunk.relative_path for chunk in load_index(self.vault)}
        self.assertNotIn(self.parent_relative, indexed)
        self.assertIn(promoted.target, indexed)
        parent_text = self.parent.read_text(encoding="utf-8")
        self.assertIn("status: superseded", parent_text)
        from arvyx_control.memory_frontmatter import frontmatter_values, scalar_value
        self.assertEqual(scalar_value(frontmatter_values(parent_text)["superseded_by"]), promoted.target)
        current = recall("relay quorum nodes", self.vault, project=self.project, limit=10)
        self.assertNotIn(self.parent_relative, {source.path for source in current.sources})
        self.assertIn(promoted.target, {source.path for source in current.sources})
        historical = excerpt(self.vault, self.parent_relative, "1-20")
        self.assertIn("two nodes", historical.text)

    def test_extends_keeps_parent_active_after_promotion(self) -> None:
        from arvyx_control.index import load_index
        from arvyx_control.writes import promote_memory

        suggestion = self._suggest(relation_type="extends")
        promoted = promote_memory(self.vault, self.project, suggestion.path, "operator")
        indexed = {chunk.relative_path for chunk in load_index(self.vault)}
        self.assertIn(self.parent_relative, indexed)
        self.assertIn(promoted.target, indexed)
        self.assertNotIn("status: superseded", self.parent.read_text(encoding="utf-8"))

    def test_mcp_schema_and_round_trip_enforce_relation_contract(self) -> None:
        from arvyx_control.mcp import handle_request

        listed = handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            vault=self.vault,
            state=self.state,
            allowed_tools={"memory.suggest_batch"},
        )
        tool = next(item for item in listed["result"]["tools"] if item["name"] == "memory.suggest_batch")
        item = tool["inputSchema"]["properties"]["memories"]["items"]
        self.assertEqual(item["properties"]["relations"]["maxItems"], 20)
        relation = item["properties"]["relations"]["items"]
        self.assertFalse(relation["additionalProperties"])
        self.assertEqual(relation["properties"]["type"]["enum"], ["updates", "extends", "derives"])
        self.assertEqual(item["properties"]["memory_class"]["enum"], ["static", "dynamic"])
        self.assertIn("content_class", item["required"])
        self.assertIn("future_job", item["required"])

        response = handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "memory.suggest_batch",
                    "arguments": {
                        "project": self.project,
                        "author": "demobot",
                        "idempotency_key": "synthetic-memory-relation-mcp",
                        "memories": [{
                            "title": "MCP update",
                            "content": "Updated through MCP.",
                            **self._quality(),
                            "relations": [{"type": "updates", "parent_source_path": self.parent_relative}],
                        }],
                    },
                },
            },
            vault=self.vault,
            state=self.state,
            allowed_tools={"memory.suggest_batch"},
        )
        self.assertNotIn("error", response)

    def test_quality_and_relations_validate_atomically_before_any_write(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        pending = self.notes.parent / "pending"
        valid = {
            "title": "Combined contract",
            "content": "A quality-gated update with lineage.",
            **self._quality(),
            "relations": [{"type": "extends", "parent_source_path": self.parent_relative}],
        }
        result = suggest_memory_batch(
            vault=self.vault, project=self.project, author="demobot", payload={"memories": [valid]}
        )
        text = (self.vault / result.suggestions[0].path).read_text(encoding="utf-8")
        self.assertIn('memory_class: "dynamic"', text)
        self.assertIn(f'"parent_source_path": "{self.parent_relative}"', text)

        baseline = sorted(pending.glob("*.md"))
        bad_relation = {
            **valid,
            "title": "Bad relation",
            "relations": [{"type": "unknown", "parent_source_path": self.parent_relative}],
        }
        with self.assertRaisesRegex(ValueError, "type must be one of"):
            suggest_memory_batch(
                vault=self.vault,
                project=self.project,
                author="demobot",
                payload={"memories": [valid | {"title": "Would write"}, bad_relation]},
            )
        self.assertEqual(sorted(pending.glob("*.md")), baseline)

        bad_quality = {**valid, "title": "Bad quality", "future_job": ""}
        with self.assertRaisesRegex(ValueError, "NO_FUTURE_JOB"):
            suggest_memory_batch(
                vault=self.vault,
                project=self.project,
                author="demobot",
                payload={"memories": [valid | {"title": "Would also write"}, bad_quality]},
            )
        self.assertEqual(sorted(pending.glob("*.md")), baseline)

    def test_http_round_trip_promotes_update_and_supersedes_parent(self) -> None:
        from arvyx_control.api import handle_api_request

        state = self.vault / "control-events.jsonl"
        suggested = handle_api_request(
            "POST",
            "/memory/suggest-batch",
            {
                "project": self.project,
                "author": "demobot",
                "memories": [{
                    "title": "HTTP update",
                    "content": "Updated through HTTP.",
                    **self._quality(),
                    "relations": [{"type": "updates", "parent_source_path": self.parent_relative}],
                }],
            },
            vault=self.vault,
            state=state,
            allow_unauthenticated_demo=True,
        )
        self.assertEqual(suggested.status, 201)
        promoted = handle_api_request(
            "POST",
            "/memory/promote",
            {
                "project": self.project,
                "source_path": suggested.body["suggestions"][0]["path"],
                "promoted_by": "operator",
            },
            vault=self.vault,
            state=state,
            allow_unauthenticated_demo=True,
        )
        self.assertEqual(promoted.status, 200)
        self.assertIn("status: superseded", self.parent.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
