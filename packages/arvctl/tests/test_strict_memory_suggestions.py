from __future__ import annotations

import tempfile
import unittest
from unittest import mock
from pathlib import Path

from arvyx_control.auth import issue_token
from arvyx_control.vault import init_vault


class StrictMemorySuggestionBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.vault = Path(self._tmp.name) / "vault"
        init_vault(self.vault)
        from arvyx_control.replica_authority import authority_context
        authority = authority_context(self.vault, self.vault / "control-events.jsonl")
        authority.__enter__()
        self.addCleanup(authority.__exit__, None, None, None)

    def _pending_files(self) -> list[Path]:
        root = self.vault / "projects" / "demo-agent" / "pending"
        return sorted(root.glob("*.md")) if root.exists() else []

    def _quality(self, **overrides: object) -> dict[str, object]:
        quality = {
            "content_class": "durable_identity",
            "memory_class": "static",
            "future_job": "Identify the durable owner during access review.",
            "assistant_suggestion_accepted": False,
        }
        quality.update(overrides)
        return quality

    def test_quality_metadata_is_required_and_persisted(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        with self.assertRaisesRegex(ValueError, "QUALITY_METADATA_REQUIRED"):
            suggest_memory_batch(
                vault=self.vault, project="demo-agent", author="demobot",
                payload={"memories": [{"title": "Owner", "content": "Atlas owns relay review."}]},
            )
        result = suggest_memory_batch(
            vault=self.vault, project="demo-agent", author="demobot",
            payload={"memories": [{"title": "Owner", "content": "Atlas owns relay review.", **self._quality()}]},
        )
        text = (self.vault / result.suggestions[0].path).read_text(encoding="utf-8")
        self.assertIn('memory_class: "static"', text)
        self.assertIn('content_class: "durable_identity"', text)
        self.assertIn('future_job: "Identify the durable owner during access review."', text)
        self.assertIn("assistant_suggestion_accepted: false", text)

    def test_noise_classes_are_rejected_atomically_with_reason_codes(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        reason_codes = {
            "boilerplate": "NOISE_BOILERPLATE",
            "greeting": "NOISE_GREETING",
            "prompt_injection": "PROMPT_INJECTION",
            "no_future_job": "NO_FUTURE_JOB",
        }
        for content_class, reason in reason_codes.items():
            with self.subTest(content_class=content_class):
                with self.assertRaisesRegex(ValueError, reason):
                    suggest_memory_batch(
                        vault=self.vault, project="demo-agent", author="demobot",
                        payload={"memories": [{"title": "Reject", "content": "Quoted or plain text.", **self._quality(content_class=content_class, memory_class="dynamic")}]},
                    )
        self.assertEqual(self._pending_files(), [])

    def test_unaccepted_assistant_suggestion_is_rejected_but_accepted_is_dynamic(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        item = {"title": "Proposal", "content": "Use three relay nodes.", **self._quality(content_class="assistant_suggestion", memory_class="dynamic")}
        with self.assertRaisesRegex(ValueError, "ASSISTANT_SUGGESTION_UNACCEPTED"):
            suggest_memory_batch(vault=self.vault, project="demo-agent", author="demobot", payload={"memories": [item]})
        item["assistant_suggestion_accepted"] = True
        result = suggest_memory_batch(vault=self.vault, project="demo-agent", author="demobot", payload={"memories": [item]})
        self.assertEqual(result.suggestions[0].memory_class, "dynamic")

    def test_static_is_only_permitted_for_durable_identity(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        for content_class in ("preference", "plan", "state", "inferred"):
            with self.subTest(content_class=content_class):
                with self.assertRaisesRegex(ValueError, "STATIC_REQUIRES_DURABLE_IDENTITY"):
                    suggest_memory_batch(
                        vault=self.vault, project="demo-agent", author="demobot",
                        payload={"memories": [{"title": "Misfiled", "content": "A changing fact.", **self._quality(content_class=content_class)}]},
                    )

    def test_static_is_rejected_for_non_durable_identity_content_classes(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        for content_class in ("durable_fact", "assistant_suggestion", "research_quote"):
            with self.subTest(content_class=content_class):
                with self.assertRaisesRegex(ValueError, "STATIC_REQUIRES_DURABLE_IDENTITY"):
                    suggest_memory_batch(
                        vault=self.vault, project="demo-agent", author="demobot",
                        payload={"memories": [{
                            "title": "Static misfile", "content": "A non-identity fact.",
                            **self._quality(
                                content_class=content_class,
                                memory_class="static",
                                assistant_suggestion_accepted=content_class == "assistant_suggestion",
                            ),
                        }]},
                    )
        self.assertEqual(self._pending_files(), [])

    def test_whitespace_only_future_job_is_rejected(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        with self.assertRaisesRegex(ValueError, "NO_FUTURE_JOB"):
            suggest_memory_batch(
                vault=self.vault, project="demo-agent", author="demobot",
                payload={"memories": [{
                    "title": "Blank job", "content": "Some durable owner detail.",
                    **self._quality(future_job="   \t\n  "),
                }]},
            )
        self.assertEqual(self._pending_files(), [])

    def test_string_accepted_flag_is_rejected_as_non_boolean(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        with self.assertRaisesRegex(ValueError, "assistant_suggestion_accepted must be a boolean"):
            suggest_memory_batch(
                vault=self.vault, project="demo-agent", author="demobot",
                payload={"memories": [{
                    "title": "Truthy string", "content": "Use three relay nodes.",
                    **self._quality(
                        content_class="assistant_suggestion",
                        memory_class="dynamic",
                        assistant_suggestion_accepted="true",
                    ),
                }]},
            )
        self.assertEqual(self._pending_files(), [])

    def test_boolean_acceptance_is_serialized_exactly(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        for accepted in (False, True):
            with self.subTest(accepted=accepted):
                result = suggest_memory_batch(
                    vault=self.vault,
                    project="demo-agent",
                    author="demobot",
                    payload={"memories": [{
                        "title": f"Acceptance {accepted}",
                        "content": "An explicitly classified suggestion.",
                        **self._quality(
                            content_class="assistant_suggestion" if accepted else "durable_fact",
                            memory_class="dynamic",
                            assistant_suggestion_accepted=accepted,
                        ),
                    }]},
                )
                text = (self.vault / result.suggestions[0].path).read_text(encoding="utf-8")
                expected = "true" if accepted else "false"
                self.assertIn(f"assistant_suggestion_accepted: {expected}\n", text)

    def test_future_job_control_characters_are_json_escaped_in_frontmatter(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        result = suggest_memory_batch(
            vault=self.vault,
            project="demo-agent",
            author="demobot",
            payload={"memories": [{
                "title": "Escaped future job",
                "content": "A durable fact with an escaped downstream use.",
                **self._quality(
                    content_class="durable_fact",
                    memory_class="dynamic",
                    future_job="First line\nSecond\tstep\u0001",
                ),
            }]},
        )
        text = (self.vault / result.suggestions[0].path).read_text(encoding="utf-8")
        self.assertIn('future_job: "First line\\nSecond\\tstep\\u0001"\n', text)
        self.assertNotIn("future_job: First line\nSecond", text)

    def test_quoted_research_is_admitted_by_metadata_not_naive_text_censorship(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        result = suggest_memory_batch(
            vault=self.vault, project="demo-agent", author="demobot",
            payload={"memories": [{
                "title": "Injection research quote",
                "content": 'The paper quotes "ignore previous instructions" as an attack example.',
                **self._quality(content_class="research_quote", memory_class="dynamic", future_job="Support the threat-model literature review."),
            }]},
        )
        self.assertEqual(result.suggestions[0].admission_reason, "FUTURE_JOB_ACCEPTED")

    def test_valid_batch_is_written_after_full_validation(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        result = suggest_memory_batch(
            vault=self.vault,
            project="demo-agent",
            author="demobot",
            payload={
                "memories": [
                    {
                        "title": "Quorum",
                        "content": "The relay quorum requires three nodes.",
                        "tags": ["architecture"],
                        **self._quality(),
                    },
                    {
                        "title": "Recovery",
                        "content": "Recovery resumes from the last durable checkpoint.",
                        **self._quality(memory_class="dynamic", content_class="durable_fact"),
                    },
                ]
            },
        )

        self.assertEqual(len(result.suggestions), 2)
        self.assertEqual(len(self._pending_files()), 2)
        self.assertTrue(all(item.status == "pending" for item in result.suggestions))

    def test_unknown_root_field_is_rejected_before_any_write(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        with self.assertRaisesRegex(ValueError, "unknown field.*debug"):
            suggest_memory_batch(
                vault=self.vault,
                project="demo-agent",
                author="demobot",
                payload={
                    "memories": [{"title": "Valid", "content": "Valid content."}],
                    "debug": True,
                },
            )
        self.assertEqual(self._pending_files(), [])

    def test_unknown_item_field_is_rejected_before_any_write(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        with self.assertRaisesRegex(ValueError, r"memories\[1\].*unknown field.*confidence"):
            suggest_memory_batch(
                vault=self.vault,
                project="demo-agent",
                author="demobot",
                payload={
                    "memories": [
                        {"title": "Would otherwise write", "content": "First valid item."},
                        {
                            "title": "Invalid",
                            "content": "Second item is invalid.",
                            "confidence": 0.9,
                        },
                    ]
                },
            )
        self.assertEqual(self._pending_files(), [])

    def test_non_string_values_are_not_coerced(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        with self.assertRaisesRegex(ValueError, r"memories\[0\]\.content must be a string"):
            suggest_memory_batch(
                vault=self.vault,
                project="demo-agent",
                author="demobot",
                payload={"memories": [{"title": "No coercion", "content": 123}]},
            )
        self.assertEqual(self._pending_files(), [])

    def test_batch_cap_is_enforced_before_any_write(self) -> None:
        from arvyx_control.writes import MAX_SUGGESTIONS_PER_BATCH, suggest_memory_batch

        payload = {
            "memories": [
                {"title": f"Memory {index}", "content": f"Content {index}."}
                for index in range(MAX_SUGGESTIONS_PER_BATCH + 1)
            ]
        }
        with self.assertRaisesRegex(ValueError, "at most 100"):
            suggest_memory_batch(
                vault=self.vault,
                project="demo-agent",
                author="demobot",
                payload=payload,
            )
        self.assertEqual(self._pending_files(), [])

    def test_tag_cap_is_enforced_before_any_write(self) -> None:
        from arvyx_control.writes import MAX_TAGS_PER_SUGGESTION, suggest_memory_batch

        with self.assertRaisesRegex(ValueError, r"memories\[0\]\.tags must contain at most 20"):
            suggest_memory_batch(
                vault=self.vault,
                project="demo-agent",
                author="demobot",
                payload={
                    "memories": [
                        {
                            "title": "Too many tags",
                            "content": "The item must not be partially written.",
                            "tags": [f"tag-{index}" for index in range(MAX_TAGS_PER_SUGGESTION + 1)],
                        }
                    ]
                },
            )
        self.assertEqual(self._pending_files(), [])

    def test_empty_batch_is_rejected(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        with self.assertRaisesRegex(ValueError, "must contain at least one"):
            suggest_memory_batch(
                vault=self.vault,
                project="demo-agent",
                author="demobot",
                payload={"memories": []},
            )
        self.assertEqual(self._pending_files(), [])

    def test_mcp_schema_is_closed_and_capped(self) -> None:
        from arvyx_control.mcp import handle_request
        from functools import partial
        handle_request = partial(handle_request, state=self.vault / "control-events.jsonl")

        response = handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            vault=self.vault,
            allowed_tools={"memory.suggest_batch"},
        )
        definition = next(
            item
            for item in response["result"]["tools"]
            if item["name"] == "memory.suggest_batch"
        )
        schema = definition["inputSchema"]
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["memories"]["maxItems"], 100)
        item_schema = schema["properties"]["memories"]["items"]
        self.assertFalse(item_schema["additionalProperties"])
        self.assertEqual(item_schema["properties"]["tags"]["maxItems"], 20)
        self.assertEqual(item_schema["properties"]["memory_class"]["enum"], ["static", "dynamic"])
        self.assertIn("content_class", item_schema["required"])
        self.assertIn("future_job", item_schema["required"])
        self.assertIn("assistant_suggestion_accepted", item_schema["required"])

    def test_http_exposes_the_same_quality_schema(self) -> None:
        from arvyx_control.api import handle_api_request

        response = handle_api_request(
            "GET", "/schemas/memory-suggest-batch", {}, vault=self.vault,
            state=self.vault / "control-events.jsonl", allow_unauthenticated_demo=True,
        )
        self.assertEqual(response.status, 200)
        item = response.body["properties"]["memories"]["items"]
        self.assertEqual(item["properties"]["memory_class"]["enum"], ["static", "dynamic"])
        self.assertIn("future_job", item["required"])

    def test_http_schema_requires_memory_suggest_scope(self) -> None:
        from arvyx_control.api import handle_api_request

        state = self.vault / "control-events.jsonl"
        unauthenticated = handle_api_request(
            "GET", "/schemas/memory-suggest-batch", {}, vault=self.vault, state=state,
        )
        read_token = issue_token(self.vault, "demobot", scopes=["memory.read"]).token
        read_only = handle_api_request(
            "GET", "/schemas/memory-suggest-batch", {}, vault=self.vault, state=state,
            authorization=f"Bearer {read_token}",
        )
        suggest_token = issue_token(self.vault, "vesper", scopes=["memory.suggest"]).token
        permitted = handle_api_request(
            "GET", "/schemas/memory-suggest-batch", {}, vault=self.vault, state=state,
            authorization=f"Bearer {suggest_token}",
        )
        self.assertEqual(unauthenticated.status, 401)
        self.assertEqual(read_only.status, 403)
        self.assertEqual(permitted.status, 200)

    def test_legacy_singular_suggestion_contract_remains_unchanged(self) -> None:
        from arvyx_control.writes import suggest_memory

        result = suggest_memory(
            vault=self.vault,
            project="demo-agent",
            title="Legacy suggestion",
            content="Legacy callers do not provide quality metadata.",
            author="demobot",
        )
        self.assertEqual(result.to_dict(), {
            "path": result.path,
            "title": "Legacy suggestion",
            "author": "demobot",
            "status": "pending",
        })

    def test_mcp_batch_round_trip_uses_strict_parser(self) -> None:
        from arvyx_control.mcp import handle_request
        from functools import partial
        handle_request = partial(handle_request, state=self.vault / "control-events.jsonl")

        response = handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "memory.suggest_batch",
                    "arguments": {
                        "idempotency_key": "strict-mcp-valid-batch-0001",
                        "project": "demo-agent",
                        "author": "demobot",
                        "memories": [
                            {"title": "One", "content": "First durable fact.", **self._quality(memory_class="dynamic", content_class="durable_fact")},
                            {"title": "Two", "content": "Second durable fact.", **self._quality(memory_class="dynamic", content_class="durable_fact")},
                        ],
                    },
                },
            },
            vault=self.vault,
            allowed_tools={"memory.suggest_batch"},
        )
        self.assertNotIn("error", response)
        structured = response["result"]["structuredContent"]
        self.assertEqual(structured["count"], 2)
        self.assertEqual(len(self._pending_files()), 2)

        rejected = handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "memory.suggest_batch",
                    "arguments": {
                        "idempotency_key": "test-test-test-02",
                        "project": "demo-agent",
                        "author": "demobot",
                        "memories": [
                            {
                                "title": "Bad",
                                "content": "Must not write.",
                                "confidence": 1,
                            }
                        ],
                    },
                },
            },
            vault=self.vault,
            allowed_tools={"memory.suggest_batch"},
        )
        self.assertIn("error", rejected)
        self.assertIn("unknown field", rejected["error"]["message"])
        self.assertEqual(len(self._pending_files()), 2)

        rejected_root = handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "memory.suggest_batch",
                    "arguments": {
                        "idempotency_key": "test-test-test-03",
                        "project": "demo-agent",
                        "author": "demobot",
                        "memories": [
                            {"title": "Bad root", "content": "Must not write."}
                        ],
                        "debug": True,
                    },
                },
            },
            vault=self.vault,
            allowed_tools={"memory.suggest_batch"},
        )
        self.assertIn("error", rejected_root)
        self.assertIn("unknown field", rejected_root["error"]["message"])
        self.assertEqual(len(self._pending_files()), 2)

    def test_http_batch_round_trip_and_unknown_root_rejection(self) -> None:
        from arvyx_control.api import handle_api_request

        state = self.vault / "control-events.jsonl"
        response = handle_api_request(
            "POST",
            "/memory/suggest-batch",
            {
                "project": "demo-agent",
                "author": "demobot",
                "memories": [
                    {"title": "HTTP", "content": "A strict HTTP suggestion.", **self._quality(memory_class="dynamic", content_class="durable_fact")}
                ],
            },
            vault=self.vault,
            state=state,
            allow_unauthenticated_demo=True,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(response.body["count"], 1)
        self.assertEqual(len(self._pending_files()), 1)

        rejected = handle_api_request(
            "POST",
            "/memory/suggest-batch",
            {
                "project": "demo-agent",
                "author": "demobot",
                "memories": [
                    {"title": "Rejected", "content": "Must not write."}
                ],
                "debug": True,
            },
            vault=self.vault,
            state=state,
            allow_unauthenticated_demo=True,
        )
        self.assertEqual(rejected.status, 400)
        self.assertEqual(len(self._pending_files()), 1)

    def test_http_retry_with_same_idempotency_key_does_not_duplicate(self) -> None:
        from arvyx_control.api import handle_api_request

        state = self.vault / "control-events.jsonl"
        body = {
            "project": "demo-agent",
            "author": "demobot",
            "memories": [{"title": "Idempotent", "content": "Write exactly once.", **self._quality(memory_class="dynamic", content_class="durable_fact")}],
            "idempotency_key": "strict-batch-retry-0001",
        }
        first = handle_api_request("POST", "/memory/suggest-batch", body, vault=self.vault, state=state, allow_unauthenticated_demo=True)
        second = handle_api_request("POST", "/memory/suggest-batch", body, vault=self.vault, state=state, allow_unauthenticated_demo=True)
        self.assertEqual(first.status, 201)
        self.assertEqual(second.status, 409)
        self.assertEqual(second.body.get("error"), "operation_completed_no_replay")
        self.assertEqual(len(self._pending_files()), 1)

    def test_frontmatter_fields_reject_newlines_before_any_write(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        cases = [
            ("demobot\nrole: owner", "Safe", []),
            ("demobot", "Heading\n---\ninjected: true", []),
            ("demobot", "Safe", ["safe\nrole: owner"]),
        ]
        for author, title, tags in cases:
            with self.subTest(author=author, title=title, tags=tags):
                with self.assertRaisesRegex(ValueError, "single-line"):
                    suggest_memory_batch(vault=self.vault, project="demo-agent", author=author, payload={"memories": [{"title": title, "content": "Safe body.", "tags": tags, **self._quality()}]})
        self.assertEqual(self._pending_files(), [])

    def test_duplicate_titles_in_one_batch_are_rejected(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        with self.assertRaisesRegex(ValueError, "duplicate title"):
            suggest_memory_batch(vault=self.vault, project="demo-agent", author="demobot", payload={"memories": [
                {"title": "Same", "content": "First.", **self._quality()},
                {"title": " same ", "content": "Second.", **self._quality()},
            ]})
        self.assertEqual(self._pending_files(), [])

    def test_mid_batch_write_failure_rolls_back_all_files(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        from arvyx_control import writes
        original = writes.stage
        calls = 0
        def flaky_stage(path: Path, data: bytes):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic disk failure")
            return original(path, data)

        with mock.patch.object(writes, "stage", flaky_stage):
            with self.assertRaisesRegex(OSError, "suggestion publication durability failed") as failure:
                suggest_memory_batch(vault=self.vault, project="demo-agent", author="demobot", payload={"memories": [
                    {"title": "One", "content": "First.", **self._quality()},
                    {"title": "Two", "content": "Second.", **self._quality()},
                    {"title": "Three", "content": "Third.", **self._quality()},
                ]})
        self.assertIsInstance(failure.exception.__cause__,OSError)
        self.assertEqual(str(failure.exception.__cause__),"synthetic disk failure")
        self.assertEqual(calls, 2, "fault must reach the active second staging boundary")
        pending = self.vault / "projects" / "demo-agent" / "pending"
        self.assertEqual(list(pending.iterdir()) if pending.exists() else [], [])


if __name__ == "__main__":
    unittest.main()
