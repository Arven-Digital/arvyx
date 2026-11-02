from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from arvyx_control.benchmark import run_recall_benchmark
from arvyx_control.index import INDEX_FORMAT
from arvyx_control.vault import init_vault

ROOT = Path(__file__).resolve().parents[3]


class BenchmarkEvidenceTests(unittest.TestCase):
    """B10: no capability claims without committed, reproducible artifacts."""

    def test_invalid_optional_embedding_config_preserves_benchmark_provenance(self) -> None:
        from arvyx_control.benchmark import _retrieval_config
        from arvyx_control.embeddings import EmbeddingError
        for error in (EmbeddingError("invalid"), ValueError("invalid"), OSError("unreadable")):
            with self.subTest(error=type(error).__name__):
                with patch("arvyx_control.recall.load_embedding_config", side_effect=error):
                    config = _retrieval_config(Path("unused"), "hybrid")
                self.assertIsNone(config["embedding_fingerprint"])
                self.assertEqual(config["index_format"], INDEX_FORMAT)

    def _cases(self, tmp: str) -> Path:
        cases = Path(tmp) / "cases.json"
        cases.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "suite": "unit-evidence",
                    "cases": [
                        {
                            "id": "decision_recall",
                            "category": "decision-recall",
                            "project": "demo-agent",
                            "question": "what did we decide about safe mcp bridge",
                            "expected_sources": ["projects/demo-agent/DECISIONS.md"],
                            "forbidden_sources": [],
                            "min_confidence": 0.1,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return cases

    def test_result_carries_run_id_and_dataset_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            cases = self._cases(tmp)
            result = run_recall_benchmark(vault=vault, cases_path=cases).to_dict()

        provenance = result["provenance"]
        self.assertEqual(provenance["provenance_schema"], "arvyx-benchmark-provenance/v2")
        self.assertEqual(provenance["dataset_sha256"], re.fullmatch(r"[0-9a-f]{64}", provenance["dataset_sha256"]).group(0))
        self.assertEqual(provenance["run_id"], re.fullmatch(r"[0-9a-f]{64}", provenance["run_id"]).group(0))
        self.assertEqual(provenance["retrieval_mode"], "lexical")
        self.assertEqual(provenance["case_count"], 1)
        self.assertRegex(provenance["corpus_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(provenance["retrieval_config"]["index_format"], INDEX_FORMAT)
        self.assertIn("implementation_version", provenance)

    def test_parsing_and_hashing_use_the_same_dataset_snapshot(self) -> None:
        import hashlib
        from arvyx_control import benchmark
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / 'vault'
            init_vault(vault)
            cases = self._cases(tmp)
            original = cases.read_bytes()
            parse = benchmark._parse_cases

            def replace_after_read(data):
                cases.write_text('{"cases":[]}', encoding='utf-8')
                return parse(data)

            with patch.object(benchmark, '_parse_cases', side_effect=replace_after_read):
                result = benchmark.run_recall_benchmark(vault=vault, cases_path=cases)
            self.assertEqual(result.total, 1)
            self.assertEqual(result.provenance['dataset_sha256'], hashlib.sha256(original).hexdigest())
            self.assertNotEqual(cases.read_bytes(), original)

    def test_offline_hybrid_policy_does_not_discover_or_call_embeddings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / 'vault'
            init_vault(vault)
            cases = self._cases(tmp)
            with patch('arvyx_control.benchmark._optional_embedding_config',
                       side_effect=AssertionError('config discovery forbidden')), \
                 patch('arvyx_control.recall.load_embedding_config',
                       side_effect=AssertionError('config discovery forbidden')), \
                 patch('arvyx_control.index.embed_texts',
                       side_effect=AssertionError('document disclosure forbidden')), \
                 patch('arvyx_control.recall.embed_texts',
                       side_effect=AssertionError('query disclosure forbidden')):
                result = run_recall_benchmark(vault=vault, cases_path=cases,
                    retrieval_mode='hybrid', allow_network_embeddings=False)
            self.assertFalse(result.provenance['retrieval_config']['allow_network_embeddings'])
            self.assertIsNone(result.provenance['retrieval_config']['embedding_fingerprint'])

    def test_run_id_is_deterministic_for_identical_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            cases = self._cases(tmp)
            first = run_recall_benchmark(vault=vault, cases_path=cases).to_dict()
            second = run_recall_benchmark(vault=vault, cases_path=cases).to_dict()
        self.assertEqual(first["provenance"]["run_id"], second["provenance"]["run_id"])
        self.assertEqual(first["provenance"]["dataset_sha256"], second["provenance"]["dataset_sha256"])

    def test_dataset_hash_changes_with_case_edits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            cases = self._cases(tmp)
            first = run_recall_benchmark(vault=vault, cases_path=cases).to_dict()
            payload = json.loads(cases.read_text(encoding="utf-8"))
            payload["cases"][0]["question"] = "which guardrail proxy protects credentials"
            cases.write_text(json.dumps(payload), encoding="utf-8")
            second = run_recall_benchmark(vault=vault, cases_path=cases).to_dict()
        self.assertNotEqual(
            first["provenance"]["dataset_sha256"], second["provenance"]["dataset_sha256"]
        )

    def test_run_id_changes_with_corpus_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            cases = self._cases(tmp)
            note = vault / "projects" / "demo-agent" / "STATUS.md"
            first = run_recall_benchmark(vault=vault, cases_path=cases).to_dict()
            note.write_text(note.read_text(encoding="utf-8") + "\nCorpus revision.\n", encoding="utf-8")
            second = run_recall_benchmark(vault=vault, cases_path=cases).to_dict()

        self.assertNotEqual(first["provenance"]["corpus_sha256"], second["provenance"]["corpus_sha256"])
        self.assertNotEqual(first["provenance"]["run_id"], second["provenance"]["run_id"])

    def test_run_id_changes_with_retrieval_config_or_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            cases = self._cases(tmp)
            first = run_recall_benchmark(vault=vault, cases_path=cases).to_dict()
            with patch("arvyx_control.benchmark.INDEX_FORMAT", INDEX_FORMAT + 1):
                config_changed = run_recall_benchmark(vault=vault, cases_path=cases).to_dict()
            with patch("arvyx_control.benchmark.__version__", "next-version"):
                version_changed = run_recall_benchmark(vault=vault, cases_path=cases).to_dict()

        self.assertNotEqual(first["provenance"]["run_id"], config_changed["provenance"]["run_id"])
        self.assertNotEqual(first["provenance"]["run_id"], version_changed["provenance"]["run_id"])

    def test_committed_benchmark_dataset_hash_and_run(self) -> None:
        cases = ROOT / "fixtures" / "recall-benchmark.json"
        result = run_recall_benchmark(
            vault=ROOT / "fixtures" / "synthetic-vault",
            cases_path=cases,
        ).to_dict()

        self.assertEqual(
            result["provenance"]["dataset_sha256"],
            "5829d9c26908721f000071274bc206e574274da5ba9126d748b1b3fa6efb3817",
        )
        self.assertEqual(result["total"], 24)
        self.assertTrue(result["ok"], result)

    def test_comparison_doc_claims_carry_evidence_pointers(self) -> None:
        """docs/comparison.md must route capability claims to receipts."""
        text = (ROOT / "docs" / "comparison.md").read_text(encoding="utf-8")
        self.assertIn("fixtures/recall-benchmark.json", text)
        self.assertIn("arvyx benchmark recall --json", text)
        self.assertIn("provenance", text)
        self.assertIn("corpus", text)
        # no stale retrieval claim: embeddings exist behind hybrid/semantic modes
        self.assertNotIn("no embeddings yet", text)


if __name__ == "__main__":
    unittest.main()
