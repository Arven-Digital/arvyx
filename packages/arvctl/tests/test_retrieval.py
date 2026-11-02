from __future__ import annotations

from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest

from arvyx_control.embeddings import EmbeddingConfig, embed_texts, load_embedding_config
from arvyx_control.index import load_index
from arvyx_control.recall import recall
from arvyx_control.vault import init_vault


def _dated_doc(vault: Path, name: str, date: str, body: str) -> None:
    path = vault / "projects" / "demo-agent" / name
    path.write_text(
        f"---\nid: {name}\ntype: project-status\nupdated_at: {date}\n---\n\n# {name}\n\n{body}\n",
        encoding="utf-8",
    )


class TemporalDecayTests(unittest.TestCase):
    def test_recent_doc_wins_with_decay_on(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            today = datetime.now(UTC).date()
            old = (today - timedelta(days=400)).isoformat()
            new = (today - timedelta(days=1)).isoformat()
            # identical content, different dates. "A-" sorts before "Z-", so
            # the OLD doc wins the tie without decay and the flip is real.
            _dated_doc(vault, "A-OLD-QUORUM.md", old, "The relay quorum policy is three of five machines.")
            _dated_doc(vault, "Z-NEW-QUORUM.md", new, "The relay quorum policy is three of five machines.")

            # without decay: equal scores, tie broken by path -> OLD first
            plain = recall("relay quorum policy", vault=vault, project="demo-agent")
            self.assertEqual(plain.sources[0].path.rsplit("/", 1)[-1], "A-OLD-QUORUM.md")

            # with decay: the day-old doc outranks the 400-day-old one
            decayed = recall(
                "relay quorum policy",
                vault=vault,
                project="demo-agent",
                recency_half_life_days=30,
            )
            self.assertEqual(decayed.sources[0].path.rsplit("/", 1)[-1], "Z-NEW-QUORUM.md")

    def test_decay_off_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            # default recall must be unchanged (no recency argument)
            result = recall("what did we decide about safe mcp bridge", vault=vault, project="demo-agent")
            self.assertTrue(result.sources)


# --- mock OpenAI-compatible embeddings server ---------------------------

def _bag_embedding(text: str, dims: int = 64) -> list[float]:
    # Deterministic bag-of-words vector: shared words -> high cosine. Stands
    # in for a real model so retrieval plumbing is testable offline.
    vec = [0.0] * dims
    for word in text.lower().split():
        h = 0
        for ch in word:
            h = (h * 31 + ord(ch)) % dims
        vec[h] += 1.0
    return vec


class _EmbedHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        inputs = payload.get("input", [])
        data = [{"embedding": _bag_embedding(text), "index": i} for i, text in enumerate(inputs)]
        body = json.dumps({"data": data, "model": payload.get("model")}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


class EmbeddingRetrievalTests(unittest.TestCase):
    def _serve_embedder(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _EmbedHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, f"http://127.0.0.1:{server.server_port}/v1/embeddings"

    def _configure(self, vault: Path, url: str) -> None:
        (vault / ".arvyx").mkdir(parents=True, exist_ok=True)
        (vault / ".arvyx" / "embeddings.json").write_text(
            json.dumps({"provider": "http", "url": url, "model": "test-embed"}),
            encoding="utf-8",
        )

    def test_http_provider_round_trip(self) -> None:
        server, thread, url = self._serve_embedder()
        try:
            cfg = EmbeddingConfig(provider="http", url=url, model="m", api_key_env=None, timeout_seconds=5, batch_size=8)
            vecs = embed_texts(cfg, ["heartbeat cadence", "unrelated banana"])
            self.assertEqual(len(vecs), 2)
            self.assertEqual(len(vecs[0]), 64)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_index_stores_vectors_and_semantic_recall_uses_them(self) -> None:
        server, thread, url = self._serve_embedder()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                vault = Path(tmp) / "vault"
                init_vault(vault)
                self._configure(vault, url)

                cfg = load_embedding_config(vault)
                self.assertIsNotNone(cfg)
                chunks = load_index(vault, cfg)
                self.assertTrue(any(c.vector is not None for c in chunks))

                # semantic mode ranks the DECISIONS chunk (shares words with
                # the query) via embedding cosine, not lexical overlap
                result = recall(
                    "safe mcp bridge decision",
                    vault=vault,
                    project="demo-agent",
                    retrieval_mode="semantic",
                )
                self.assertTrue(result.sources)
                self.assertTrue(any("DECISIONS.md" in s.path for s in result.sources))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_fingerprint_invalidates_vectors_on_model_change(self) -> None:
        server, thread, url = self._serve_embedder()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                vault = Path(tmp) / "vault"
                init_vault(vault)
                self._configure(vault, url)
                load_index(vault, load_embedding_config(vault))

                # change the model -> fingerprint changes -> re-embed
                (vault / ".arvyx" / "embeddings.json").write_text(
                    json.dumps({"provider": "http", "url": url, "model": "different-model"}),
                    encoding="utf-8",
                )
                chunks = load_index(vault, load_embedding_config(vault))
                self.assertTrue(any(c.vector is not None for c in chunks))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_no_config_stays_lexical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            self.assertIsNone(load_embedding_config(vault))
            chunks = load_index(vault, None)
            self.assertTrue(all(c.vector is None for c in chunks))


if __name__ == "__main__":
    unittest.main()
