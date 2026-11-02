# Recall Benchmark

`arvyx benchmark recall` runs a deterministic golden-set benchmark for the
token-bounded recall layer.

The benchmark checks that fuzzy memory questions return the expected cited
curated sources, avoid forbidden raw/archive sources, and meet a minimum
confidence threshold.

## Run

```bash
arvyx benchmark recall --json
arvyx benchmark recall --retrieval-mode hybrid --json
```

Default inputs:

- vault: `fixtures/synthetic-vault`
- cases: `fixtures/recall-benchmark.json`

## Case Schema

```json
{
  "schema_version": 1,
  "suite": "synthetic-vault-recall",
  "description": "Golden recall cases for the curated synthetic vault.",
  "cases": [
    {
      "id": "safe_bridge_decision",
      "category": "decisions",
      "question": "what did we decide about safe mcp bridge",
      "project": "demo-agent",
      "expected_sources": ["projects/demo-agent/DECISIONS.md"],
      "forbidden_sources": ["projects/demo-agent/raw/private-draft.md"],
      "min_confidence": 0.8
    }
  ]
}
```

The JSON result includes the top-level fixture metadata and a `categories`
object with per-category pass counts and scores. Categories keep release
evidence legible as the golden set grows.

The `retrieval_mode` field records which ranker produced the result:

- `lexical`: default deterministic term/alias scoring.
- `hybrid`: lexical scoring plus vector cosine from a configured embedding
  endpoint, or local char-trigram similarity when no valid provider is selected.

Hybrid/semantic CLI runs may send queries and uncached document chunks to the
configured HTTP embedding endpoint and may incur provider costs. Inspect ambient
`ARVYX_EMBEDDINGS` and vault configuration before an explicitly approved run;
secret redaction does not make private prose safe to share. Lexical mode does
not use embeddings. Evidence export explicitly sets `allow_network_embeddings=False`
for its hybrid comparison. Its provenance records a null embedding fingerprint
and the disabled-network policy: an offline fallback is not a hosted-model result.

## Content Budget and Citation Contract

`max_tokens` is a bounded-content approximation, not an exact model tokenizer.
Each content string costs the larger of its whitespace word count and its UTF-8
byte length divided by 16 (rounded up). Clipping includes its ellipsis in that
bound and redacts secrets before truncation. This bounds unbroken identifiers,
URLs, and multibyte text as well as ordinary prose.

Recall answers share one budget. Context-pack answers and excerpt text share
one decreasing aggregate budget; excerpts are omitted when fewer than the
minimum 40 units remain. Repeated card claims and response metadata are not
additional content-budget allocations; the budget is not a serialized JSON
byte cap. Cards retain the accepted claim's originating source and line range,
even when an earlier ranked match contributes no answer.

Candidate15 review findings 5–7 were exercised with private regressions:
the unchanged recall implementation failed all three scenarios (seven failing
assertions/subtests); the corrected implementation passed all three tests.
The 18 existing recall/excerpt/context-pack API, CLI and MCP checks also passed.
Receipts: `dependency-fix/sol16-recall-red.log`,
`sol16-recall-green.log`, and `sol16-recall-targeted.log` in the private
round-five deliverables. An attempted broad `test_recall.py` run timed out;
this is not a full-suite or release approval. Deployment/public release remain HOLD.

## What It Proves

- Fuzzy recall can find durable decisions and current truth.
- The default recall path cites source files and line ranges.
- Raw/archive memory lanes stay out of the retrieved source set.
- Category summaries can show whether regressions are isolated to decisions,
  status/current-truth, security, or future benchmark groups.
- Hybrid retrieval can be compared against the same golden fixtures without
  changing the default recall contract.
- Recall quality can be regression-tested in CI.

## What It Does Not Prove

- An offline hybrid fallback does not qualify a configured hosted embedding model.
- It does not prove answer correctness beyond expected source retrieval.
- It does not replace human review for public release.

## Optional embedding configuration failures

Benchmark provenance uses the same optional configuration boundary as recall.
Invalid or unreadable embedding configuration yields a null
`embedding_fingerprint` and retains lexical/trigram fallback rather than aborting
provenance generation after recall. The requested retrieval mode remains recorded;
a null fingerprint is not evidence of dense embedding execution. The integration
regression is authored but not executed.
