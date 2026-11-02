# Retrieval

Recall is deterministic and citation-backed. It runs entirely on the memory
host and is exposed identically over CLI, HTTP, and MCP, so retrieval quality
does not depend on which harness an agent uses.

## Modes

| Mode | Signal | When to use |
| --- | --- | --- |
| `lexical` (default) | BM25 over the persistent term index | Fast, no external services. Good default. |
| `hybrid` | BM25 combined with vector cosine (embeddings if configured, else char-trigram) | Fuzzy questions where wording differs from the docs. |
| `semantic` | Vector cosine first, light lexical tie-break | Concept search when keywords barely overlap. |

`hybrid` and `semantic` use real embeddings only when an embeddings provider
is configured (below). With no provider they fall back to the built-in
trigram similarity — still useful, still offline, never an error.

## Temporal decay

Recent memory can be weighted above stale memory with a half-life:

```bash
arvyx recall "current deploy status" --project relay-ops --recency-half-life-days 30
```

Each chunk carries a timestamp taken from its frontmatter date
(`updated_at`, then `promoted_at`, `created_at`, `date`) or, failing that,
the file mtime. The score is multiplied by `0.5 ** (age_days / half_life)`.
Decay is **off by default** (equal weighting) so results stay reproducible
until you opt in. This is the "temporal decay" behavior from the v1 vault,
now a per-query knob rather than a global.

## Embeddings — provider-agnostic

Embeddings are optional and never vendor-locked. Configure a provider via
`$ARVYX_EMBEDDINGS` or a gitignored `<vault>/.arvyx/embeddings.json`:

```json
{
  "provider": "http",
  "url": "https://api.openai.com/v1/embeddings",
  "model": "text-embedding-3-small",
  "api_key_env": "OPENAI_API_KEY"
}
```

`provider: "http"` speaks the OpenAI `/embeddings` request/response shape,
which is the de-facto standard. Point `url` at whatever your team runs:

- OpenAI or any hosted OpenAI-compatible API,
- a local server (vLLM, llama.cpp, text-embeddings-inference, LM Studio),
- a model hosted on one of your own machines (e.g. a Hermes box) reachable
  over the private network.

Vectors are computed at index time and cached in `.arvyx/index.json`. They
are recomputed when a file changes or when the provider/model fingerprint
changes, so switching models re-embeds automatically. If the endpoint is
unreachable at query or index time, recall silently degrades to lexical
rather than failing — memory access never depends on an embeddings service
being up.

Configuration discovery is part of this fallback boundary: unreadable or malformed
JSON, unsupported providers, missing fields, and invalid numeric settings disable
only the optional enhancement for that request. The shared loader reports these
as `EmbeddingError`; retrieval catches the error without exposing configuration
contents. Numeric JSON strings and booleans are not accepted as numbers.
`timeout_seconds` defaults to 20 and must be finite and greater than zero, at most
60 seconds (the bounded transport maximum). `batch_size` defaults to 64 and must be an integer from 1 through
2048 (fractional or floating-point JSON values are rejected). Direct
`EmbeddingConfig` construction enforces the same contract. `api_key_env` is null
or a nonempty string. No disabled state is cached across requests.

Derived chunks are reused only when source hash, mtime, size and the complete
heading-based line partition match a captured source snapshot. Out-of-range,
overlapping, truncated or missing chunks are rebuilt, including durable
checkpoints and completed-artifact repair. Empty snapshots cannot be replaced
by cached headings as citation evidence. Format 6 invalidates earlier cached
partitions, terms and vectors. Durable checkpoints are also revalidated against
source-derived headings and exact term counts before reuse.

Fenced Markdown is excluded consistently from heading boundaries, lexical and
trigram terms, embedding inputs and extracted answers/cards. Backtick and tilde
fences (including up to three spaces of indentation) close only with the same
character and at least the opening run length; an unclosed fence excludes the
remaining text. Logical source lines and citation ranges are preserved. Explicit
source excerpts remain source excerpts, and may contain examples.

Malformed derived JSON, including decoder `ValueError` (oversized integers) and
`RecursionError` (excess nesting), is invalid cache data, not canonical memory.
Recall rebuilds it from eligible source files. Completed-artifact validation and
checkpoint recovery use the same failure policy; publication rejects a checkpoint
that becomes invalid after processing instead of advertising completion.

## Durable rebuild worker

For a large lexical rebuild, run `arvyx index rebuild --vault <path> --owner
<worker> --json`. The worker stores status, attempt count, lease, and one
checkpoint per source file in `.arvyx/jobs.sqlite3`; an expired lease resumes
from those checkpoints instead of reprocessing completed files. Live leases
reject overlapping workers, and `--max-attempts` bounds stale recovery. On
real-clock runs a background heartbeat renews the lease every
`lease-seconds / 3`, so a single slow file can never let the lease lapse and be
stolen mid-processing (with a deterministically injected `now`, e.g. in tests,
the heartbeat is off and `lease-seconds` must exceed the longest single-file
processing time). If a source file changes during a rebuild, the attempt is
marked failed but all durable checkpoints survive: the next run reprocesses
only the changed or new files, and a changed manifest resets the attempt
budget. Job state transitions (start/complete/fail) are appended to a
hash-chained audit log at `.arvyx/jobs-audit.jsonl`. Inspect
the same receipt without doing work with `arvyx index status --vault <path>
--json`. This command is a resumable worker primitive, not a scheduler; existing
cron or execution dispatch remains responsible for invoking it.

All index publishers use `.arvyx/index-publication.lock`. A rebuild takes this
publication flock **before** starting its SQLite jobs transaction, and holds both
through atomic replacement, durable readback, source revalidation and completion.
Completed-artifact acceptance uses the same order. File processing and heartbeat
transactions never wait on the publication flock. Recall computes document and
query embeddings outside publication locks; its locked section only merges and
publishes derived cache entries. No provider I/O runs under either lock.

## Cost and privacy notes

- The vault's raw/archive/pending lanes are never embedded or recalled.
- Only chunk text (heading + body, truncated) is sent to the embeddings
  endpoint. If that endpoint is external, treat it as you would any external
  service; for sensitive vaults, host the embeddings model on your own
  network and point `url` at it.
- Embeddings are a quality boost, not a dependency. `lexical` needs nothing
  external and is the safe default for air-gapped hosts.
