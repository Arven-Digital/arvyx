# Limitations and Non-Goals

**Status:** alpha, version `0.1.0a0`. Last checked against the code on
2026-11-02.

This page lists what the system deliberately does not do today. Each item
names where the behavior lives, so every claim can be checked against the
tree. A change that lifts a limit must update this page in the same change.

## Alpha status

- Interfaces, CLI output, HTTP routes, MCP tool shapes, and persisted formats
  (vault layout, `.arvyx/index.json`, control-event JSONL) may change before
  1.0, and a migration path is not guaranteed.
- A release requires `arvyx release-candidate --json` to pass on the exact
  candidate tree, followed by the maintainer's explicit approval; see
  [release-gate.md](release-gate.md).
- The system does not replace backups, access control, or operator review.

## Retrieval: no real embedding backend by default

- The default recall mode, `lexical`, is BM25 over a persistent term index.
- `hybrid` and `semantic` add a vector signal. Unless an embeddings endpoint
  is configured, that signal is a built-in character-trigram similarity (a
  local proxy, not a learned embedding model). No embedding model ships with
  the package and none is enabled by default.
- A real backend is bring-your-own: any OpenAI-compatible `/embeddings`
  endpoint, configured through `ARVYX_EMBEDDINGS` or
  `<vault>/.arvyx/embeddings.json`.
- When the endpoint is unreachable, recall silently falls back to the
  lexical/trigram signal instead of failing.
- The recall benchmark checks expected-source retrieval on synthetic golden
  fixtures. Its hybrid numbers measure the trigram proxy, not a hosted
  embedding model, and it does not measure answer correctness.

Check: `packages/arvctl/src/arvyx_control/embeddings.py`,
`packages/arvctl/src/arvyx_control/recall.py`, [retrieval.md](retrieval.md),
[recall-benchmark.md](recall-benchmark.md).

## MCP: request/response only

- Supported transports are direct stdio JSON-RPC, HTTP JSON-RPC at
  `POST /mcp`, and the scoped stdio-to-HTTP `safe-mcp-bridge`.
- There is no SSE transport, no long-lived response streaming, and no partial
  tool-result streaming. Clients that require SSE need a separate adapter.
- The release pipeline's `mcp_client_real` evidence is produced with the official
  MCP **Python SDK** client, not with an agent UI such as Claude Desktop or Codex.
  It is third-party protocol code on the exact tagged tree, and it is honestly
  labelled `client: python-mcp-sdk`; it is not evidence that an agent client ran.
- The posture is recorded in `examples/mcp-clients/streaming-compatibility.json`
  and checked by `make mcp-streaming-smoke`.

Check: [mcp-streaming.md](mcp-streaming.md).

## Topology: one host, not distributed

- Control state is one append-only JSONL event log on one host, serialized by
  local file locks. SQLite is a rebuildable projection of that log, not the
  source of truth.
- The only second node is a warm standby: pull replication into a vault
  marked as a replica. It is not high availability. There are no multi-writer
  primaries and no distributed consensus. Writable replica promotion is refused,
  including manual, forced and automatic paths: vault/log sync does not replicate
  the matching operation-journal/effect authority. Freshness and peer reachability
  do not override that refusal or authorize DNS/proxy cutover.
- The API speaks plain HTTP (TLS belongs to a reverse proxy), has no rate
  limiting, and trusts its network boundary. Registry changes (agents, scopes)
  are file edits on the host, not API calls.

Check: [multi-machine.md](multi-machine.md) (Known limits),
[backup-and-health.md](backup-and-health.md).

## Importers: no collision report and no schema-drift detection

- Imported notes land flat in `projects/<project>/imported/` (or its
  `obsidian/` or `basic-memory/` lane). Source subfolder structure is not kept.
- A filename collision is resolved by renaming (`note.md`, `note-2.md`)
  without reporting it as a collision. Re-importing the same source adds new
  numbered copies; imports are not idempotent updates.
- Existing frontmatter is kept verbatim and is not validated. Nothing detects
  drift between a source tool's format and what the importer expects.
- The import manifest records imported paths, skipped paths, and counts.
  Skipped entries carry no reason (secret-shaped content and paths outside the
  source are both just "skipped").

Check: `packages/arvctl/src/arvyx_control/importers.py`,
[importers.md](importers.md).

## Operator settings: local-only

- Dashboard queue filters and review controls persist only in the browser's
  local storage (`arvyx_dashboard_preferences`); the bearer stays in session
  storage. Nothing syncs these preferences across browsers, machines, or
  operators, and they are never written to the vault or the control log.

Check: [operator-surface.md](operator-surface.md).

## Dashboard: polling, not live streaming

- The operator dashboard polls `/summary`: every ten seconds, backing off to at
  most sixty seconds after failures, and paused while the tab is hidden. A
  snapshot older than thirty seconds is marked stale. Manual refresh is always
  available. There is no server push (no WebSocket or SSE).
- The Observatory demo in `apps/control-center-web` renders a static synthetic
  fixture and connects to no API.

Check: `packages/arvctl/src/arvyx_control/static/index.html`,
`apps/control-center-web/README.md`.

## Platform support

- Linux is the supported platform: the required hosted CI job runs the full suite
  on Linux for every push and pull request. The maintainers keep the clean-machine
  journey receipt in their private records.
- macOS and Windows are conditional. Their hosted CI jobs run only when the
  repository variable `HOSTED_ACTIONS_ENABLED` is `true`; until candidate-SHA
  matrix receipts exist, they are not verified.
- The Makefile and documented commands assume a POSIX shell. On Windows, run
  `python -m arvyx_control.cli ...` directly or use Git Bash; that path is
  also conditional.
- Python 3.11 or newer is required.

## Non-goals

The product does not aim to:

- be an agent framework, a vector database, or a transcript archive. It is an
  operating layer around agents: governed memory, scoped identity, approvals,
  and evidence;
- be a hosted service in its first release. It is self-hosted and
  local-first;
- ship as a markdown-only framework, a prompt pack, or screenshots without
  executable software and synthetic tests behind each claim;
- carry real operator data. Fixtures and examples are synthetic; real memory,
  prompts, credentials, hostnames, deployment configuration, and production
  logs never belong in the distribution;
- claim automatic failover, autonomous authority changes, semantic-retrieval
  guarantees, or production maturity that has not been publicly reproduced;
- trade operator clarity for decorative animation.

## Open decisions (not commitments)

The project owner has not decided whether to fund the items below. They are
listed so their absence is not mistaken for an oversight. None is promised,
scheduled, or implied by this page.

- **Embeddings:** whether to ship or recommend a default real embedding
  backend, or keep embeddings bring-your-own.
- **Streaming:** whether to add a streaming MCP transport (SSE or a successor)
  and server push for the dashboard.
- **Distributed topology:** whether to support a multi-writer or
  consensus-backed control log with automatic promotion.

## Control room, harness adapters and the native frontend

- Discovery finds known harness markers only; detection is not connection and
  connection is not execution. Read-only session-metadata adapters exist for
  Hermes (`state.db`), Claude Code (`projects/<project>/<session>.jsonl`) and
  Codex (`sessions/YYYY/MM/DD/rollout-*.jsonl[.zst]`); every other harness shows
  "No compatible local connection adapter is configured".
- Listing never reads transcripts: Last 5 and All come from the harness index or
  from file names and timestamps; an explicit reviewed inspection reads a
  bounded prefix for routing fields. A compressed Codex rollout reports its
  working directory as unavailable rather than decoding it.
- Native terminal attach is available for Hermes sessions on Linux x86_64 only,
  with the admitted onboarding-v1 artifact digest (receipt under
  `frontends/arvyx/receipts/`, rebuilt 2026-11-02 with the overlay patch applied
  fail-closed and its unit tests executed); macOS, Windows and other
  architectures report the frontend as unavailable. The admitted build has not
  yet been exercised on a real PTY with a disposable stored profile. A second,
  older `mouse-existing` digest stays pinned for installations that already
  carry it; it predates the fail-closed build and has no public receipt, so new
  installations should use the onboarding-v1 artifact, which carries both
  capabilities.
- Creating an agent from the control room produces a clean metadata profile;
  sandbox, host and root execution, remote-machine runtime control and organizer
  delegation stay unavailable until separately provisioned and verified.

Check: `packages/arvctl/src/arvyx_control/metadata_adapters.py`,
`native_artifact_policy.py`, [local-quickstart.md](local-quickstart.md).
