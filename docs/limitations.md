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

## Inputs: JSON nesting is bounded

- Every network and loopback intake (MCP stdio and HTTP, the control APIs, the
  onboarding and control-room servers, pairing, delivery and replica peers, remote
  embedding and broker replies) refuses a JSON document nested deeper than
  **256** levels before parsing it. The refusal is the ordinary decode error of
  that surface (JSON-RPC `-32700`, HTTP `400`); the limit does not depend on the
  Python version's recursion behaviour. The bridge keeps its own stricter
  post-parse limit of 64 for the requests it forwards.
- Legitimate payloads are flat; the bound exists so a hostile peer cannot pick the
  interpreter's recursion limit as a failure mode. It is not configurable.

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

- Linux and Windows are the supported platforms. The hosted platform jobs run the
  full suite on Linux and on Windows (Python 3.11, 3.12 and 3.13) for pushes to
  `main`, pull requests targeting `main` and manual dispatch, when the repository
  variable `HOSTED_ACTIONS_ENABLED` is `true`; the release workflow requires both
  sets on the tagged commit. A job definition is not a receipt: the maintainers
  keep the candidate-SHA runs and the clean-machine journey receipts in their
  private records.
- Windows scope. The npm launcher (`setup`, `doctor`, `amc`, `web`), the memory
  CLI, the MCP server, the importers, harness discovery (Claude Code, Codex,
  Cursor and the other marker families) and the web control room work natively on
  Windows 10/11. The launcher requires Node 24.11 or newer and Python 3.11 or
  newer with `venv` and pip; privacy provisioning uses the system `whoami.exe` and
  `icacls.exe` and needs an NTFS volume (owner and DACL checks). The Windows job
  builds, installs and smokes the npm package (`setup`, `doctor`, `amc`, `web`);
  building the tarball needs the repository-pinned setuptools and the cached
  frontend dependencies, which the job prepares before the offline build. The
  Windows smoke checks the platform's native-install refusal (no admitted native
  artifact for Windows); planted native metadata is verified by the POSIX-only
  verifier. The following are POSIX-only and refuse explicitly on Windows
  rather than degrade: the PTY owner and native terminal attach, host and sandbox
  executors (`--execution-policy`), secret delivery destinations, the Docker
  deployment kit, the Hermes restart continuation and the fork-based snapshot
  guard. The terminal surface (`curses`) is not available; use `arvyx web`.
- Windows privacy model. Where POSIX code requires `uid` ownership and mode
  `0700`/`0600`, Windows requires the NTFS owner and DACL to name only the current
  user, `SYSTEM` and `Administrators` (`arvyx_control.windows_acl`); directories
  and files the product creates owner-only get that DACL, so a prefix or home
  under `%LOCALAPPDATA%` qualifies, while `%TEMP%` trees that grant other accounts
  access are refused like a world-writable `/tmp`. An elevated administrator's
  new objects are owned by `Administrators` (the token's default owner), so
  ownership means the user SID or that default owner; a hosted CI runner is such
  an account. Modes are not applied on Windows (`chmod` there only sets the
  READONLY attribute, which would break rename and delete).
- Windows durability. File contents are fsynced; directory names are not
  (`FlushFileBuffers` on a directory handle flushes the whole NTFS volume), so
  crash-durable namespaces rely on NTFS journaling. Descriptor-relative no-follow
  opens use `NtCreateFile` relative to a directory handle with
  `FILE_OPEN_REPARSE_POINT` (`arvyx_control.safe_open`); junctions and symbolic
  links are refused like POSIX symlinks. `st_ctime` on Windows is the creation
  time. SQLite stores file identities as signed 64-bit integers.
  Atomic replacement of a file that another handle holds open uses the NTFS
  POSIX-semantics rename, which succeeds for readers that share delete access (the
  product's own readers do); a program holding the file without delete sharing
  (an editor, an indexer) delays the replacement up to two seconds, after which the
  write fails rather than corrupt the file.
- Windows bytes. The C run-time opens raw descriptors (`os.open` without
  `O_BINARY`) in text mode, dropping carriage returns on read and inserting them
  on write; importing `arvyx_control` sets the process default to binary
  (`_set_fmode(_O_BINARY)`), so descriptor reads and writes carry bytes
  unchanged (Python's own `open()` is not affected). Product text writes pass an
  explicit LF newline; a file the operator edits with CRLF is read byte for byte,
  so its digest is the digest of those bytes.
- Windows owner endpoint. Python on Windows has no `AF_UNIX`; the cockpit owner
  listens on `127.0.0.1` at an ephemeral port and writes the port and a random
  token into the private `runtime/cockpit.sock` file; clients present the token
  with every request. The reachable set is the same as the POSIX socket's: processes
  that can read the owner's private runtime directory.
- The Python control plane also runs on macOS. `pipe2`, `waitid(WNOWAIT)`,
  `/proc/self/fd` and `pidfd` are not on Darwin, so those calls go through
  `posix_support`: a CLOEXEC pipe, a kqueue exit watch that does not reap, a
  no-follow walk that accepts only the root-owned `/var`, `/tmp` and `/etc`
  firmlinks, and process-group cleanup where pidfd is absent. Native sealed
  execution (memfd) remains Linux-only. A macOS binary is not admitted in this
  change. Hosted macOS CI stays conditional: it runs only when
  `HOSTED_ACTIONS_ENABLED` and `HOSTED_EXPERIMENTAL_PLATFORMS` are both `true`,
  and the release workflow does not require it.
- The Makefile assumes a POSIX shell. On Windows, run `python -m arvyx_control.cli ...`
  (or the npm launcher) from PowerShell or Git Bash.
- Python 3.11 or newer is required. The suite runs on 3.11, 3.12 and 3.13 in CI.
  Python 3.13 verifies TLS peers with `VERIFY_X509_STRICT`: a CA used for the
  secret-delivery or pairing endpoints must carry `basicConstraints CA:TRUE` and
  a `keyUsage` with `keyCertSign`, and leaves need `keyUsage`, a SAN and an EKU;
  a bare `openssl req -x509` certificate is refused there.

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
  architectures report the frontend as unavailable. The maintainers ran the
  chooser acceptance on a real pseudo-terminal against a synthetic store
  (`scripts/native_chooser_pty_acceptance.py`: open, exact target, activity-ordered
  Last 5, search, scroll, close, no transcript bytes, no launch); the receipt is
  attached to the release beside the artifact, not stored in this tree, and the
  script needs a POSIX host, the admitted binary and the `pyte` terminal emulator.
  Exact pane presentation with a live Hermes binding is not yet exercised. A second,
  older `mouse-existing` digest stays pinned for installations that already
  carry it; it predates the fail-closed build and has no public receipt, so new
  installations should use the onboarding-v1 artifact, which carries both
  capabilities.
- Creating an agent from the control room produces a clean metadata profile;
  sandbox, host and root execution, remote-machine runtime control and organizer
  delegation stay unavailable until separately provisioned and verified.

Check: `packages/arvctl/src/arvyx_control/metadata_adapters.py`,
`native_artifact_policy.py`, [local-quickstart.md](local-quickstart.md).
