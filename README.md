# Arvyx

**A self-hosted memory and control plane for teams of AI coding agents.**

Arvyx gives every agent on your machines one governed memory vault with
citation-backed recall, one identity and permission model, an append-only
control log with exact-command approvals, and an operator control room (web
and terminal). It runs locally, stores everything in files you can read, and
talks to agents over MCP, HTTP and a CLI. It is an operating layer around
agents, not an agent framework, a vector database or a transcript archive.

> **Alpha, version `0.1.0a0`.** Interfaces and persisted formats may change
> before 1.0. Read [Limitations](docs/limitations.md) before relying on it.

## Who it is for

- You run several AI coding agents (Hermes, Claude Code, Codex, OpenClaw or
  anything that speaks MCP or HTTP) on one or more machines and want them to
  share one curated memory instead of re-reading transcripts.
- You want every agent action that matters (approvals, handoffs, tasks, secret
  use) recorded in a log you can audit, with the operator deciding what runs.
- You want to see and steer those agents from one place: discover harnesses,
  register identities, browse recent sessions, prepare reviewed workspaces,
  attach a terminal, all without handing the browser or any agent a standing
  credential.

## What Arvyx does

**Governed memory**
- Markdown vault with curated lanes (project docs, decisions, status, policies,
  runbooks) that outrank raw history, plus a write lane
  (`suggest → pending → refine → promote/reject`) so unreviewed text never enters
  recall.
- Cited recall: deterministic lexical retrieval (BM25) with optional hybrid
  character-trigram or bring-your-own embeddings; every answer returns source
  cards and exact excerpts under a token budget (`arvyx recall`, `excerpt`,
  `context-pack`).
- Importers for Obsidian, Basic Memory and plain markdown trees into governed
  lanes; a durable, resumable index with checkpointed jobs; a repeatable recall
  benchmark (`arvyx benchmark recall`).

**Identity and authority**
- Agents, runtimes, machines and projects are modelled explicitly. Per-agent
  bearer tokens carry scopes that the HTTP API and the MCP surface enforce on
  every call (`arvyx auth`).
- Sanctioned secret references (`secret://broker/path`) resolve through a broker
  at use time; raw secrets never enter memory, logs or recall (`arvyx secret`).

**Append-only control plane**
- Tasks, approvals bound to exact command hashes, handoffs, a War Room threaded
  inbox, bus messages, health handoffs and a hash-chained server audit log.
  SQLite and the dashboards are projections of the event log, never the truth.
- A durable inter-agent execution queue with fenced effects, operator HOLD and
  replay, out-of-band delivery liveness probes, and watchdog alerts
  (`arvyx execution`, `delivery`, `health`).
- Notifier adapters (stdout, file, webhook, Telegram) that are safe by default.

**One authority model over three transports**
- `arvyx mcp` (stdio MCP server with `read-only`, `agent` and `operator`
  profiles), `POST /mcp` and the local HTTP API (`arvyx serve-api`), and the CLI,
  all gated by the same scopes.
- `safe-mcp-bridge`: a scoped stdio-to-HTTP bridge with allowlist policies, so a
  harness only ever sees the tools you granted (`arvyx bridge-policy`).

**Control room for existing agents**
- Discover local harness profiles, register an identity, connect read-only
  session metadata (Hermes, Claude Code, Codex), browse Last 5 / All sessions
  with search and pagination, and prepare reviewed workspaces, in the browser
  (`arvyx web`) or in the terminal (`arvyx amc setup`); both are commands of the
  npm launcher, which runs the same Python modules a source checkout has.
- A native terminal frontend (Linux x86_64) over owner-managed sessions, built
  reproducibly and admitted by digest only.
- Owner-side services: machine enrollment, proof-backed pairing, backup
  replication to a warm standby (`arvyx replica`), snapshot and restore drills.

**Release evidence as executable gates**
- `arvyx audit`, `readiness`, `benchmark`, `dogfood self`, `evidence export` and
  `release-candidate` turn the release decision into checks you can run; CI signs
  run-provenance and real MCP-client evidence, two model reviews by different
  providers are recorded per tree as unsigned, tree-bound receipts, and a release
  is published only after the candidate verdict on the signed assets.

## How it fits together

```text
 agents / harnesses ──MCP (stdio)──▶ arvyx mcp ─┐
                   ──MCP via safe-mcp-bridge──▶ │   one authority model:
                   ──HTTP (bearer token)──────▶ ├─▶ identities · scopes · approvals
 operator ────────── CLI / control room ──────▶ ┘            │
                                                             ▼
                      memory vault (markdown, governed lanes) + index
                      control events (append-only log) → SQLite/dashboard projections
                      hash-chained audit log · secret broker references
```

Details: [Architecture](docs/architecture.md), [Threat model](docs/threat-model.md).

## Install

Python 3.11 or newer is required for every path. Node 24.11 or newer is required
for the npm package and the web control room. Linux is the supported platform
(see [Platform support](#platform-support)).

### npm

The package is published as `arvyx@alpha` with each prerelease; until a release
exists you can install from the GitHub release assets or from source below.

```bash
npm install -g arvyx@alpha
arvyx setup --prefix ~/.arvyx-venv          # installs the bundled wheel offline into a new venv
arvyx doctor --prefix ~/.arvyx-venv         # verifies installed imports and web assets
```

The control room works against an owner home on this machine. Enroll once and
start the owner in the foreground; the venv's Python runs the same modules the
source quickstart uses:

```bash
PY=~/.arvyx-venv/bin/python
$PY -m arvyx_control.machine_enrollment --home ~/arvyx-home --machine my-laptop --confirm-local-enrollment
umask 077
printf '{"host_uid": %s, "allow_host": true}\n' "$(id -u)" > ~/arvyx-home/runtime/policy.json
printf '{"home": "%s"}\n' ~/arvyx-home > ~/arvyx-home/runtime/connection.json
$PY -m arvyx_control.cockpit --root ~/arvyx-home/runtime --vault ~/arvyx-home/vault \
  --state ~/arvyx-home/events.jsonl --host my-laptop \
  --execution-policy ~/arvyx-home/runtime/policy.json \
  --operator-credential-file ~/arvyx-home/runtime/operator.secret serve
```

`allow_host: true` lets explicitly requested host-user shells run for agents you
connect; it never grants root or sandbox execution. Omit `--execution-policy` to
deny every launch. In a second terminal, open the control room against that owner:

```bash
arvyx web --prefix ~/.arvyx-venv --connection ~/arvyx-home/runtime/connection.json \
  --operator-credential-file ~/arvyx-home/runtime/operator.secret \
  --discovery-home ~ --open
```

`arvyx web` listens on 127.0.0.1 only and hands the browser a one-time capability
in the URL fragment; on a shared host use `--browser-connection-out FILE` instead
of `--open`, because a browser launcher's command line is visible to other local
users. `arvyx amc --prefix ~/.arvyx-venv setup --url http://127.0.0.1:PORT`
offers the same steps in the terminal. The full journey and its current limits
are in [docs/local-quickstart.md](docs/local-quickstart.md).

### GitHub release assets

Each release carries the Python wheel and sdist, the Docker image archive, their
SBOMs, the signed run-provenance and MCP-client evidence, a `SHA256SUMS` file,
and, attached by the maintainer after the verdict (PUBLISHING.md step 6), the
native terminal frontend for Linux x86_64 with its receipts and `verdict.json`,
the `release-candidate` verdict computed on exactly those signed assets. Verify
before use:

```bash
sha256sum -c SHA256SUMS
gh attestation verify arvyx-0.1.0a0-py3-none-any.whl --repo Arven-Digital/arvyx
```

`SHA256SUMS` and the attestation cover the workflow-built assets. The hand-attached
native binary is verified against its pinned digest by `arvyx setup`; its receipts
and `verdict.json` are plain JSON records.

### From source

```bash
git clone https://github.com/Arven-Digital/arvyx.git
cd arvyx
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/arvyx demo --json
.venv/bin/arvyx recall "what did we decide about safe mcp bridge" \
  --vault fixtures/synthetic-vault --project demo-agent --json
```

Success is `"ok": true` from the demo and a cited answer from recall, both
against the shipped synthetic vault. The runtime is standard-library Python;
`requirements/*.lock` pin the developer, build and evidence tooling with hashes.

### Docker

The compose file refuses to start without an explicitly scoped data volume
(`ARVYX_DATA_VOLUME` in `.env`, see `.env.example`) and a control secret staged
into that volume with `scripts/stage_control_secret.py`; both steps, then
`docker compose up -d arvyx-server` (loopback-only API on 127.0.0.1:8765,
read-only root filesystem, no capabilities), are in
[docs/vps-deployment.md](docs/vps-deployment.md) together with TLS, firewalling
and rollback.

## Quick start by task

| You want to… | Start here |
| --- | --- |
| Give an MCP-speaking agent governed memory | `arvyx mcp --vault VAULT --profile agent`, or `safe-mcp-bridge` with a generated policy: [docs/safe-mcp-bridge.md](docs/safe-mcp-bridge.md), [examples/mcp-clients](examples/mcp-clients/README.md) |
| Run the operator loop (tasks, approvals, War Room, digest) | [docs/operator-surface.md](docs/operator-surface.md) and the full walkthrough in [docs/quickstart.md](docs/quickstart.md) |
| Import an existing knowledge base | `arvyx import markdown|obsidian|basic-memory`: [docs/importers.md](docs/importers.md) |
| Connect agents on another machine | per-agent tokens against a memory host: [docs/multi-machine.md](docs/multi-machine.md), [docs/auth.md](docs/auth.md) |
| Open the control room for the agents already on this machine | the npm journey above and [docs/local-quickstart.md](docs/local-quickstart.md) |
| Deploy on a VPS with TLS | [docs/vps-deployment.md](docs/vps-deployment.md) |
| Back up, check health, fail over | [docs/backup-and-health.md](docs/backup-and-health.md), [docs/notifiers.md](docs/notifiers.md) |
| Run agents' queued work durably | [docs/durable-agent-execution.md](docs/durable-agent-execution.md), [docs/outbox.md](docs/outbox.md) |
| Understand what a release proves | [docs/release-gate.md](docs/release-gate.md), [docs/evidence-bundle.md](docs/evidence-bundle.md) |

## Harness support

| Harness | Detection | Session metadata (Last 5 / All / inspect) | Native terminal attach |
| --- | --- | --- | --- |
| Hermes | yes | yes (`state.db`) | yes, Linux x86_64 with the admitted artifact |
| Claude Code | yes | yes (`projects/<project>/<session>.jsonl`, names and timestamps only) | no |
| Codex | yes | yes (`sessions/YYYY/MM/DD/rollout-*.jsonl[.zst]`, names and timestamps only) | no |
| OpenClaw, Pi, Cursor, VS Code Copilot, OpenCode, Gemini, Cline and others | marker detection only | no ("No compatible local connection adapter is configured") | no |

Any harness that speaks MCP or HTTP can use the memory and control tools
regardless of this table; the table is about the control room's local adapters.
Metadata access never reads transcripts eagerly: listing uses the harness's own
index or file names and timestamps; an explicit reviewed inspection reads a
bounded prefix for routing fields only. Detection is not connection, and
connection is not execution. See [docs/harnesses.md](docs/harnesses.md).

## Native terminal frontend

Linux x86_64 only. The frontend is a reproducible source build of
[herdr](https://github.com/herdrdev/herdr) (Apache-2.0) with the Arvyx
onboarding overlay in `frontends/arvyx/`. Its exact digest is pinned in
`arvyx_control.native_artifact_policy`; bytes with any other digest are refused,
and execution happens only from a sealed in-memory copy. Download
`arvyx-linux-x86_64` and its receipt from the GitHub release, then:

```bash
arvyx setup --prefix ~/.arvyx-venv --native-binary ./arvyx-linux-x86_64 \
  --native-receipt ./onboarding-v1-linux-x86_64.json --native-capability onboarding-v1
```

To rebuild it yourself, follow `frontends/arvyx/receipts/onboarding-v1-linux-x86_64.json`
and `scripts/build_arvyx_native.py`. Other platforms report the native frontend
as unavailable rather than falling back.

## Security posture

- Local-first: the API and the control room bind to 127.0.0.1; remote access is
  an explicit TLS reverse proxy you configure. No telemetry; the only outbound
  connections are the ones you configure (a notifier, an embedding endpoint, a
  secret broker, a replica source, delivery routes, the bridge's upstream, a
  remote delegation peer).
- Least authority: scopes per token, exact-command approvals, consent records for
  every connection, and fail-closed defaults (a missing policy denies launches; an
  unknown native digest is refused; a torn log fails the read).
- Secret hygiene: secret-shape and private-context scanners run on every push, the
  broker keeps raw values out of memory, and recall redacts secret shapes.
- Bounded inputs: every network and loopback intake bounds JSON nesting (the
  bridge additionally enforces its own, stricter post-parse limit); HTTP bodies,
  PTY output and index work are size- and time-bounded.
- Reporting: see [SECURITY.md](SECURITY.md); the design is in
  [docs/threat-model.md](docs/threat-model.md) and the audit record in
  [docs/security-audit.md](docs/security-audit.md).

Everything in this repository is synthetic or scrubbed. Do not import real
memory-vault contents, prompts, chat or audit history, tokens, keys, private
hostnames or personal context.

## How a release is made

The release workflow runs only on a protected `v*` tag whose commit has green
CI. It builds, tests, signs and attests the release assets into a **draft**
release (Docker and bridge run-provenance, real external MCP-client evidence,
SBOMs, OIDC build provenance). The maintainer then runs
`arvyx release-candidate --require-provenance` on the exact tagged commit with
those signed assets and the two recorded model-review receipts, and publishes
the draft only when the verdict is `public_release_allowed: true`. No workflow
publishes on the maintainer's behalf. See [docs/release-gate.md](docs/release-gate.md)
and [PUBLISHING.md](PUBLISHING.md).

## Platform support

Linux is the supported platform: the required CI checks run the full suite on
Linux for every push and pull request (Python 3.11, 3.12 and 3.13), and the
release workflow requires those jobs on the tagged commit. macOS and Windows
jobs exist as an experimental matrix that runs only when the repository variables
`HOSTED_ACTIONS_ENABLED` and `HOSTED_EXPERIMENTAL_PLATFORMS` are both `true`;
until their receipts exist they are not supported. The Makefile assumes a POSIX
shell; on Windows run `python -m arvyx_control.cli ...` directly or use Git Bash.

## Status and limitations

Alpha. The current ceilings are deliberate: BM25 plus trigram similarity by
default, request/response MCP only (no SSE or streaming), a single-host
append-only log with a warm standby, importers without collision reports, a
polling dashboard, native attach for Hermes on Linux x86_64 only, and
metadata-only adapters for Claude Code and Codex. Sandbox, host and root
execution of newly created agents from the control room, remote-machine runtime
control and organizer delegation remain unavailable until separately provisioned
and verified. Each claim and the check behind it are in
[docs/limitations.md](docs/limitations.md).

## Documentation

- [Architecture](docs/architecture.md): components and trust boundaries
- [Quickstart](docs/quickstart.md): the operator walkthrough from a source checkout
- [Control room journey](docs/local-quickstart.md): discover, register, connect, browse sessions
- [Operator surface](docs/operator-surface.md): the canonical operator loop
- [Retrieval](docs/retrieval.md) and [Memory quality](docs/memory-quality.md)
- [MCP bridge](docs/safe-mcp-bridge.md) and [MCP streaming posture](docs/mcp-streaming.md)
- [Harnesses](docs/harnesses.md): harness-agnostic access
- [Authentication](docs/auth.md) and [Secret broker](docs/secret-broker.md)
- [Imports](docs/importers.md): Obsidian, Basic Memory and markdown
- [Multi-machine](docs/multi-machine.md): memory host and per-agent tokens
- [Durable execution](docs/durable-agent-execution.md) and [Outbox](docs/outbox.md)
- [Backup and health](docs/backup-and-health.md), [Notifiers](docs/notifiers.md), [Watchdog alerts](docs/watchdog-alert-contract.md)
- [VPS deployment](docs/vps-deployment.md): Docker, TLS, firewall and rollback
- [Self-dogfood](docs/dogfood-self.md), [Evidence bundle](docs/evidence-bundle.md), [Release gate](docs/release-gate.md)
- [Security audit](docs/security-audit.md), [Threat model](docs/threat-model.md), [Limitations](docs/limitations.md)
- [Comparison with adjacent tools](docs/comparison.md)

## Repository layout

```text
packages/arvctl/            CLI, API, MCP, memory, control and onboarding implementation
packages/safe-mcp-bridge/   scoped stdio-to-HTTP MCP bridge
apps/control-center-api/    read-only Control Center API
apps/control-center-web/    control room evidence (screenshots, replay fixtures)
frontends/paperclip/        web control room (vendored Paperclip components, MIT)
frontends/arvyx/            native terminal frontend overlay and build receipts
packaging/npm/              the `arvyx` npm package (bundled wheel plus web assets)
fixtures/synthetic-vault/   public-safe demo memory
examples/                   synthetic integration examples (MCP clients, bridge policies)
scripts/                    audit, package, Docker, MCP and release checks
docs/                       architecture, operations and release guides
```

## Contributing and support

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request: every
change runs the same gates as a release (scanners, the full suite on three
Python versions, integration smokes, coverage floor), and documentation claims
must match the code. Report vulnerabilities as described in
[SECURITY.md](SECURITY.md), not in public issues.

## License

Apache-2.0. Keep `LICENSE`, `NOTICE` and the Arven Digital attribution when
redistributing. Vendored third-party components keep their own notices under
`licenses/` and `frontends/paperclip/vendor/`.
