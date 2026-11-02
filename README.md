# Arvyx

Self-hosted memory and control plane for operating AI agent teams.

Arvyx gives a team of agents one governed memory vault, citation-backed recall,
scoped identities, append-only control events, exact-command approvals and an
operator control room, all local-first and inspectable. It is an operating layer
around agents, not an agent framework, vector database or transcript archive.

> **Alpha, version `0.1.0a0`.** Interfaces and persisted formats may change
> before 1.0. Read [Limitations](docs/limitations.md) before relying on it.

## What you get

- **Governed markdown memory**: curated project docs, decisions, status, policies
  and runbooks outrank raw history; a write lane (`suggest → pending → refine →
  promote/reject`) keeps unreviewed text out of recall.
- **Cited recall**: deterministic lexical retrieval (BM25) with optional hybrid or
  bring-your-own embeddings; every answer returns source cards and exact excerpts,
  bounded by a token budget.
- **Identity and authority**: agents, runtimes, machines and projects are modelled
  explicitly; per-agent bearer tokens carry scopes that the API and MCP surface
  enforce on every call.
- **Append-only control**: tasks, approvals bound to exact command hashes,
  handoffs, War Room threads, health handoffs and a hash-chained audit log; SQLite
  is only a projection of the event log.
- **MCP, HTTP and CLI on one authority model**: `arvyx mcp` (stdio), `POST /mcp`,
  the scoped `safe-mcp-bridge`, the `arvyx` CLI and a packaged operator dashboard.
- **Control room for existing agents**: discover local harness profiles, register
  an identity, connect read-only session metadata (Hermes, Claude Code, Codex),
  browse Last 5 / All sessions with search and pagination, and prepare reviewed
  workspaces, in the browser or with `amc setup` in the terminal.
- **Native terminal frontend (Linux x86_64)**: a reproducibly built, digest-pinned
  terminal UI over owner-managed sessions; see [Native frontend](#native-terminal-frontend).
- **Release evidence as executable gates**: audit, dogfood, Docker runtime smoke,
  real MCP-client evidence, multi-model review receipts and a candidate verdict.

## Install

Python 3.11 or newer is required for every path. Node 24.11 or newer is required
for the npm package and the web control room.

### npm (recommended)

```bash
npm install -g arvyx
arvyx setup --prefix ~/.arvyx-venv          # installs the bundled wheel offline into a new venv
arvyx doctor --prefix ~/.arvyx-venv         # verifies installed imports and web assets
```

The control room works against an owner home on this machine. Enroll once and
start the owner in the foreground; the venv's Python runs the same modules the
source quickstart uses (Linux is the supported platform):

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
against the shipped synthetic vault. The full operator walkthrough (MCP,
approvals, imports, live API, release evidence, War Room) is in
[docs/quickstart.md](docs/quickstart.md); the end-to-end control-room journey
on a clean machine is in [docs/local-quickstart.md](docs/local-quickstart.md).

### Docker

The compose file refuses to start without an explicitly scoped data volume
(`ARVYX_DATA_VOLUME` in `.env`, see `.env.example`) and a control secret staged
into that volume with `scripts/stage_control_secret.py`; both steps, then
`docker compose up -d arvyx-server` (loopback-only API on 127.0.0.1:8765,
read-only root filesystem, no capabilities), are in
[docs/vps-deployment.md](docs/vps-deployment.md) together with TLS, firewalling
and rollback.

## Harness support

| Harness | Detection | Session metadata (Last 5 / All / inspect) | Native terminal attach |
| --- | --- | --- | --- |
| Hermes | yes | yes (`state.db`) | yes, Linux x86_64 with the admitted artifact |
| Claude Code | yes | yes (`projects/<project>/<session>.jsonl`, names and timestamps only) | no |
| Codex | yes | yes (`sessions/YYYY/MM/DD/rollout-*.jsonl[.zst]`, names and timestamps only) | no |
| OpenClaw, Pi, Cursor, VS Code Copilot, OpenCode, Gemini, Cline and others | marker detection only | no ("No compatible local connection adapter is configured") | no |

Metadata access never reads transcripts eagerly: listing uses the harness's own
index or file names and timestamps; an explicit reviewed inspection reads a
bounded prefix for routing fields only. Detection is not connection, and
connection is not execution.

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

## Platform support

Linux is the supported platform: the required CI job runs the full suite on
Linux for every push and pull request. macOS and
Windows jobs exist in the matrix and run when the repository variable
`HOSTED_ACTIONS_ENABLED` is `true`; until their receipts exist they are
conditional. The Makefile assumes a POSIX shell; on Windows run
`python -m arvyx_control.cli ...` directly or use Git Bash.

## Safety boundary

Everything in this repository is synthetic or scrubbed. Do not import real
memory-vault contents, prompts, chat or audit history, tokens, keys, private
hostnames or personal context. The private-context scanner, the secret-shape
scanner and Gitleaks run in CI; `arvyx audit --json` repeats the internal
evidence checks locally.

The release workflow builds, tests, signs and attests the release assets into a
**draft** release (Docker and bridge run-provenance, real external MCP-client
evidence). The maintainer then runs `arvyx release-candidate --json` on the exact
tagged tree with those signed assets, the two multi-model review receipts, the
audit, readiness, recall benchmarks and self-dogfood, and publishes the draft only
when the verdict allows. No workflow publishes on the maintainer's behalf. See
[docs/release-gate.md](docs/release-gate.md).

## Documentation

- [Architecture](docs/architecture.md): components and trust boundaries
- [Retrieval](docs/retrieval.md): lexical, hybrid, semantic and temporal recall
- [MCP bridge](docs/safe-mcp-bridge.md): scoped bridge policies
- [Harnesses](docs/harnesses.md): harness-agnostic access
- [Control room journey](docs/local-quickstart.md): discover, register, connect, browse sessions
- [Operator surface](docs/operator-surface.md): the canonical operator loop
- [Authentication](docs/auth.md): bearer enforcement for the local API
- [Imports](docs/importers.md): Obsidian, Basic Memory and markdown imports
- [Multi-machine](docs/multi-machine.md): memory host and per-agent tokens
- [Backup and health](docs/backup-and-health.md): backup, checks and failover
- [VPS deployment](docs/vps-deployment.md): Docker, TLS, firewall and rollback
- [Notifier safety](docs/notifiers.md): stdout, file, webhook and Telegram adapters
- [Self-dogfood](docs/dogfood-self.md): recall and evidence against these docs
- [Release gate](docs/release-gate.md) and [Security audit](docs/security-audit.md)
- [Threat model](docs/threat-model.md) and [Limitations](docs/limitations.md)

## Repository layout

```text
packages/arvctl/            CLI, API, MCP, memory, control and onboarding implementation
packages/safe-mcp-bridge/   scoped stdio-to-HTTP MCP bridge
apps/control-center-api/    read-only Control Center API
frontends/paperclip/        web control room (vendored Paperclip components, MIT)
frontends/arvyx/            native terminal frontend overlay and build receipts
packaging/npm/              the `arvyx` npm package (bundled wheel plus web assets)
fixtures/synthetic-vault/   public-safe demo memory
examples/                   synthetic integration examples
scripts/                    audit, package, Docker, MCP and release checks
docs/                       architecture, operations and release guides
```

## Limitations

The current ceilings are deliberate: BM25 plus trigram similarity by default,
request/response MCP only, a single-host append-only log with a warm standby,
importers without collision reports, a polling dashboard, native attach for
Hermes on Linux x86_64 only, and metadata-only adapters for Claude Code and
Codex. Sandbox, host and root execution of newly created agents from the control
room, remote-machine runtime control and organizer delegation remain
unavailable until separately provisioned and verified. Details and the checks
behind each claim are in [docs/limitations.md](docs/limitations.md).

## License

Apache-2.0. Keep `LICENSE`, `NOTICE` and the Arven Digital attribution when
redistributing. Vendored third-party components keep their own notices under
`licenses/` and `frontends/paperclip/vendor/`.
