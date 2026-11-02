# API Auth

The Control Center API has three credential levels:

1. **Per-agent tokens (recommended).** `arvyx auth issue <agent>` mints a
   bearer token for a registry agent; only its sha256 hash is stored (in
   `registry/tokens/`). The token's scopes gate every route and MCP tool,
   and the authenticated agent id overrides whatever actor name a request
   body claims — an agent cannot approve its own request by lying about
   who it is.
2. **Shared operator secret (`--auth-env`).** Grants all scopes as the
   `operator` identity. Constant-time comparison. Suitable for a single
   trusted operator, not for a fleet.
3. **Unauthenticated.** Only curated-memory reads (`/memory/recall`,
   read-only MCP tools) are served. Every mutating route returns 401
   unless the server was started with `--allow-unauthenticated-demo`
   (loopback-only escape hatch for demos).

Binding a non-loopback host such as `0.0.0.0` always requires `--auth-env`.
The API server itself speaks plain HTTP: for any non-loopback deployment,
terminate TLS in front of it (see `docs/multi-machine.md`).

## Scopes

| Scope | Grants |
| --- | --- |
| `memory.read` | recall, excerpt, context packs; excerpts are limited to curated Markdown under `projects/` and `agents/`, with forbidden lanes excluded on both requested and resolved paths; unpromoted `conversations/cockpit-archive/` blobs are not readable |
| `memory.suggest` | suggest new memory into the pending lane, list pending |
| `memory.refine` | claim pending/imported suggestions into the refining lane and rewrite them, list refining |
| `memory.curate` | promote/reject pending, imported, and refined memory |
| `control.read` | list tasks, approvals, handoffs, bus messages; start-of-session / weekly digest |
| `control.delivery` | list only the authenticated agent's deliveries and write identity-bound lifecycle receipts; grants no task, approval, or general control authority |
| `control.write` | create/complete tasks, request/consume approvals, handoffs, bus posts; excludes operator-only approval decisions and delivery receipt tools |
| `session.read` | read hot agent checkpoint state; separate from curated memory reads |
| `session.write` | write only the authenticated agent's own hot checkpoint state |
| `secret.inspect` | inspect configured provider health and validate `secret://` pointers without resolving values; intended for Kiran's security-authority identity |
| `secret.resolve` | REST secret resolution for identities explicitly granted `secret.resolve`, including scoped agent tokens; excluded from the agent MCP profile and never implied by `secret.inspect` |

Issue, inspect, and revoke tokens. Use named slots when one agent has independent long-lived and short-lived credentials; reissuing one slot invalidates only that slot. Omitting `--slot` preserves the legacy `registry/tokens/<agent>.json` path.

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli auth issue demobot \
  --vault fixtures/synthetic-vault \
  --slot presence \
  --scope control.read
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli auth issue demobot \
  --vault fixtures/synthetic-vault \
  --slot job --ttl-seconds 900 \
  --scope memory.read --scope memory.suggest
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli auth list --vault fixtures/synthetic-vault
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli auth revoke demobot --slot job --vault fixtures/synthetic-vault
```

Token records are written atomically with mode `0600`. Slot names are lowercase path-safe identifiers; separators, traversal, uppercase, and ambiguous `--` names are rejected.

Issued credentials use `arv_<agent-id>_<40 hex characters>`. Canonical secret
screening and the standalone bridge detector reject/redact this shape even in
ordinary prose, without an assignment or Bearer prefix. An agent named
`operator` remains an agent: identity-bound handoff completion requires a handoff
participant. The trusted operator completion override remains available to the
authenticated shared-operator identity and local operator workflows.

## HTTP thread target spelling

Concrete thread targets use the dispatch identity policy: trim and casefold
names for comparison only. `Sage` and `sage` identify the same recipient for
HTTP inbox/pending queries (including the legacy `agent` query alias), read-all,
ACK and DONE. Historical stored spelling is preserved. An explicit target
query for another canonical identity is still rejected; `all` is a broadcast,
not recipient ownership, and grants no ACK/DONE authority. Operator/global
access and authenticated actor binding are unchanged. The shared HTTP scope
helper also gates delivery/execution lists, whose target filters use the same
concrete-name comparator.

This does not casefold event/subject/execution IDs, worker ownership tokens,
completion artifact strings or exact evidence anchors. Reply completion
contracts continue to require their stored literal target-specific artifact
and reply spelling. MCP's separate participant/ownership gates are not changed
by this HTTP policy update.

## Operator secret example

```bash
umask 077
python3 scripts/create_secret_file.py secrets/arvyx-control-secret

PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli serve-api \
  --host 127.0.0.1 \
  --port 8765 \
  --delivery-routes config/agent-delivery-routes.example.json \
  --auth-file secrets/arvyx-control-secret
```

When serving:

- `/health`, `/`, and `/dashboard` remain public
- everything else requires a scope the caller's identity carries
- request bodies larger than 1 MiB are rejected before parsing
- invalid `Content-Length` headers are rejected with `400`
- every non-public request (allowed or denied) is appended to the
  hash-chained audit log; verify it with `arvyx audit-log verify`

Do not pass real bearer values as command arguments. Use environment variables
or a secret manager.

The raw `/mcp` route defaults to the `read-only` MCP profile. `agent` adds
session checkpoints, memory suggestions, delivery receipts, ordinary coordination
(tasks, approval request/list/consume, handoffs, bus, and identity-scoped threads),
and the value-free `secret.providers` / `secret.pointer_check` inspection tools when
the caller also holds `secret.inspect`. It deliberately excludes approval decisions,
handoff review, curation, and `secret.resolve`. `operator` adds the full curation and
control surface. The profile is intersected with the caller's token scopes, so a
profile can never grant more than the identity holds.

For a bounded expiry validation, `auth issue` also accepts `--ttl-seconds` (mutually
exclusive with `--ttl-days`). Use it only with a synthetic or dedicated disposable
identity, confirm one authenticated request succeeds, wait for wall-clock expiry, then
confirm the same request returns `401`. Revoke the token after the test; never capture
its value in transcripts.
