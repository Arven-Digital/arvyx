# safe-mcp-bridge Integration

`safe-mcp-bridge` should sit between stdio MCP clients and the Arvyx HTTP/MCP
surface when a client needs scoped tool access.

This repo ships two synthetic safe-mcp-bridge config examples:

- `examples/safe-mcp-bridge/read-only.json`: memory recall and source expansion
  only.
- `examples/safe-mcp-bridge/agent.json`: governed memory, own session checkpoint,
  suggestions, and non-authority coordination tools.
- `examples/safe-mcp-bridge/operator.json`: memory plus task and approval tools.

The examples intentionally use placeholder local upstream and token environment
names. They contain no real hostnames, tokens, or private service pointers.

You can also generate matching bridge config JSON from the live MCP tool
surface:

```bash
arvyx bridge-policy --profile read-only
arvyx bridge-policy --profile agent --output /tmp/arvyx-agent-bridge.json
arvyx bridge-policy --profile operator --output /tmp/arvyx-operator-bridge.json
```

The generator fails if a policy references a tool name that the Arvyx MCP server
does not export. That keeps bridge policy drift visible before a runtime starts.
The generated JSON uses the schema consumed by `safe-mcp-bridge run` and
`safe-mcp-bridge doctor`: `target`, `auth`, `policy`, `audit`, and `redaction`.

For offline config diagnostics without starting an upstream server:

```bash
safe-mcp-bridge lint examples/safe-mcp-bridge/read-only.json --json
safe-mcp-bridge lint examples/safe-mcp-bridge/operator.json --json
```

The lint command checks the allowlist shape, duplicate/unknown tools when the
Arvyx tool registry is importable, audit redaction, and fail-on-leak settings.

Before upstream dispatch, `target.timeout_seconds` must convert to a finite,
positive number (default 20 seconds). Null, Boolean, malformed, nonpositive and
nonfinite values return a typed bridge error without dispatching; they do not
escape the stdio request loop as conversion errors. This validation is not a
hard cancellation guarantee for kernel or filesystem operations.

When running the local API server, point safe-mcp-bridge at the raw MCP endpoint:

```text
http://127.0.0.1:8765/mcp
```

The `/mcp` route returns JSON-RPC directly. The REST-style `/memory/*`,
`/tasks`, `/approvals`, `/handoffs`, and `/bus` routes keep their status/body
envelope for dashboard and CLI API calls.

The HTTP API enforces MCP profiles server-side. By default, `/mcp` uses the
`read-only` profile and exposes only memory tools. `--mcp-profile agent` exposes
the bounded working-agent surface; `--mcp-profile operator` is reserved for the
full authority surface. Identity-bound agent tokens are always capped at the
`agent` profile server-side, even when the API itself runs `--mcp-profile
operator` for the dashboard and `arvctl`, so a per-agent bearer token never
receives approval decisions or handoff review through `/mcp`. The bridge remains the
recommended client boundary, but raw `/mcp` now fails closed for read-only
clients instead of relying on the bridge as the only filter.

See `docs/dogfood.md` for the reference end-to-end bridge run against
this repository.

CI validates a public-safe E2E transcript:

```bash
make bridge-e2e-smoke
```

To rerun the stronger live binary integration locally:

```bash
SAFE_MCP_BRIDGE_BIN=/path/to/safe-mcp-bridge make bridge-dogfood-smoke
```

## Read-Only Shape

Use read-only policy for agent clients that should remember and cite, but should
not create tasks or approvals.

Allowed tools:

- `memory.recall`
- `memory.excerpt`
- `memory.context_pack`
- `control.thread_inbox`
- `control.thread_pending`

The two thread tools are War Room reads only: a read-only client may see its
inbox and pending queue, while post/ack/done/read-all require the agent or
operator profile, and identity-bound callers are always scoped to their own
inbox.

## Agent Shape

Use the agent policy for Hermes/OpenClaw working agents. The `agent` profile is
HTTP-only because authenticated identity and token-scope intersection are mandatory;
direct stdio startup with `--mcp-profile agent` is rejected fail-closed. It combines governed
recall, session get/set, suggestions, delivery receipts, tasks, approval
request/list/consume, handoffs, bus, and identity-scoped thread operations. Task
completion is limited to the owner, approval consumption to the requester, and
handoff completion to a participant. It
does not expose `control.approval_approve`, `control.handoff_review`, memory
curation/refinement, or secret tools. The HTTP server also intersects this
allowlist with the per-agent token scopes; the bridge never receives an operator
credential.

## Operator Shape

Use operator policy for local trusted runtimes that may coordinate work through
the control plane.

Additional allowed tools:

- `control.task_create`
- `control.task_list`
- `control.task_done`
- `control.approval_request`
- `control.approval_approve`
- `control.approval_consume`
- `control.approval_list`
- `control.handoff_create`
- `control.handoff_list`
- `control.handoff_accept`
- `control.handoff_review`
- `control.handoff_complete`
- `control.bus_post`
- `control.bus_list`
- `control.thread_post`
- `control.thread_inbox`
- `control.thread_pending`
- `control.thread_ack`
- `control.thread_done`
- `control.thread_read_all`

The test suite verifies that these policies reference real MCP tool
names exported by this repo. CI also validates the read-only bridge transcript
for visible tools, forwarded recall, blocked control writes, required audit
events, and absence of credential/private-path leakage.

For direct stdio client examples, see `examples/mcp-clients/`. Those fixtures
stay read-only and are validated by `make mcp-client-smoke`.
