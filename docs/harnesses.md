# Harness-Agnostic Access

Arvyx exposes one governed memory surface through three transports — CLI,
HTTP, and MCP (stdio). Every harness uses the same tools, scopes, and
retrieval; nothing is specific to any one agent runtime. Hermes and OpenClaw
connect the same way, and so do Claude Desktop, Codex, or anything that
speaks MCP or HTTP.

For the current private mixed-runtime fleet policy, including V2-primary
usage, V1 archive-only boundaries, agent-to-agent lifecycle, and the
stabilization gate, see the V2 primary fleet operations record (private, not exported).

## The one surface, three transports

| Transport | Best for | Auth |
| --- | --- | --- |
| MCP (stdio) | A harness that launches a local MCP server per session | Bearer token via the bridge, or direct |
| HTTP API | A harness that calls a remote memory host | `Authorization: Bearer <token>` |
| CLI | Cron jobs, operators, scripts | Local (operator) |

The tools are identical across transports: `memory.recall`,
`memory.excerpt`, `memory.context_pack`, `memory.suggest`, `memory.promote`,
`secret.resolve`, and the control tools — each gated by the caller's scopes.

## OpenClaw

OpenClaw launches stdio MCP servers. Point it at the bridge (recommended, so
the token is injected and output is filtered) or at `arvyx mcp` directly.

```json
{
  "mcpServers": {
    "arvyx-memory": {
      "command": "python",
      "args": ["-m", "safe_mcp_bridge.cli", "run", "/home/you/.arvyx/bridge.json"]
    }
  }
}
```

`bridge.json` points at the memory host and names the env var holding this
machine's agent token. On Windows set `command` to `python` or `py`.

## Hermes

Hermes reaches the same host. If the Hermes harness speaks MCP, use the same
bridge config as above. If it calls HTTP, it sends the bearer token itself:

```bash
# recall from Hermes over HTTP — identical governance, no OpenClaw involved
curl -s https://memory.internal.example/memory/recall \
  -H "Authorization: Bearer $ARVYX_HERMES_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"question":"current relay quorum","project":"relay-ops","retrieval_mode":"hybrid"}'
```

Each Hermes agent gets its own scoped token (`arvyx auth issue <agent>`), so
its writes and secret resolutions are attributed to it in the audit log just
like an OpenClaw agent's.

## Why this is not OpenClaw-oriented

- **Retrieval** runs on the host (BM25 + optional embeddings + temporal
  decay). It does not rely on any harness's indexer. See
  [retrieval.md](retrieval.md).
- **Embeddings** are an OpenAI-compatible endpoint you choose — including a
  model you host on a Hermes box — not a built-in vendor call.
- **Identity, scopes, write review, audit, and the secret broker** are
  enforced at the boundary, so every harness gets the same guarantees.
- A mixed fleet (some agents on OpenClaw, some on Hermes) shares one vault,
  one token scheme, and one audit trail.

## Migrating from a flat vault

If your agents currently read a plain markdown vault directly (the v1
pattern), keep the markdown and put this layer in front of it: map
`agents/*` and `shared/*` into project lanes, issue per-agent tokens, and
switch the harnesses from reading files to calling `memory.recall`. The human
editing experience stays markdown; the agents gain identity, review, audit,
secret brokering, and embeddings-quality recall.
