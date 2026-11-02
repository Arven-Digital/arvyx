# Multi-Machine Deployment

The intended shape for an agent fleet (for example five agents on five
machines) is one governed memory host and per-agent tokens everywhere else.
Memory stays in one place; agents connect to it, they do not replicate it.

```text
machine-1 (memory host)
  arvyx serve-api --host 127.0.0.1 --port 8765 --delivery-routes /etc/arvyx-v2/routes.d/agent-delivery-routes.json --auth-env ARVYX_CONTROL_SECRET
  reverse proxy (TLS) -> 127.0.0.1:8765
  vault on local disk, .arvyx/index.json cache, hash-chained audit log

machine-2..5 (agent hosts)
  safe-mcp-bridge run bridge-config.json   # stdio MCP for the local harness
    -> https://memory.internal.example/mcp
    -> Authorization: Bearer <that agent's token>
```

## Setup, once, on the memory host

1. Register each agent, machine, and runtime in `registry/`.
2. Issue one token per agent and deliver it to that machine's secret store:

   ```bash
   arvyx auth issue demobot --vault /srv/arvyx/vault --scope memory.read --scope memory.suggest
   arvyx auth issue vesper --vault /srv/arvyx/vault --scope memory.read --scope memory.suggest --scope control.write
   ```

   Tokens are shown once; only sha256 hashes are stored in the vault.
3. Serve the API on loopback and put a TLS reverse proxy (Caddy, nginx) or a
   private mesh (WireGuard/Tailscale-style) in front of it. The API speaks
   plain HTTP by design — never expose the port directly across machines.
4. Keep the operator secret (`--auth-env`) for humans; agents get scoped
   tokens, not the operator secret.

## Setup on each agent machine

1. Store that agent's token in an environment variable.
2. Generate a bridge policy and run the bridge as the harness's stdio MCP
   server:

   ```bash
   arvyx bridge-policy --profile read-only --upstream https://memory.internal.example/mcp \
     --auth-env ARVYX_AGENT_TOKEN --output bridge-config.json
   safe-mcp-bridge run bridge-config.json
   ```

   The bridge injects the token, filters tools, denies non-MCP JSON-RPC
   methods, redacts secret-shaped strings in responses, and writes its own
   audit trail. Harnesses that speak HTTP MCP directly can skip the bridge
   and send the bearer token themselves.

## What each agent can do

- recall / excerpt / context packs (`memory.read`)
- suggest memory into the pending lane (`memory.suggest`); an operator
  reviews with `arvyx memory pending` and promotes or rejects
- control-plane actions if granted `control.write`; the server binds every
  actor field to the authenticated agent id, so approvals and handoffs
  reflect who actually acted

## Operational checks

- `arvyx audit-log verify --log <state-dir>/audit-log.jsonl` — tamper check
- `arvyx auth list --vault <vault>` — token inventory
- `arvyx doctor --vault <vault>` — vault structure and secret-shape scan
- recall latency: the on-disk index makes warm recall single-digit
  milliseconds for vaults of hundreds of documents; the index rebuilds
  per-file on mtime change

## Known limits (deliberately not papered over)

- Warm standby is available via pull-replication and a manual failover step
  (see [docs/backup-and-health.md](backup-and-health.md)); there is no
  automatic failover or multi-primary quorum. Back up the vault directory (it
  is plain files) with your normal tooling as well.
- TLS is the proxy's job; the server does not terminate TLS itself.
- No rate limiting; the host trusts its network boundary.
- Registry edits (new agents, scope changes) are file edits on the host, not
  an API.
