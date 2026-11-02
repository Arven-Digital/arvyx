# Secret Broker

Memory should describe *where* a secret lives, never the secret itself. The
broker makes that safe and operational: agents store a reference, the broker
resolves it to a value at access time, and the value never enters the vault,
recall output, or the audit log.

This is the v1 vault's "store a pointer, not the key" rule turned into an
enforced runtime path.

## References

A secret reference is a URI:

```
secret://<broker>/<path>
```

Examples: `secret://railway/DATABASE_URL`, `secret://onepassword/DEMO-DB/credential`,
`secret://project-a/supabase.env`.

References are sanctioned: they are allowed in stored memory and survive
recall untouched, because they carry no value. A **literal** secret (a
password or key written inline) is still refused on write and redacted on
read, while a `secret://vault/db` reference is fine.

## Providers

Brokers are defined outside the tracked tree, in `$ARVYX_SECRET_BROKERS` or a
gitignored `<vault>/.arvyx/secret-brokers.json`:

```json
{
  "brokers": {
    "env":         { "provider": "env", "prefix": "ARVYX_SECRET_" },
    "railway":     { "provider": "envfile", "path": "/home/you/.secrets/railway.env" },
    "project-a":       { "provider": "file", "base": "/home/you/.secrets" },
    "onepassword": { "provider": "command", "command": ["op", "read", "op://Example/{path}"] }
  }
}
```

| Provider | Resolves | Notes |
| --- | --- | --- |
| `env` | `secret://env/DB` → `$ARVYX_SECRET_DB` | Optional `prefix`. |
| `envfile` | `secret://railway/DATABASE_URL` → that key in a dotenv-style file | Trims outside whitespace and removes one matching outer quote pair only; inner or unmatched quotes remain literal. No shell expansion. |
| `file` | `secret://project-a/supabase.env` → file contents under `base` | Path-traversal guarded. |
| `command` | `secret://onepassword/DEMO-DB/credential` → stdout of the command with `{path}` substituted | `{path}` is one argv element — no shell, no injection. Covers 1Password, Vault, etc. |

## Access is scoped and audited

Resolution requires the `secret.resolve` scope. Every resolution is written
to the hash-chained audit log **by reference, never by value**:

```bash
# CLI (local operator)
arvyx secret brokers --repo /srv/arvyx/vault
arvyx secret resolve "secret://railway/DATABASE_URL" --repo /srv/arvyx/vault
arvyx secret scan agents/demobot/MEMORY.md         # find refs in a doc
```

```bash
# HTTP (an agent with a secret.resolve-scoped token)
curl -s https://memory.internal.example/secret/resolve \
  -H "Authorization: Bearer $ARVYX_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ref":"secret://railway/DATABASE_URL"}'
```

The same `secret.resolve` and `secret.brokers` tools are available over MCP,
so a harness resolves a reference the same way it recalls memory.

## Production deployment

### Production authority: reuse the existing external broker

A production V2 deployment should **not** become a second secret store. Keep V2
as the governed pointer and audit plane, and resolve values through the existing
`arvyx-secret` broker at the agent/runtime edge. The broker remains separately
identity-bound, scope-gated, rate-limited, and loopback/private-network only.

The production contract is:

```text
V2 memory/recall -> secret://project/name pointer only
agent runtime     -> short-lived identity token
existing broker   -> POST /v1/secret/resolve
process edge      -> inject returned value without writing it to V2
```

Do not mount the broker runtime cache into the V2 API container, copy broker
values into `control.env`, or expose the broker publicly. The V2 `agent` MCP
profile intentionally omits `secret.resolve`; production resolution belongs to
the existing external broker and its own audit log. The built-in providers in
this package are local-development/operator adapters, not a replacement for
that production authority.

Before declaring the integration healthy, verify all of the following without
printing a value:

1. the external broker is listening only on an approved loopback/private address;
2. `/healthz` returns `200`;
3. its service manager reports a clean running state;
4. V2 stores and recalls the pointer unchanged;
5. the V2 agent MCP tool list does not expose `secret.resolve`;
6. a scoped edge-client can resolve one approved synthetic/canary pointer and
   the broker audit records only pointer metadata, never the returned value.

## Recommended pattern

1. Store the pointer in memory: `DB creds: secret://railway/DATABASE_URL`.
2. At runtime, the agent resolves it only when it actually needs the value.
3. Grant `secret.resolve` narrowly — most agents never need it; the ones that
   do get a scoped token, and their use shows up in the audit trail.

Rotate the underlying secret in your real store (1Password, env file, Vault);
nothing in the vault or its history ever has to change.
