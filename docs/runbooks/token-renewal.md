# Runbook: agent token expiry and renewal

Agent bearer tokens carry an expiry (30 days unless issued with `--ttl-days`).
When one lapses, every call that agent makes to the control plane fails with
`401`, and nothing inside the agent says why — its MCP client just keeps
retrying. Tokens issued together also expire together, so one missed renewal
can cut several agents off at once.

## Detection

The watchdog checks the token registry on every tick when it is given a vault
(`execution watchdog --vault <vault>`, or `ARVYX_TOKEN_EXPIRY_VAULT` in its
environment):

- `attention` gains `tokens_expiring` while any live (unrevoked) token is
  expired or expires within `--token-expiry-days` (default 7);
- `tokens_expiring` in the report lists `agent_id`, `slot`, `expires_at`,
  `expired` — metadata only, never a hash or token;
- one thread per `(agent, slot, expires_at)` goes to `--token-expiry-target`
  (`ARVYX_TOKEN_EXPIRY_NOTIFY`). Renewing changes `expires_at`, so the next
  cycle warns again; closing a warning thread does not re-post it.

`operator` has no delivery route, so a warning sent there only shows on the
dashboard. Name an agent that can act on it.

A registry the watch cannot read is reported separately and never aborts the
tick: `attention` gains `token_expiry_check_failed` and the report carries
`token_expiry_error` with the exception class. Read that flag as "the watch is
blind", not as "nothing is expiring" — the two mean opposite things. The tick
itself still completes, so escalations, dead-letter replay and the stale-work
sweep keep running around a broken token registry.

A record whose expiry is unparseable **or carries no timezone** cannot be
compared with a clock; it is reported as `malformed: true` and treated as
expired rather than silently skipped. A record with no expiry at all never
expires and is not reported.

## Renewal

`arvyx auth renew <agent> --slot <slot> [--ttl-days N]` re-issues an existing,
unrevoked slot with **exactly its current scopes** — renewal never widens or
narrows access, and it refuses a revoked slot (issue a new one deliberately
instead). The old token stops working as soon as the new record replaces it.

`stdout` carries **only the token**; metadata goes to `stderr` as JSON. That
makes the renewal one pipe from the control-plane host to the agent's token
file, with the value never printed, logged, or held in a shell variable:

```sh
<run on the control plane> arvyx auth renew <agent> --slot <slot> \
  | <run on the agent host> sh -c 'umask 077; cat > "$TOKEN_FILE.new" \
        && test -s "$TOKEN_FILE.new" && mv "$TOKEN_FILE.new" "$TOKEN_FILE"'
```

**If that pipe breaks, the agent is already cut off and the new token is gone**
— only its hash was stored, so it cannot be recovered. The old token died the
moment the record was replaced, not when the new value reached the host. Recovery
is simply to run the renewal again and deliver the new value; do not go hunting
for the lost one. Treat "renewed, but the host never got it" as an ordinary
retry, and check the agent's calls before assuming the slot is healthy.

Check before relying on it:

1. `arvyx auth list` shows the slot with the new `expires_at`.
2. From the agent host, an MCP `tools/list` with the new token returns `200`
   and exactly the tools its scopes allow.
3. The agent's MCP client reconnects (most retry on their own; otherwise
   restart the agent's gateway).

Renew the agent **and** whatever else reads the same token file (a bridge, a
provider surface) — the renewal replaces the only valid token for that slot.

## Cleanup

An expired slot that nothing uses still raises `tokens_expiring`. Revoke it
(`arvyx auth revoke <agent> --slot <slot>`) rather than renewing it.
