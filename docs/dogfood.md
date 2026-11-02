# Dogfood Notes

## 2026-09-10 - Release-host bridge and Docker runtime evidence

Refreshed evidence for the two release-host checks that the release gate
references. Both ran on a macOS arm64 developer workstation acting as the
release host, with Docker provided by a Colima Linux VM (Docker Engine 29.5,
Compose 5.5), first against `main` at `fa41540` and again inside `arvyx release-candidate --run-docker --run-bridge --json` on `2fa945c`, with the same results.

Commands:

```bash
arvyx release-host --run-bridge --json
arvyx release-host --run-docker --json
```

Observed:

- `safe_mcp_bridge_e2e`: `complete`. Visible tools through the bridge were
  exactly `memory.recall`, `memory.excerpt`, and `memory.context_pack`; audit
  events were `tools_list_filtered`, `request_forwarded`, and `tool_blocked`;
  `credential_leaked=false`.
- `docker_runtime`: `complete` in `compose-authenticated-server` mode. Auth
  probes returned `401`, `401`, `200` (missing token, wrong token, correct
  token); an empty secret was rejected; the service bound loopback only; the
  container ran as `10001:10001` with a read-only root filesystem,
  `cap_drop: ALL`, `no-new-privileges`, a 512 MiB memory limit, 1 CPU, and a
  128 PID limit; secrets were file-only; a mutation succeeded and persisted
  across a restart. The previous-release rollback probe was not exercised
  (`previous_release_rollback=false`).
- The first Docker attempt failed honestly as `blocked` because the Compose
  plugin was missing (`docker: unknown command: docker compose`); it passed
  after the plugin was installed. The gate reported the missing capability
  instead of a clean result, as designed.

What this proves:

- The live bridge contract and the hardened container posture both hold on a
  real Docker runtime, not only on the CI-safe fixture transcript.

What this does not prove:

- That these results carry over to a later tree. Re-run both commands on the
  exact frozen release candidate; `arvyx release-candidate --json` is the only
  verdict.
- Real external stdio MCP client evidence (`mcp_client_real`), which needs a
  signed, commit-bound file from a pinned signer.
- Linux release-host parity beyond the Colima VM, OAuth or rotating tokens,
  streaming MCP transports, or production deployment posture.

## 2026-07-01 - safe-mcp-bridge Against Arvyx HTTP MCP

This alpha validation run tested `safe-mcp-bridge` against the packaged Arvyx
Control Center API server.

The repeatable local smoke is:

```bash
SAFE_MCP_BRIDGE_BIN=/path/to/safe-mcp-bridge make bridge-dogfood-smoke
```

If `safe-mcp-bridge` is already on `PATH`, the environment override is not
needed.

The CI-safe evidence check is:

```bash
make bridge-e2e-smoke
```

That target validates `fixtures/safe-mcp-bridge/read-only-e2e.json`, a
public-safe transcript of the same bridge contract. It proves the expected
tool filtering, forwarded recall, blocked control write, audit events, and
credential redaction shape without requiring the external bridge binary to be
installed in CI.

Setup:

- Started `arvyx serve-api` on a local throwaway port.
- Enabled bearer auth with a synthetic environment token.
- Pointed safe-mcp-bridge at the raw HTTP MCP endpoint: `/mcp`.
- Used an allowlist policy containing only memory tools.

Observed:

- Upstream `tools/list` returned 15 tools.
- Bridge-filtered `tools/list` exposed 3 tools:
  - `memory.recall`
  - `memory.excerpt`
  - `memory.context_pack`
- `memory.recall` succeeded through the bridge and returned cited memory cards.
- `control.bus_post` was blocked locally with JSON-RPC error `-32001`.
- Audit events included `tools_list_filtered`, `request_forwarded`, and
  `tool_blocked`.
- The synthetic bearer token did not appear in stdout, stderr, or audit output.

What this proves:

- The Arvyx API server can act as an HTTP MCP upstream.
- safe-mcp-bridge can narrow the Arvyx tool surface for read-only agent clients.
- The bridge blocks control-plane writes before they reach the upstream.
- The smoke can be rerun without copying private machine paths into the repo.

What this does not prove:

- External security review.
- OAuth or rotating-token flows.
- Streaming MCP transports.
- Fresh execution of the external safe-mcp-bridge binary in CI.
- Production deployment posture.
