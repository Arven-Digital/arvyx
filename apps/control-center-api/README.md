# Control Center API (read model)

A read-only read-model API for the control-center surfaces: Command Deck,
Work Board, Squad, Signal, Governance, and Delivery. It is a standalone,
stdlib-only Python service (package `arvyx_control_center_api`, source in
`src/`) that serves versioned, bounded JSON views over a vault and a
control-event log.

The operator API started by `arvyx serve-api` (which the rest of the docs
call the Control Center API) stays the authority for every write, for MCP, and for
the packaged dashboard. This service is not a second control plane and not
a copy of that API. Every view is built by calling the existing
`arvyx_control` projections: the same card/lane, agent-workload, safe-event,
activity, delivery-health, and fleet-verdict projection that
`arvyx serve-api` serves at `GET /control-plane`, plus the approval,
retention, replica, memory-queue, and audit-chain helpers behind
`GET /summary` and `GET /audit/events`. The views select, filter, and bound
that output. They never re-implement lifecycle rules and never write.

## Run

The package is installed with the repository (`pip install -e .` from the
repository root) and needs no extra dependency. A synthetic quickstart in a
scratch directory:

```bash
arvyx init /tmp/amc-cc/vault
arvyx task create "Review synthetic fleet" --owner demobot --state /tmp/amc-cc/events.jsonl
export TOKEN="$(arvyx auth issue vesper --scope control.read --vault /tmp/amc-cc/vault --json \
  | python -c 'import json, sys; print(json.load(sys.stdin)["token"])')"
python -m arvyx_control_center_api --vault /tmp/amc-cc/vault --state /tmp/amc-cc/events.jsonl &
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8766/v1/work-board
```

| Option | Meaning |
| --- | --- |
| `--vault` (required) | Vault root: registry, agent memory file counts, and token hashes. Read only. |
| `--state` (required) | The append-only control-event log (JSONL), the same file `arvyx serve-api --state` uses. A missing file is an empty log. Read only. |
| `--delivery-routes` | Authoritative agent-delivery route document. Without it the fleet verdict is red with `route_configuration_unavailable`, as in the operator API. |
| `--audit-log` | Hash-chained audit log to verify. Default: `audit-log.jsonl` next to `--state`. Read only. |
| `--host` | Bind address. Default `127.0.0.1`. |
| `--port` | Bind port. Default `8766` (the operator API defaults to `8765`). |
| `--auth-env` / `--auth-file` | Operator bearer secret, validated exactly like `arvyx serve-api` (one 32 to 4096 character printable ASCII token). A named but unset environment variable is an error. |

From a source checkout without installing, put both source roots on the
path: `PYTHONPATH=packages/arvctl/src:apps/control-center-api/src`.

## Authentication

Authentication fails closed and reuses `arvyx_control.auth.resolve_identity`,
the operator API's own mechanism:

- Send `Authorization: Bearer <token>`. The token is either the operator
  secret passed with `--auth-env`/`--auth-file`, or a per-agent token issued
  with `arvyx auth issue` (only its sha256 is stored, under
  `registry/tokens/` in the vault).
- Every data route requires the `control.read` scope. A missing, unknown,
  revoked, expired, or malformed credential gets `401` with a
  `WWW-Authenticate: Bearer` challenge; a valid identity without
  `control.read` gets `403`.
- There is no anonymous or demo bypass. If no credentials are configured at
  all, every data route answers `401`.
- Unknown paths are authenticated before they are reported as `404`.
- A `control.read` identity sees the global read model, exactly as it does on
  `GET /control-plane`.
- The server binds loopback by default and refuses a non-loopback bind unless
  an operator secret is configured. It speaks plain HTTP, so put a TLS proxy
  in front of any non-loopback bind.

## Routes

Only `GET` is served. Any other method, on any path, is answered with `405`
and `Allow: GET` before authentication and without parsing a request body.
`GET /v1/routes` returns this table in machine-readable form, including every
parameter's type, bounds, and default.

| Route | Auth | Query parameters | View |
| --- | --- | --- | --- |
| `/v1/health` | none | none | Liveness only. Reads no vault, event, or audit state. |
| `/v1/routes` | none | none | Machine-readable route index: auth, scope, parameters, limits. |
| `/v1/command-deck` | `control.read` | none | Fleet verdict and reasons, delivery attention, lane pressure, task/handoff/thread/approval counts by status, squad status mix, memory-queue totals, recent-activity total. |
| `/v1/work-board` | `control.read` | `lane` (queued, active, review, done, retired), `owner` (agent id), `kind` (task, handoff, thread), `limit` (per lane, default 50, max 200) | Kanban lanes of tasks, handoffs, and actionable threads, current work first. |
| `/v1/squad` | `control.read` | `agent` (agent id), `limit` (default 100, max 100) | Registry agents with runtime and machine labels, scopes, workload, blockers, continuation health, skills reporting (`reported: false` means not reported, never zero), and memory footprint counts. |
| `/v1/signal` | `control.read` | `limit` (default 50, max 100) | Newest-first safe event metadata and 12 hourly activity buckets (empty hours included). |
| `/v1/governance` | `control.read` | `limit` (approvals, default 20, max 100) | Approvals (metadata and effective status only), audit-chain integrity (`ok`, `broken`, `absent`, `unavailable`), retention manifest, replica role, memory-queue counts by project. |
| `/v1/delivery` | `control.read` | none | Outbox delivery health and the fail-closed fleet verdict with its execution and watchdog layers. |

Query parameters are validated strictly: an unknown, repeated, empty, or
out-of-range parameter is `400 invalid_query` rather than being ignored.

## Response envelope

Every data view returns:

```json
{
  "ok": true,
  "schema": "arvyx-control-center/v1",
  "view": "work-board",
  "generated_at": "2026-09-10T08:00:00Z",
  "source": {
    "event_count": 42,
    "first_timestamp": "2026-09-01T09:00:00Z",
    "last_timestamp": "2026-09-10T07:59:12Z",
    "freshness_seconds": 48,
    "retention": "append-only-jsonl"
  },
  "bounds": {},
  "data": {}
}
```

`generated_at` is when the snapshot was built; `source.freshness_seconds` is
the age of the newest event. `bounds` reports total, returned, limit, and
truncated counts for every bounded list, so omission is never silent. Errors
are `{"ok": false, "schema": ..., "error": <code>, "message": ...}` with the
codes `unauthorized`, `insufficient_scope`, `not_found`,
`method_not_allowed`, `invalid_query`, `projection_unavailable`,
`auth_unavailable`, and `internal_error`.

## Safety boundary

- No mutation routes exist. The package imports only read functions from
  `arvyx_control`; a test pins that import allowlist, and another asserts
  that the vault, event log, and audit log are byte-identical after every
  route has been exercised, refused writes included.
- Unlike the operator API, reads are not recorded in the audit log, because
  this service performs no writes of any kind. Use the operator API when a
  read must leave an audit record.
- Responses carry no memory content, thread or handoff bodies, review notes,
  approval commands or reasons, receipt payloads, token values, secret
  references, vault paths, or replica sync sources.
- Every string in every response passes through
  `arvyx_control.security.redact_secrets` and is capped at 512 characters, as
  defense in depth for legitimately exposed free text such as titles.
- A torn or malformed event log answers `503 projection_unavailable` instead
  of rendering an empty, healthy fleet. Details go to the server's stderr
  only.
- Only the standard library and `arvyx_control` are imported; the project
  keeps `dependencies = []`.

## Limitations

- Snapshots are built per request for bounded polling, like the operator
  dashboard. There is no push channel and no cache, so the event log is
  re-read on every request.
- The Work Board comes from the operator projection, which is itself capped
  at 200 cards (current work before done/retired history). Per-lane limits apply
  inside that cap; `bounds.projection.truncated` says when the cap was hit,
  and the Command Deck's done/retired history counts are then floors. Retirement is not completion.
- Views are computed from projection helpers that are module-private in
  `arvyx_control.api`. `views.py` imports them in one place, so a rename
  fails loudly in the test suite instead of letting the two surfaces drift.
- This HTTP surface is not yet part of the generated external contract in
  `docs/contracts/external-contracts.json`; `GET /v1/routes` is its
  machine-readable description for now.
- The operator dashboard (`packages/arvctl/src/arvyx_control/static/index.html`)
  still reads the operator API; it has not been switched to these routes.

## Tests

```bash
python -m unittest packages.arvctl.tests.test_control_center_api -v
```

The tests live in `packages/arvctl/tests/test_control_center_api.py`, so the
standard `python -m unittest discover packages/arvctl/tests` gate runs them.
They build a synthetic vault and event log with the suite's usual helpers
and cover fail-closed auth, `405` on every non-GET method, every route,
parity with `GET /control-plane`, payload bounds, strict query validation,
secret redaction, and the no-write guarantee.
