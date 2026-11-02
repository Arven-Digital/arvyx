# Operator Surface

This repository is the combined operator surface for the
memory and control plane. Operators should start here before reaching for older
component repositories.

## Authority

- `arvyx` is the operator-facing distribution surface.
- Historical split repositories can remain useful as source references, but
  day-to-day preview, testing, dashboard, and MCP bridge work belongs here.
- Machine-specific clone paths belong in the private memory registry, not in
  this public-safe repo.
- Do not import production vaults, real prompts, private chat logs, raw audit
  logs, hostnames, tokens, secret pointers with private service names, or
  personal context into this repository.

## Local Loop

Run the complete local release gate:

```bash
make ci
```

Serve the operator dashboard locally:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli serve-api \
  --host 127.0.0.1 \
  --port 8765 \
  --delivery-routes config/agent-delivery-routes.example.json \
  --mcp-profile operator
```

Open:

```text
http://127.0.0.1:8765/dashboard
```

The operator dashboard reads:

- `GET /control-plane` for API readiness plus the bounded fleet read model: normalized Kanban lanes,
  registry-backed agent identity, optional skill reporting, memory footprint counts,
  recent safe event metadata, activity buckets, and delivery health. Selecting a
  Squad Orbit node filters the board, event stream, memory, and skill surfaces.
- `GET /summary` for control counts, recent state, MCP profile, store retention
  posture, approvals, and provider/session/fallback/hardening posture panels.
- `GET /audit/events` for an authenticated four-state audit-chain integrity check (`OK`, `BROKEN`, `UNKNOWN` authorization required, or `UNAVAILABLE`).
- `GET /digest` for a start-of-session / weekly brief (`?agent=` to scope it,
  `?window_hours=168` for a weekly review): session state, open work, what
  needs attention, and a short focus.
- `POST /memory/recall` for cited recall.
- task, approval, handoff, handoff review, and bus API routes for synthetic
  control actions.
- thread inbox routes (`GET /threads`, `GET /threads/pending`,
  `POST /threads`, `POST /threads/:id/ack`, `POST /threads/:id/done`,
  `POST /threads/read-all`) for War Room-style coordination. `/summary`
  carries thread counts (pending/unread/by-status) and recent threads for the
  dashboard's War Room panel.

All list panels render through `textContent`/`createElement` (no HTML parsing
sink), so agent-supplied strings — bus messages, handoff titles, event titles,
skill names, registry labels, and audit identities — cannot execute in the
operator's browser.

## Dynamic Control Plane behavior

The dashboard is a dependency-free observatory rather than a generic admin
page. Its live surfaces are:

- **Command Deck:** registry, active-work, queue, requested-approval, and
  delivery metrics with bars derived from the current response.
- **Squad Orbit:** keyboard-selectable agent nodes with runtime, machine, scope,
  latest-activity, and work-pressure detail. Selection is a client-side filter;
  it never changes authoritative state.
- **Work Board:** horizontally scrollable Queued, Active, Review, and Done lanes.
  At mobile widths this is the only intentionally horizontal region; the page
  itself remains within the viewport.
- **Signal Room:** an SVG activity trace, lifecycle mix bars, bounded event pulse
  stream, and delivery projection. Graph geometry is calculated only from API
  values; there are no decorative or synthetic series.
- **Memory Atlas and Skills:** per-agent file/line/byte and document-class counts,
  without memory content. Missing optional skill telemetry is rendered as **Not
  reported**, never as zero.
- **Governance Rail:** requested approvals plus audit, retention, and replica
  posture from the existing summary projection.

Read data polls at a bounded ten-second interval. The dashboard prevents
concurrent refreshes, pauses polling while the document is hidden, refreshes on
return, marks a snapshot stale after thirty seconds, and preserves the last good
snapshot on transient failure. HTTP 401/403 receives a distinct authorization
state. The manual refresh control remains available in all states.

All existing synthetic mutation controls remain available in the operator
controls drawer: task/approval/handoff/bus creation, sequential bulk handoff
lifecycle operations, recall, bearer entry, and local queue preferences. The
bearer is kept only in browser session storage; non-secret preferences use local
storage. The drawer closes with Escape, traps Tab focus while open, returns focus
to its opener, and exposes semantic labeled controls.

Motion is limited to data causality (changed metric widths, chart trace reveal,
new cards, node liveness, and drawer movement). `prefers-reduced-motion: reduce`
removes animation and spatial transition duration without removing state or
controls. The 390px layout uses 44px primary targets, stacked detail surfaces,
and snap-aligned Kanban lanes for operator triage.

Recent handoff rows expose selection controls when the current status allows a
lifecycle transition. The operator then runs explicit bulk accept, review, or
complete actions from the drawer. Review actions use the dashboard reviewer,
decision, and notes controls and append a `handoff.reviewed` event instead of
mutating previous log entries.

The dashboard can select all visible actionable handoffs and run bulk accept,
review, or complete flows. Bulk actions are intentionally implemented as
sequential calls to the existing append-only lifecycle endpoints.

The five queue controls are persisted as non-secret browser preferences and sent
as `/summary` query parameters whenever they change.

Queue filters and review controls are persisted only in browser local storage
under `arvyx_dashboard_preferences`; reset them with the dashboard's local reset
control. These preferences are intentionally not written to the public-safe repo
or append-only control log.

`GET /summary` accepts `handoff_status` to filter the recent handoff list,
`handoff_to_agent` to focus a queue by assignee, `handoff_limit` to choose the
visible queue size, `handoff_sla_hours` to annotate visible handoffs with age
and SLA status, and `retain_events` to preview a bounded projected-store event
window without changing the append-only JSONL source log.

When bearer auth is enabled, `/` and `/dashboard` stay loadable, while
`/summary`, recall, MCP, and control routes require the bearer header.

## War Room and Health Ops

The thread inbox is the coordination surface: an `ask`, `handoff`, or
`blocker` thread stays pending until it is marked done (acknowledging keeps it
pending); `update`/`status` threads are informational and are what `read-all`
clears by default. Identity-bound agent tokens are scoped to their own inbox —
reads default to the caller, a foreign target is rejected (HTTP 403 / MCP
policy error), and ack/done only work on threads targeting the caller. The
operator identity and the local demo context see and mutate everything, which
is what keeps the dashboard's global War Room panel working.

Daily health handoffs create the day's ask threads from a config-driven role
list (explicit `--config` required; dedupe per date and role). This example
uses synthetic identities, not a production fleet roster:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli --authority-vault fixtures/synthetic-vault health daily-handoff --config examples/local-dev/daily-handoff.example.json --json
```

The agent readiness matrix probes a config-defined topology into
OK/WARN/FAIL/SKIP (the topology lives entirely in the config file; a
loopback-only example ships in `examples/local-dev/agents.json`):

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli --authority-vault fixtures/synthetic-vault health agent-matrix \
  --config examples/local-dev/agents.json --json
```

`health notify-check` turns pending actionable threads into deduped
notification and one-shot escalation candidates and hands them to one
notifier adapter (stdout by default). See [notifiers.md](notifiers.md) for
the adapter safety model.

## Retired default-author compatibility

New task owners/creators, approval requesters, handoff sources/targets, bus
actors, thread actors/targets, and reply authors must not be the retired
`atlas` identity (case-insensitive, after whitespace trimming). Validation is
at the domain producer before append, not deferred to delivery routing. This
is a narrow retirement rule, not a fixed fleet allowlist. Bound HTTP/MCP agent
identities retain their existing precedence; human operator identities and
future agent names are not removed. Historical records are not rewritten;
completion events may still copy an old author. Synthetic examples use the
registered `demobot` fixture identity and must never be installed as live routes.

Only an inferred `thread.done` notification to historical author `atlas` is
excluded from materialization. This is a permanent identity retirement rule,
not a one-time list of source IDs. Existing explicit Atlas assignments and
other unknown targets still remain visible routing failures; this change does
not archive them, synthesize completion, or clear held executions.

The append-only skip record retains the existing `unconfigured_route` category:
Atlas has no supported agent route. It includes `reason: obsolete_author` and
exact `source_event_ids`; it is **not** categorized as `intentional_human`.
Strict old readers can project the category/counts and ignore extra metadata.
Their historical unconfigured-route totals include these retired notifications;
only the current tick's routing failures indicate live blockage. The dispatcher
advances its checkpoint for these retired notifications once, provided no
unconfigured predecessor pins it. Unknown enum values still fail closed.

### Bounded deployment and rollback checklist

- Before deployment, inspect all external daily-handoff cron/watchdog callers:
  each must supply an operator-approved live roles config. The repository
  example is synthetic, not a live replacement. Inventory MCP callers that
  previously relied on omitted author/owner/requester arguments; update them
  to explicit authorized identities or verify their identity binding.
- Verify the candidate patch hash and tests; snapshot the append-only log,
  its checkpoint, current held execution IDs, and the existing live route map.
  No route, token, credential, or roster creation is part of this repair.
- Before any tick, reject deployment if an earlier experimental build already
  persisted `category: obsolete_author`. That incompatible record requires a
  separately reviewed recovery plan; do not ignore unknown enums, rewrite the
  log, or deploy an old strict reader over it.
- Canary the four operator-approved live identities in an isolated state;
  verify rejected explicit Atlas inputs append no domain events. Then verify
  the first authorized live tick has exact skip source IDs, no Atlas delivery,
  no synthetic completion, and unchanged held executions. No bulk replay.
- Rollback is wire-compatible for the skip records emitted by this build.
  Preserve the advanced checkpoint and full log: rolling it back/replaying
  old history can reintroduce stale Atlas notification blockage. An old binary
  also restores unsafe author defaults and lacks the new-write retirement
  fence, so disable ingress/cron producers before binary rollback and keep them
  disabled until the fence is restored. Never truncate or edit authority events
  to recover. Any checkpoint recovery requires exact-source operator review.

## Fleet verdict

`/control-plane` carries a `fleet` block and `GET /fleet/health` returns it
standalone: a fail-closed headline verdict (`green` / `amber` / `red`) with
explicit reason lists. It folds together delivery health, the durable
execution queue (`acked_without_live_execution`, dead-lettered, held, stale
heartbeats), the latest watchdog tick, route-configuration availability, and
continuation staleness. Any actionable red layer makes the whole verdict red;
softer signals (uninitialized watchdog, watchdog attention findings, stale
continuations) degrade it to amber; green means every layer affirmatively
reported clean.

The rule the verdict enforces: an empty pending inbox and an empty outbox are
**not** proof of health. "No work in flight" and "healthy" stay
distinguishable, so a fleet that has silently stopped executing renders red,
not idle-green. The dashboard's headline dot and the Fleet verdict tile bind
to this verdict; transport reachability alone never renders green.

## MCP Profiles

The HTTP `/mcp` route defaults to `read-only`, exposing memory recall and exact
source expansion. Use `--mcp-profile operator` only for trusted local operator
runtimes that may create tasks, approvals, handoffs, handoff reviews, or bus messages.

Generate safe-mcp-bridge policy examples with:

```bash
PYTHONPATH=packages/arvctl/src python3 -m arvyx_control.cli bridge-policy \
  --profile operator \
  --output /tmp/arvyx-operator-bridge.json \
  --json
```

## Private Registry Mapping

The private memory registry may map multiple project slugs to this combined
checkout. That mapping is deployment state, not release content. Keep it out
of screenshots, examples, fixtures, and committed docs.

## Release Discipline

Private dogfood may proceed from this repository while public release remains
blocked. Before anything public:

- run `make ci`
- export evidence with `arvyx evidence export`
- run the private-context scan
- complete multi-model security review and synthesis
- update `docs/release-gate.md` explicitly
