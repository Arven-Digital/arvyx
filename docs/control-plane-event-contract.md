# Control Plane Read Model & Realtime Contract

## Authority boundary

`GET /control-plane` is a read-only, operator-scoped projection. It does not become a new source of truth. Every card, metric, chart point, and agent load value must be reproducible from the append-only control event log or governed vault/registry files.

The API enforces both `control.read` and an authenticated operator identity before
building the fleet projection. An agent token with `control.read`, or anonymous
demo scope alone, does not grant this cross-agent view. This is the same explicit
operator boundary used for the global `/summary`; clients must supply their
existing operator credential rather than minting or discovering one. Contract
metadata records `operator_only: true`; static source agreement is not runtime
qualification.

## Refresh model

Version 1 uses bounded polling rather than pretending to have push telemetry:

- active tab: refresh every 10 seconds;
- hidden tab: polling paused;
- manual refresh: immediate request;
- request overlap: forbidden (one in-flight refresh);
- stale threshold: 30 seconds after the last successful response;
- reconnect: exponential delay capped at 60 seconds after failures;
- freshness timestamp is always visible.

A future SSE/WebSocket route may replace polling only if it preserves the same response semantics, auth boundary, and append-only source.

## Response envelope

```json
{
  "ok": true,
  "schema": "arvyx-control-plane/v1",
  "generated_at": "RFC3339 UTC",
  "source": {
    "event_count": 0,
    "events": 0,
    "first_timestamp": null,
    "last_timestamp": null
  },
  "cards": [],
  "kanban": {
    "queued": [],
    "active": [],
    "review": [],
    "done": []
  },
  "agents": [],
  "activity": {
    "buckets": [],
    "event_types": []
  },
  "events": [],
  "delivery": {}
}
```

`source.events` is a compatibility alias for `source.event_count`; both carry the same integer. `cards` is the bounded normalized collection from which the four `kanban` lanes are projected. `source.bounds` reports total/returned/truncated counts for cards, agents, and safe events plus invalid registry records, so omission is never silent. Version 1 limits cards to 200, registry agents to 100, and safe events to 100.

`retain_events` is a read-only preview parameter: it changes only the projected retention label returned by `/summary`; it never prunes or mutates the append-only source log.

## Kanban card contract

Every card carries:

- `id`: canonical subject id;
- `kind`: `task`, `handoff`, or `thread`;
- `title`: bounded source title;
- `owner`: canonical current owner/target;
- `actor`: creator/originator where available;
- `source_status`: exact domain status;
- `lane`: visual projection only;
- `severity`: when the source has it;
- `created_at`, `updated_at`;
- `evidence`: completion artifact/anchor/method when declared.

Mapping:

| Source            | Source state | Visual lane |
| ----------------- | ------------ | ----------- |
| task              | open         | queued      |
| task              | done         | done        |
| handoff           | open         | queued      |
| handoff           | accepted     | active      |
| handoff           | reviewed     | review      |
| handoff           | completed    | done        |
| actionable thread | open         | queued      |
| actionable thread | acked        | active      |
| thread            | done         | done        |

All threads returned by the canonical inbox projection appear in the Kanban as bounded cards; their source `type`, `status`, and pending semantics remain authoritative.

The UI may animate a card between lanes after a refreshed projection. Dragging cannot mutate state in v1. Lifecycle changes use explicit, auditable controls and existing idempotent API routes.

## Agent contract

Agent identity comes from `registry/agents/*.json`. Runtime and machine display metadata join through registry ids. The response never exposes token values, secret references, private paths, hostnames, prompts, or memory content.

Per-agent fields:

- identity: `id`, `display_name`, runtime/machine display labels, scopes;
- workload: queued/active/review/done/total card counts;
- memory footprint: document, line, byte, curated/raw/session document counts;
- skills: `{reported, count, items}`;
- latest activity timestamp.

`skills.reported=false` means telemetry is absent. It must never render as "0 skills". Skills may be reported through an explicit `skills` list in the canonical agent registry record in this schema version.

## Memory metric contract

Metrics inspect only file metadata and counts beneath `agents/<agent-id>/`:

- `.md` document count;
- newline/line count;
- byte count;
- `MEMORY.md` curated count;
- `SESSION-STATE.md` session count;
- documents beneath `raw/` as raw count.

No file content, title, excerpt, path, or sensitive text is returned.

## Event/activity contract

The event stream is newest-first and bounded. It exposes only safe event metadata: id, type, subject id, timestamp, actor/target/title when already present as control metadata. Bodies, messages, review notes, receipt details, commands, and memory content are excluded.

Activity buckets are deterministic UTC time buckets derived from event timestamps. Empty buckets are included so chart geometry represents silence honestly.

## Delivery health

Delivery health reuses the existing outbox projection and reports aggregate counts, unresolved dead letters, dispatcher/checkpoint posture, and backlog age. The UI must not expose failure payloads or secret-bearing receipt details.

## Privacy and public boundary

This contract belongs to the private operator repository/runtime. Public demos use a deterministic synthetic vault and synthetic event log. Production screenshots and raw response payloads are not public release artifacts.

`--allow-unauthenticated-demo` is loopback-only at the server boundary. A non-loopback bind without authentication is rejected, and demo bypass remains rejected on non-loopback even when a bearer secret is also configured. Demo mode must never be started against the private production vault.
