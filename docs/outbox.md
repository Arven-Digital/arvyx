# Durable Agent Delivery Outbox

The agent-delivery outbox turns authoritative control events into retryable delivery work without making a human operator act as a message relay.

## Authority and storage

- The append-only control JSONL log remains authoritative.
- SQLite `outbox` is a rebuildable projection only; it is never a second queue authority.
- Eligible forward and reverse source events are:

| Source event | Delivery target |
|---|---|
| `task.created` | `owner` |
| `handoff.created` | `to_agent` |
| `handoff.reviewed` | `from_agent` |
| `handoff.completed` | `from_agent` |
| `thread.created` | `target` |
| `thread.done` | original `actor` |

This makes both assignment and completion/review return paths automatic. `claim_due(..., deliver_after=...)` re-derives any missing intent from those source events while holding the existing control-state lock. A crash after the domain event but before `outbox.enqueued` therefore cannot lose the delivery.
- Dispatchers must configure a rollout watermark. It is a bootstrap floor only. After a successful batch, an append-only `outbox.materialization.checkpoint` records the last completely scanned source event under the same lock. Later ticks continue from that event ID, not from the static timestamp. Omitting `deliver_after` processes only explicitly enqueued items; it never surprise-delivers historical control events.

Execution-managed assignment deliveries are informational. Eligibility uses the same identity-bound actionable thread/handoff policy as the execution worker, including its narrow pre-provenance target-authorization fallback. The dispatcher emits `delivery_mode=notification` with `execution_managed=true`; its response contract prohibits starting work, ACK/accept, or DONE. Only the canonical execution wake supplies the exact execution and attempt IDs to validate through `control.execution_session_get` before work. The target records only a delivery receipt for the notice; that receipt grants no execution authority. Old queued direct assignments receive the same restriction at transport time without changing their durable ID or payload. Ordinary notifications, broadcasts, unbound coordination, and strict exact-dispatch admission retain their existing gates.

## Lifecycle events

```text
outbox.enqueued
outbox.attempt.started
outbox.attempt.failed
outbox.delivered
outbox.dead_lettered
outbox.replayed
outbox.receipt
outbox.cancelled
outbox.resolved
outbox.materialization.checkpoint
outbox.dispatcher.tick
```

Every item lifecycle transition event carries the complete projected item. Checkpoints carry only the scanned source event ID. Each completed non-dry-run dispatcher cycle appends `outbox.dispatcher.tick` with its health, materialization status, configured target names, and the loaded route-document attestation (`route_revision` and `route_sha256`, empty strings while the route document is unversioned; see the operators' delivery guide, private); endpoint URLs and credentials are never included. Projection follows append order, not timestamp sorting.

## Semantics

- Delivery is **at least once**.
- Identity is deterministic over `(subject_id, target, canonical_payload_hash, epoch)`.
- A finite lease prevents overlapping workers from claiming the same item.
- Worker finalizers `record_failure`, `defer_lease`, `mark_delivered`, and `mark_delivery_ambiguous` require `claim_attempts` from the original item returned by `claim_due`. The positive integer must match the current generation under the state lock. Re-reading a projection for the token would authorize a stale sender. The dispatcher forwards the original token on all four exits; a stale result appends nothing and reports lease loss. Late human-facing receipts also retain the original generation fence.
- An expired non-human lease is reclaimable after a worker crash. Human-facing session-return and decision-card leases are fenced as ambiguous instead of automatically resent.
- Transient failures use bounded exponential backoff and deterministic bounded jitter.
- Permanent failures dead-letter immediately.
- Transient failures dead-letter when `max_attempts` is reached.
- Failure details pass through secret-shape redaction before append.
- Delivered and dead-lettered states are terminal until an explicit replay.
- Replay appends a new item with an incremented epoch; history is never edited or deleted.
- Source events for targets listed in `ARVYX_AGENT_INTENTIONAL_HUMAN_TARGETS` are intentionally skipped, recorded with privacy-minimal category/count observability, and the materialization checkpoint advances without making health red. A target missing from both that list and the route allowlist is fail-closed: the checkpoint remains before that source event, each dispatcher tick stays unhealthy, and adding the route causes the same event to materialize automatically without rewind or source-event loss.

## Source-derived payload

The outbox stores only routing and authoritative lookup identifiers:

```json
{
  "schema": "v2.agent-delivery/1",
  "source_event_id": "event_...",
  "source_event_type": "handoff.created",
  "subject_id": "handoff_..."
}
```

It does not duplicate thread bodies, task content, credentials, endpoint URLs, Authorization headers, or exception traces. The target agent must fetch the authoritative object by ID after wake-up.

## Worker boundary

The worker must:

1. Validate routing and credential references before claiming.
2. Claim under the control-state lock.
3. Perform network I/O after releasing the lock.
4. Use the stable outbox ID as the transport idempotency key.
5. Mark `delivered` only after the target durable inbox or gateway returns its acceptance receipt.
6. Record sanitized transient/permanent failure classification.
7. Treat gateway acceptance separately from `seen`, `acknowledged`, and `completed` business receipts.

## Agent lifecycle receipts

Transport acceptance and business progress are separate. After the dispatcher records `outbox.delivered`, the target identity writes monotonic receipts:

```text
seen → accepted → completed | failed
```

Receipts are append-only `outbox.receipt` events. Duplicate status writes are idempotent; regressions and terminal rewrites are rejected. Only the identity whose `agent_id` equals the delivery target may write a receipt. Operator/global callers cannot impersonate an agent receipt.

Agent-facing surfaces:

```text
GET  /deliveries
POST /deliveries/<delivery_id>/receipt
control.delivery_list
control.delivery_receipt
```

HTTP and MCP reads are identity-scoped to the caller's own target. Both surfaces require the dedicated `control.delivery` scope; that scope grants neither `control.approval_approve` nor any general `control.write` tool. `control.delivery_receipt` requires an authenticated bound actor even if an `actor` argument is supplied. Agents never receive claim, retry, dead-letter, replay, or transport-finalization tools.

## Operator cancellation of unroutable work

After at least one dispatcher tick has recorded the current route allowlist, an authenticated operator may remove legacy active work whose target is not routable:

```text
POST /deliveries/<delivery_id>/cancel
{"reason_category":"unroutable_target"}
```

Only `pending` or `leased` items whose target is absent from both the current authoritative route file and a fresh dispatcher snapshot can be cancelled. Missing/invalid route configuration and stale/uninitialized dispatcher state fail closed, and so does a declared-vs-loaded divergence: when the fresh tick attests a `route_sha256`, it must equal the hash of the route document the API loads. The body accepts only the fixed reason category; free-form details are rejected so they cannot leak into the log. Repeating the same request is idempotent and appends only one `outbox.cancelled` event. Agent delivery identities cannot use this endpoint, and routable, delivered, dead-lettered, or otherwise terminal items are rejected.

Cancellation is irreversible for that outbox item: cancelled work cannot be replayed, and later adding a route does not revive it. Recovery requires restoring a valid route first and then creating a new authoritative source event (for example, a new assignment or handoff) so normal materialization creates new delivery work. The append-only cancellation remains in history.

## Operator resolution of dead letters

A dead letter can never be cancelled - its failure evidence is history - but
leaving it permanently "unresolved" forces the health surface to demand action
for work that no longer needs any. An authenticated operator classifies it
instead:

```text
POST /deliveries/<delivery_id>/resolve
{"resolution_category":"obsolete","detail":"optional secret-safe note"}
```

Categories: `obsolete` (the subject no longer matters), `superseded` (a newer
delivery or subject replaced it), `terminal_elsewhere` (the underlying subject
reached an authoritative terminal state through another route). The record
keeps its `dead_lettered` status and full evidence; the resolution is one
append-only `outbox.resolved` event. Resolving with the same category is
idempotent; a different category is refused so reclassification surfaces as an
explicit conflict instead of a silent rewrite.

Delivery health counts a dead letter as unresolved only while it has neither
an exact replay (`epoch+1` sibling) nor a resolution. `GET
/deliveries/dead-letter` reports each record's `resolution_category`,
`resolved_by`, `resolved_at`, `resolution_detail`, plus `replayable` and
`replay_blocked_reason` derived from the current authoritative route map, so
the operator sees eligibility without probing with a POST.

The full classify-then-replay procedure lives in
`docs/runbooks/dead-letter-recovery.md`.

Some dead letters are classified in the same append-only `outbox.dead_lettered`
event that records them, because authoritative state already proves nothing is
left to act on and a replay could only fail the same way:

- a session return refused at the dispatch gate because its fenced attempt is
  gone is dead-lettered as `superseded` (or `terminal_elsewhere` when the
  subject already has an authoritative terminal), `resolved_by=dispatcher`;
- an execution wake record whose send was rejected or never finalized is
  dead-lettered as `superseded`, `resolved_by=execution-worker`.

A session return whose target does not own the execution, or whose execution
is unknown, is never auto-classified: it stays an unresolved, operator-visible
dead letter. Replay refuses session returns whose attempt is no longer live and
execution wake records outright.

The wake prompt must follow this sequence:

1. `control.delivery_receipt {status: "seen"}` after parsing the wake.
2. Fetch the authoritative source object through scoped control tools.
3. `accepted` only after taking ownership.
4. `completed` with a sanitized result reference, or `failed` with a sanitized blocker.

## Execution wake records

The execution worker sends its fenced-attempt wakes itself, but every wake it
sends has a real delivery record in this projection, appended as
`outbox.enqueued` (status `leased`, `delivery_mode=execution`, target = the
execution owner) **before** any network I/O, under the execution fence, and
finalized to `delivered` or a classified dead letter afterwards. The delivery
ID a wake names (`execution_delivery_<hash of execution_id and attempt_id>`)
therefore always resolves through `control.delivery_get` for its target. The
dispatcher never claims, retries, or replays these records: redelivery belongs
to the execution lineage (new fenced attempt, lease, backoff, HOLD). A record a
crashed worker left `leased` is settled from the execution lineage on the next
dispatcher tick, never redelivered: an identity-bound target heartbeat on the
record's exact fenced attempt proves the wake arrived, so the record becomes
`delivered`; while that attempt is still the execution's live leased attempt
the record is left alone; only once its lease has expired and its attempt is
no longer live is it dead-lettered as `superseded`. The watchdog's
receipt-less detection skips them; the execution's own heartbeat and terminal
are their receipt.

## Bounded dispatcher

Run one tick with the package module:

```bash
python -m arvyx_control.dispatcher --vault /srv/arvyx-v2/data/vault \
  --state /srv/arvyx-v2/data/state/control-events.jsonl \
  --routes /etc/arvyx-v2/routes.d/agent-delivery-routes.json \
  --deliver-after "$ARVYX_AGENT_DELIVER_AFTER" \
  --intentional-human-targets "$ARVYX_AGENT_INTENTIONAL_HUMAN_TARGETS" \
  --limit 5 \
  --per-target-limit 2 \
  --materialization-limit 100 \
  --max-watermark-age-seconds 86400 \
  --lease-seconds 120 \
  --max-attempts 8
```

The route JSON stores only runtime type and environment-variable names. Inline endpoint/credential keys are rejected. Credential-bearing delivery requires HTTPS; plain HTTP is accepted only for literal loopback IPs. Redirects and environment proxies are disabled so credentials cannot move to another host. All configured routes must validate before any item is claimed.

`attempts` counts leases/transport starts. `failures` counts recorded delivery failures plus expired-lease reclaims and is the bounded dead-letter budget. `--per-target-limit` prevents one target from monopolizing a tick. `--materialization-limit` bounds source-derived appends per tick. The enqueue batch is flushed first and its checkpoint is then appended while the same global lock is held: a crash between them safely re-scans and deduplicates the batch, while concurrent source writers cannot be skipped. `--max-watermark-age-seconds` applies only before the first checkpoint. An expired bootstrap blocks new source materialization and produces a nonzero/actionable result, but never blocks delivery, retry, or reclaim of work already in the outbox. Once initialized, the checkpoint keeps advancing regardless of the static bootstrap timestamp's age. The dispatcher reports `materialized` and `materialization_remaining` alongside cap deferrals, quarantined malformed projections, lost leases, and work deferred by the lease deadline.

The CLI prints one JSON result and uses a stable service contract: exit `0` for a healthy tick, `1` for an operationally unhealthy tick (including stale uninitialized bootstrap, retries, quarantine, lost leases, or dead letters), and `2` for invocation/config-file errors. The systemd template sends stdout/stderr to journald under `arvyx-agent-delivery`, so `systemctl status arvyx-agent-delivery.service` and `journalctl -u arvyx-agent-delivery.service` expose the actionable JSON failure. The operator-authenticated `GET /deliveries/health` response includes the latest checkpoint source event and `advanced_at` timestamp; this liveness detail is not exposed on the public `/health` route or to agent delivery tokens.

Before enabling the timer, run the same command once with `--dry-run`. It validates the watermark/routes and reports the bounded materialization batch without appending an enqueue, checkpoint, or claim event and without making network calls. Remove `--dry-run` only after reviewing the JSON report. The bootstrap timestamp may age after initialization because subsequent scans are anchored by the durable checkpoint.

Packaging templates:

- `config/agent-delivery-routes.example.json` (shipped)
- a systemd oneshot service plus timer running `python -m arvyx_control.dispatcher`
  with the route file and vault above (the maintainers' deployment kit names them
  `arvyx-agent-delivery.service` and `.timer`; they are not shipped in this repository)

Before installing the production units, create `/etc/arvyx-v2/routes.d` as a root-owned non-secret configuration directory and stage `agent-delivery-routes.json` there with an atomic replace. The API mounts only this directory read-only; keep `control.env` and `agent-delivery.env` outside it.

These templates are inactive artifacts. Installation, environment provisioning, timer enablement, and gateway restarts remain approval-gated.

## Rollout safety

Before first activation, set the watermark to the approved deployment event/timestamp. Test in this order:

1. synthetic fixture,
2. operator-created task assigned to a canary agent,
3. agent-to-agent handoff,
4. remaining configured-agent canaries,
5. 24-hour retry/duplicate/dead-letter observation.

Production activation, gateway configuration, service restart, credential provisioning, and agent scope changes remain approval-gated.

## Receipt-continuation recovery fence

Under the existing state lock, recovery additionally compares the delivered
original's payload hash, execution ID, current attempt ID and target before
constructing any wake. It skips archived execution IDs and canonical execution
subjects as well as archived return-request IDs. A receipt from an older attempt
does not authorize waking its replacement. Lease expiry alone is intentionally
not a refusal: recovery must still work after the original runtime exits.
These are source changes with unexecuted regression sources, not acceptance or
provider-delivery evidence.
