# Durable inter-agent execution runbook

Authority prerequisite: set `ARVYX_VAULT` to the actual configured absolute vault path before using these commands (for the maintained V2 host units, `/srv/arvyx-v2/data/vault`). Do not derive it from `--state`; state may be outside the vault. An empty variable is not a valid configuration. Global `--authority-vault` precedes the CLI subcommand; the standalone dispatcher uses `--vault`.


This slice is a control-plane-owned execution queue. Runtime adapters may activate Hermes's real persistent `/goal` command or an OpenClaw hook, but the control-plane lease, retry, and authoritative terminal reconciliation remain the durable source of truth.

## Exact operator retirement (not completion)

Two bounded transitions share `arvyx_control.retirement` validators. No batch,
implicit lookup, replay, receipt, notification, continuation, or materialization
is performed. Production application requires separate approval of exact IDs
and current evidence; an audit inventory is not an executable approval.

- `POST /threads/<exact-id>/retire` (scope `control.write`) supports only
  `category=obsolete_watchdog_alert`: an **open operator-targeted blocker**
  created by the canonical unbound `arvyx-watchdog`, with the exact generated
  title/body and preceding HOLD for the named execution. That execution must
  currently be closed/completed at the supplied terminal event. Unknown
  lineage, continuation links, or any execution owned by the alert reject.
  It appends `thread.retired`, preserving messages and completion fields;
  pending becomes false and the API board exposes a separate `retired` history
  lane. It does not claim the underlying subject was completed.
- `POST /deliveries/<exact-id>/retire` (scope `control.delivery`) supports only
  `category=obsolete_subject`: epoch-zero pending **unleased legacy actionable
  thread-created** transport whose exact source is already target-authored done.
  It uses `outbox.cancelled` with distinct resolution metadata, preserving
  payload/hash, counters, failure detail and receipts. Notifications, explicit
  delivery modes, execution wakes, session returns, continuations, leased
  (even expired), delivered, dead-lettered and ambiguous records reject.
  Every historical attempt must be accounted for: pre-I/O deadline deferral or
  the adapter's exact missing delivery URL/credential environment error is
  supported; timeouts, HTTP outcomes, receipt evidence, replay and unknown
  failure histories are not. A pending snapshot alone never proves unsent.

Both endpoints require the authenticated **operator** identity, not an agent
with broad scopes and not anonymous demo access. Actor fields in the body are
rejected. Validation, expected-revision checking, and append happen under one
state lock shared with claims. Invalid operations leave the control log
unchanged. Exact identical domain retries return the existing retirement;
changed reason/category/bindings reject. The HTTP audit journal still has its
normal request-key semantics (a completed HTTP key may return its usual 409;
use a fresh audit key to revalidate the identical domain action).

The body is one exact request object (plus optional boolean `dry_run` and the
normal API `idempotency_key`), never the read-only audit manifest:

- Both: `expected_event_id` (latest event for the record), `source_event_id`,
  `target`, `terminal_event_id`, `category`, nonempty `reason` (max 1024 chars).
- Thread: also `execution_id`, `execution_subject_id`, `execution_target`.
- Delivery: also `subject_id`, `payload_hash`, integer `epoch` (exactly zero).

Local CLI uses the existing OS/state-file operator trust boundary, with no
caller-supplied actor or remote auth bypass. Its manifest is exactly one JSON
request object with the fields above, excluding HTTP-only fields:

```sh
arvyx --authority-vault "$ARVYX_VAULT" thread retire <exact-thread-id> --state <local-state> --manifest <request.json> --dry-run --json
arvyx --authority-vault "$ARVYX_VAULT" delivery retire <exact-outbox-id> --state <local-state> --manifest <request.json> --dry-run --json
```

Dry-run is the default; an approved local write requires `--apply` instead.
`--apply --dry-run` conflicts. CLI and HTTP use the same validators; neither
converts broad audit categories into automatic actions. Handoffs, held
executions/approvals, agent continuations, unknown work and historical dead
letters are outside these transitions.

Rollback is reader-only: old readers ignore `thread.retired` and may resurface
alerts, but understand `outbox.cancelled`, so retired transport stays inert.
Keep the log and retirement evidence; do not append fake DONE to accommodate
an old reader. Upgrading the reader restores the distinct retirement history.
SQLite stores retirement metadata in additive `retirement_json` columns;
checkpoint readers reject old incompatible seeds and fall back to the log.

## Safety contract

- An execution root is created directly from an authenticated identity-bound actionable `thread.created` (`ask`, `handoff`, or `blocker`) or `handoff.created` assignment for a concrete target present in the validated route map. Assignment is execution authority; a later model-authored ACK/accept is normally a coordination receipt, not a new execution trigger. Operator/global and unbound assignment events remain coordination-only except for the narrowly supported historical compatibility path below.
- Historical compatibility applies only when the **source assignment** was created strictly before `2026-09-02T00:00:00Z` and its payload has **no** `actor_identity_bound` field. A corresponding `thread.acknowledged` or `handoff.accepted` with `actor_identity_bound=true` and the same target identity (trimmed/casefolded) may authorize that old assignment during ordinary materialization. The receipt itself is not required to predate the cutoff. Explicit `false`, explicit `null`, newer/malformed source timestamps, and unbound receipts do not qualify. Route capability, actionable subject type, archive and root-quarantine gates still apply. Exact one-shot canary admission does not use this fallback. This is a source compatibility contract, not evidence that historical work is currently safe to dispatch.
- Broadcasts, status/update notifications, transport receipts, unbound/operator lifecycle events, and non-target lifecycle events never create executions.
- The stable execution ID is derived from `(subject type, subject ID, target)`. Lease expiry and retries retain that ID; every retry receives a new fenced `attempt_id`.
- Runtime delivery output is diagnostic only. Only target-authored `thread.done` or `handoff.completed` events carrying authenticated identity-bound actor provenance complete execution.
- If terminal completion races transport failure, failure finalization atomically projects `execution.completed` and does not append a false `execution.attempt.failed` event.
- Dead-lettered work remains visible, but a later valid authoritative terminal event reconciles it to completion.

### Exact one-shot canary (operator-local only)

Use `--subject-id <literal-id> --target nova` to materialize and claim only
that assignment, or `--execution-id <literal-id> --target nova` for an already
materialized fresh pending root. The selectors are mutually exclusive and
require a canonical target in the validated route map. For fleet canaries use
only the four configured squad agents; this change does not provision any runtime.

Exact mode validates and claims under one state lock. It never globally
materializes or reconciles, never selects another root, and rejects unknown,
foreign, unbound, terminal, held, paused, dead-lettered, live or expired leased
work. It accepts only never-attempted pending work whose root history has no
attempt start, HOLD, replay, cancellation/pause, or resume. Holding/replaying or
pausing/resuming a never-attempted root does not restore canary freshness,
even when its projected status is pending with attempts=0. Ordinary workers
retain their existing replay/resume behavior. Subject mode accepts newly identity-bound assignments,
not the historical pre-provenance ACK fallback. It does not impose a creation
age TTL: operators must choose the exact fresh canary ID. Refusal exits 2,
without execution/outbox mutation or dispatch. Ordinary worker liveness
telemetry is still written, including on refusal. No selector retains the
ordinary global behavior; `--target` alone is refused, not a queue filter.

This is not an approval grant or a dispatcher filter. Keep the global worker
off and independently resolve deferred/ambiguous outbox safety before an
approved canary. Route/timeout validation and target-authored heartbeat/DONE
requirements are unchanged. Assignment ownership compares trimmed/casefolded
concrete agent names consistently with dispatch; the explicit `--target` must
still be canonical. Stored subject/execution IDs, target spelling in thread
history, completion artifacts and anchors are never rewritten or casefolded.
A locally green test is not fleet delivery proof.

## Runtime binding contract

`arvyx --authority-vault "$ARVYX_VAULT" execution worker` loads the same secret-reference-only route schema as the delivery dispatcher. The map binds target identity to a supported runtime class, endpoint environment reference, credential environment reference, and bounded timeout. Inline endpoints and credentials are rejected by the route loader/validator.

```bash
arvyx --authority-vault "$ARVYX_VAULT" execution worker \
  --state /var/lib/arvyx/control-events.jsonl \
  --worker worker-a \
  --routes /etc/arvyx/agent-routes.json \
  --lease-seconds 60 --max-attempts 3 --json
# optional: --first-heartbeat-seconds 300 (see "First-heartbeat window" below)
```

The worker validates every configured route and the lease/timeout budget **before** claiming work. It derives execution-capable targets from the map rather than accepting a caller capability assertion. A claimed attempt is wrapped in a deterministic `v2.agent-delivery/1` envelope carrying `delivery_mode=execution`, stable `execution_id`, fenced `attempt_id`, and the authoritative subject reference. Delivery uses the existing in-process Hermes/OpenClaw HTTP adapters with identity-bound authentication, no redirect/proxy fallback, bounded timeout, and stable request ID. No external provider command or subprocess is spawned. This is the kernel boundary: assignment → stable execution → atomic claim/lease → runtime launch. The model does not create its own execution.

Runtime HTTP acceptance writes the worker's initial heartbeat, which opens the attempt's first-heartbeat window (below), and leaves execution leased; it is not completion. The execution wake names the exact `execution_id + attempt_id` and the receiver callback tools:

- `control.execution_session_get` refetches the live fenced attempt plus authoritative thread/handoff, and only for the identity-bound target. It also returns the lineage's `session_returns` (with live delivery status and provider receipt), so a reclaimed attempt or restarted session finalizes an existing return instead of sending another.
- `control.execution_heartbeat` extends that same attempt's lease from the identity-bound target. It records target provenance and core-enforces a 3,600-second maximum; each periodic call must use a fresh `idempotency_key`, and heartbeat never supplies terminal authority. The attempt's first such call ends its first-heartbeat window; every call renews the lease by `lease_seconds` from that call.

The receiver must stop and refetch on a fencing or expiry error. Rejection records a fenced failure and requeues the stable execution. Failure recording may occur after nominal lease expiry only while the same `attempt_id` and worker still own the unreclaimed lease. See the selective-transplant record (private, not exported) for the source provenance and the ACP/MCP boundary adapted from Buzz.

Beyond the session tools, the continuation contract carries:

- **Restart rediscovery**: `control.execution_list` (or `GET /executions`,
  identity-scoped) lets a restarted runtime find its leased execution and
  resume the exact `execution_id`/`attempt_id` through the session tools
  instead of starting unrelated work. A duplicate wake for the same attempt
  is idempotent: refetch state, never repeat lifecycle writes.
- **HTTP surfaces** for webhook-native runtimes without an MCP client:
  `GET /executions`, `GET /executions/<id>`, and
  `POST /executions/<id>/heartbeat` (identity-bound target only) mirror the
  MCP tools under the standard control scopes.
- **Envelope context**: the wake payload also names `target`, the originating
  lifecycle event as `origin_event_type` (`source_event_type` stays
  `execution.attempt.started` for compatibility), the worker's
  `lease_seconds` so the runtime knows its renewal cadence, and
  `first_heartbeat_seconds` so it knows how long it has to send the first
  heartbeat. The wake text states both numbers.
- **Re-wake backoff**: an expired lease retries only after its expiry plus a
  deterministic exponential backoff (15 s base, 300 s cap, keyed by attempt
  count), and a rejected wake retries after the same backoff from its failure
  time; a fresh execution claims immediately. This keeps a stalled or failing
  target from burning its dead-letter budget in minutes under duplicate
  wakes.
- **Resolvable wake delivery**: before any network I/O the worker appends the
  wake's delivery record (`execution_delivery_<hash>`, `delivery_mode=execution`,
  target = execution owner) to the outbox projection under the execution
  fence, then finalizes it to `delivered` or a `superseded` dead letter. The
  delivery ID the wake names therefore always resolves through
  `control.delivery_get` for the target. The dispatcher never claims or
  replays these records; see `docs/outbox.md`.
- **Owner-only wakes**: an execution wake, a session return, and a
  session-return receipt continuation are only ever addressed to the identity
  that owns the execution; no wake names another identity's execution or
  attempt. An assignment whose *subject text* asks its target to act on
  someone else's execution still wakes only the target for its own execution;
  the identity-bound session, return, and delivery reads refuse the foreign
  access, and the target's BLOCKED report ends in HOLD (below), not a loop.

### First-heartbeat window and renewal lease

An LLM runtime needs time to start before it can send its first heartbeat
(production: 71 s on a healthy path, against a 120 s lease; four executions
dead-lettered because the 120 s lease was not enough). Raising the lease would
also delay noticing a target that stopped, so an attempt has two distinct
deadlines:

- **First-heartbeat window.** When the wake is accepted, the worker's
  heartbeat runs the attempt's lease to `accepted_at + first_heartbeat_seconds`
  and records that deadline as `first_heartbeat_deadline` (plus
  `first_heartbeat_seconds`) in its `execution.heartbeat` event. The default
  is 300 s (`--first-heartbeat-seconds` on `arvyx --authority-vault "$ARVYX_VAULT" execution worker`; when that
  flag is omitted and `--lease-seconds` is larger than 300, the window equals
  the lease). An explicit value below `--lease-seconds` or above 3600 is
  rejected before any claim.
- **Renewal lease.** The first identity-bound target heartbeat for the attempt
  is recorded once as `first_target_heartbeat_at`. From then on every target
  heartbeat renews by `lease_seconds` from that call, exactly as before. The
  first heartbeat can therefore end the attempt earlier than the window would
  have: after it, silence longer than `lease_seconds` expires the attempt.

Only an identity-bound target heartbeat ends the window. The worker's own
heartbeat never does, a target can never open or reopen a window, and a
worker heartbeat recorded after a target heartbeat never reopens it. Both
fields are empty on events written before this change, so older logs project
and expire exactly as before, and projection never depends on the current
worker configuration.

When an attempt expires, `last_failure` names the case:

| `last_failure` | meaning |
| --- | --- |
| `no target heartbeat within first-heartbeat window (300s) after accepted wake` | the wake was accepted but the target never started: check the runtime and its session, not the lease |
| `target heartbeat lapsed: the renewal lease (120s) expired after the last heartbeat ...` | the target started and then stopped heartbeating |
| `lease expired before heartbeat or finalization` | no window was recorded: an attempt from before this change, or a worker that died between the claim and recording the accepted wake |

The same text is kept when the attempt budget runs out and the execution is
dead-lettered. `leased_without_recent_heartbeat` does not count an attempt that
is still inside its window; once the window closes, or after the first target
heartbeat, the usual `--heartbeat-stale-seconds` rule applies. The BLOCKED
retry below is unchanged, but a target that reports BLOCKED without ever
heartbeating is only re-woken, or held, once its window has closed.

The production worker unit needs no change: the 300 s default applies with
the existing `--lease-seconds 120`. Pass `--first-heartbeat-seconds` only to
tune the window.

### Bounded BLOCKED retry

A target that cannot proceed posts one `control.thread_reply` whose text
starts with `BLOCKED` (the execution wake contract tells it to, for example
when the subject asks it to inspect another identity's execution). The first
word may carry markdown emphasis, heading or list markers and must be followed
by punctuation, whitespace or the end; quoted or questioned forms
(`"BLOCKED" earlier`, `> BLOCKED?`) and identifiers (`BLOCKED_BY_X`,
`unblocked`) are not reports. Before
re-waking an execution whose attempt ended, the worker counts the trailing
consecutive attempts whose target's latest reply on the subject was a BLOCKED
report. Any new input resets the count: a reply from anyone other than the
target, a steer request, a resume, or a replay, and any attempt in which the
target replied with something other than BLOCKED. An attempt with no target
reply at all (silence, or a transport rejection) is neutral: it neither
extends nor clears the count. "Same reason" is structural: with no new input the
blocker cannot have been resolved through the control plane, however the model
words it the second time.

After **two** consecutive BLOCKED attempts with no new input, the worker does
not wake the target again. It appends `execution.held` with
`held_by=<worker>` and a `hold_reason` that starts with `target reported
BLOCKED` and quotes the latest report. That is the canonical HOLD: claims skip
it, `held_count` and the watchdog's `held_executions` attention show it, and
only an operator replay (a fresh budget) or a real target-authored terminal
moves it. The watchdog posts exactly one `[watchdog] execution <id> held for
operator` blocker thread per HOLD, deduplicated by log order, so closing that
thread never causes a re-post while the same HOLD stands. Only a thread with
watchdog provenance counts for that dedup (posted by the watchdog worker
identity, to `operator`, not through an identity-bound agent surface): an
agent posting the same title cannot suppress the operator page. The existing
`max_attempts` dead letter plus one autonomous replay still bounds targets that
fail without reporting BLOCKED.

Production activation is a systemd oneshot service plus timer (the maintainers' deployment kit names them `arvyx-execution-worker.service` and `.timer`; they are not shipped in this repository, so write the unit around the `execution` command above). The oneshot runs inside the supervised API container every five seconds and consumes the same root-owned route and credential references as agent delivery. Installing the code without installing and enabling such a timer is not an autonomy rollout.

## Health and recovery

```bash
arvyx --authority-vault "$ARVYX_VAULT" execution health --state /var/lib/arvyx/control-events.jsonl \
  --capable-target amir --json
```

Alert on:

- `assigned_without_live_execution_count > 0` (`acked_without_live_execution_count` remains as a compatibility alias),
- `dead_lettered_count > 0`,
- `held_count > 0`, or
- `leased_without_recent_heartbeat_count > 0`.

`closed_count` reports executions an operator terminally resolved (see below).
Those are not debt and never make the queue unhealthy; they exist so resolved
work stays visible instead of being mistaken for a silent truncation.

Operators can also read the same posture over HTTP: `GET /executions/health`
(operator identity only) returns the queue health plus the latest watchdog
tick.

## Autonomy watchdog

`arvyx --authority-vault "$ARVYX_VAULT" execution watchdog --state ... --routes ... [--probe] --json` runs one
overlap-locked tick that detects the four lifecycle gap classes and applies at
most one bounded remediation per subject:

1. **Target endpoint unavailable** — secret-safe route validation (plus an
   optional bounded TCP probe with `--probe`). Work for an unreachable target
   is deferred, never blind-replayed.
2. **Wake accepted but no ACK** — deliveries that stayed receipt-less past
   `--receipt-stale-seconds` are surfaced; the watchdog never forges receipts
   or posts another wake into the same broken path.
3. **Assignment without a live execution** — missing executions are materialized
   (idempotent), and a dead-lettered execution is replayed **once** per
   lineage when its route is reachable. A second dead letter moves it to the
   canonical `held` state and posts exactly one operator blocker thread. A
   HOLD the worker applied for repeated BLOCKED reports is escalated the same
   way, once per HOLD.
4. **Leased without a recent heartbeat** — detected via
   `--heartbeat-stale-seconds` (an attempt still inside its first-heartbeat
   window is not counted); the remediation is the worker's own lease
   reclaim plus re-wake backoff, so the watchdog only reports it.

All mutations go through the fenced execution domain functions, every
remediation is idempotent, and a dedicated lock serializes whole ticks, so an
overlapping run cannot double-activate anything. Production activation is a
systemd oneshot plus timer at a 60 s cadence (`arvyx-execution-watchdog` in the
maintainers' deployment kit; not shipped in this repository).

## Operator replay and HOLD

- `arvyx --authority-vault "$ARVYX_VAULT" execution replay --execution-id ... --routes ...` (or operator-only
  `POST /executions/<id>/replay`) gives a dead-lettered or held execution a
  fresh attempt budget under the same stable ID. The route map must still
  contain the target; the dead-letter/hold evidence stays in the append-only
  log.
- `arvyx --authority-vault "$ARVYX_VAULT" execution hold --execution-id ... --reason ...` (or operator-only
  `POST /executions/<id>/hold`) parks an execution in the operator-attention
  `held` state: claims skip it, replay or a real authoritative terminal event
  are the only ways forward. Holding is idempotent; a completed execution
  cannot be held.
- Triage a held execution by its `hold_reason`. `target reported BLOCKED ...`
  means the target itself cannot proceed: supply the missing input or
  authority on the subject thread (or re-assign the work to the identity that
  owns it, for example the execution owner or the operator for an ambiguous
  session-return reconciliation) and only then replay; work that no longer
  matters is **closed** (never held forever — see below). `autonomous replay
  budget exhausted ...` means repeated silent failures: fix the route or
  runtime first. Replaying without changing anything just spends another
  budget.
- `arvyx --authority-vault "$ARVYX_VAULT" execution close --execution-id ... --resolution-category ... --reason ...`
  (or operator-only `POST /executions/<id>/close`) is the terminal resolution
  for work that will never run again: a superseded canary, an obsolete flow,
  work already completed through another route, or a subject that no longer
  matters. It accepts `held` or `dead_lettered` executions only (a `paused`
  execution must be resumed or held first), requires a
  `superseded | obsolete | terminal_elsewhere | no_longer_actionable` category
  plus a non-empty reason, is idempotent for the same category (a retried close
  never rewrites the recorded resolution, and a repeat naming a different
  category is refused rather than silently ignored), and appends
  `execution.closed` while leaving the hold
  or dead-letter evidence in the log. A closed execution is inert: it is never
  claimed, never replayable, cannot be re-opened by hold or cancel, and it
  leaves
  `assigned_without_live_execution`/`held_count`, so a queue with only
  superseded canaries can honestly reach zero. A later authoritative terminal
  event still reconciles it to `completed`.

Crash-after-ACK recovery:

1. Let the old lease expire; do not create or ACK another root.
2. Start the worker with the same state log and route map.
3. Verify the returned `execution_id` equals the original ID and `attempt_id` changed.
4. Complete work through `control.thread_done` or `control.handoff_complete` only.
5. Run worker/health again to reconcile the authoritative terminal event.

## Exact dispatcher fence (local opt-in)

The exact worker selector does **not** constrain another dispatcher daemon.
Before any production canary, the independent normal dispatcher must be paused
or separately configured under explicit production approval. This patch does
not grant that approval, reconcile backlog, or demonstrate canary clearance.
Fleet scope is nova, rowan, uma, quill only.

`python -m arvyx_control.dispatcher --vault "$ARVYX_VAULT" --exact-allowlist <manifest.json>` selects
an existing-fresh-outbox-only path. Supply the normal state/routes/worker and
`--deliver-after` arguments as well; the watermark never causes materialization
in exact mode. The manifest is a non-empty JSON array of objects with exactly:
`outbox_id`, `subject_id`, `target`, `source_event_id`, `source_event_type`,
`execution_id`, `attempt_id`, `payload_hash`. Values are literal strings copied
from the authorized fresh item and its source, not guessed historical IDs.
For direct thread/handoff delivery, execution/attempt fields must be empty;
for session returns both must match the authoritative live attempt and request.
The outbox ID and payload hash are recomputed and checked under the state lock.
The entire list is validated before any append, and must fit `--limit`.

Missing, malformed, empty, mismatched, already-attempted, non-pending or not-due
items refuse without writes or sends; there is no fallback to normal dispatch.
Exact mode never globally materializes, advances cursors, settles orphan wakes,
reclaims leases, refreshes projection checkpoints, or records normal dispatcher
liveness. Only explicit existing fresh direct assignments and session returns
are supported. Session returns retain provider receipt/ambiguity semantics,
but **never automatically enqueue a receipt continuation**. Receipt-continuation
and execution-wake outboxes are refused by this narrow path. Creating or sending
a continuation requires a separate supported and approved gate; this is not a
complete end-to-end canary rollout command.

Exact execution claims reject any existing invalid/quarantined root rather than
recreating it. Both subject-ID and execution-ID selection require equality of the
complete source-derived root/subject/type/target/source-event/type tuple before
any append. A refusal neither claims nor dispatches work.

## Rollout gates

Before deployment or runtime enablement, an operator must separately approve and prove:

1. route-map revision/hash, secret references, and identity/runtime match for every target;
2. consumer-loaded attestation, not merely file presence;

   Gates 1–2 are mechanized by the versioned route document (described in the
   operators' delivery guide, private): `arvyx routes doctor --routes <path>` proves the
   document's sha256/revision/metadata and per-route references, dispatcher
   ticks and worker JSON output attest the loaded `route_revision` and
   `route_sha256`, and `GET /deliveries/health` exposes the dispatcher's last
   attested pair for the declared-vs-loaded comparison.


3. positive wake probes and negative controls for stale map, wrong identity, missing credential, unsupported runtime, and unreachable endpoint;
4. identity-bound ACK/accept and terminal calls always use the authenticated target actor;
5. supervisor cadence shorter than lease and alert budgets;
6. one canary per enabled target showing delivery acceptance, receiver-authored execution activity, same-ID reclaim, heartbeat, inter-agent blocker routing, authoritative completion, and zero queue-health gaps.

Until those gates pass, keep the worker disabled. Hermes `/goal` and OpenClaw hooks must be proven end to end per enabled identity; HTTP acceptance is never treated as completion.

## Deep10 integrated recovery fences

Execution wake delivery retains the outbox record returned by pre-effect
persistence and finalizes with that exact record’s worker and claim-attempt
generation. Watchdog dead-letter remediation checks authoritative subject
completion from the same locked event snapshot before either replay or HOLD.
A terminal subject yields `changed` without effects even if the execution revision
has not changed. These integration contracts were inspected statically only;
current runtime regressions are not executed.


Execution-managed assignment deliveries are informational. Eligibility uses the same identity-bound actionable thread/handoff policy as the execution worker, including its narrow pre-provenance target-authorization fallback. The dispatcher emits `delivery_mode=notification` with `execution_managed=true`; its response contract prohibits starting work, ACK/accept, or DONE. Only the canonical execution wake supplies the exact execution and attempt IDs to validate through `control.execution_session_get` before work. The target records only a delivery receipt for the notice; that receipt grants no execution authority. Old queued direct assignments receive the same restriction at transport time without changing their durable ID or payload. Ordinary notifications, broadcasts, unbound coordination, and strict exact-dispatch admission retain their existing gates.
