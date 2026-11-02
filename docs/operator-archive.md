# Exact current-operator archival

Authority prerequisite: set `ARVYX_VAULT` to the actual configured absolute vault path before using these commands (for the maintained V2 host units, `/srv/arvyx-v2/data/vault`). Do not derive it from `--state`; state may be outside the vault. An empty variable is not a valid configuration. Global `--authority-vault` precedes the CLI subcommand; the standalone dispatcher uses `--vault`.


`operator-archive` is a separate, non-success lifecycle. It does not relax
`retirement.py`, infer missing historical identity flags, impersonate an owner,
complete work, approve business acts, reconcile delivery, or contact a provider.
There is no agent MCP tool, role expansion, batch apply, or background sweeper.

## Entry points and authorization

**Disabled by default for the dismissal-only release.** The domain function,
HTTP API (before audit/journal writes), and local CLI refuse generic archival
unless the server/CLI process explicitly sets `ARVYX_ENABLE_OPERATOR_ARCHIVE=1`.
Unset, empty, `0`, and `true` do not enable it. Request bodies cannot enable it,
and operator credentials or demo mode do not override it. Do not set this flag
for the dismissal-only production release. Tests opt in explicitly. This gate
does not disable authenticated notification-only alert dismissal or inertness
readers for already recorded dispositions. The commands below require opt-in.

```
PYTHONPATH=packages/arvctl/src python -m arvyx_control.cli --authority-vault "$ARVYX_VAULT" operator-archive RECORD_ID --state OFFLINE_STATE --manifest EXACT_REQUEST.json --dry-run --json
PYTHONPATH=packages/arvctl/src python -m arvyx_control.cli --authority-vault "$ARVYX_VAULT" operator-archive RECORD_ID --state OFFLINE_STATE --manifest EXACT_REQUEST.json --apply --json
```

CLI defaults to dry-run and uses the existing local OS/operator trust boundary.
Flags are mutually exclusive. One invocation selects one record and appends at
most one authority event. Do not give agents OS access as an authentication
workaround.

HTTP: `POST /operator-archive/RECORD_ID`, existing authenticated operator with
`control.write` and the existing operation-journal idempotency header. The body
is the exact request below plus optional boolean `dry_run` (default **true**).
Only explicit `dry_run: false` applies. Demo mode cannot authorize it. Domain
dry-run writes no authority event; HTTP audit/journal files can still change.
Use separate journal keys for dry-run and apply. Approval text is audit data,
never authentication. No Telegram message ID is manufactured.

## Exact manifest v1

Exactly these keys are required; unknown/missing keys, arrays and wildcard
selectors are rejected:

- `schema`: `operator-archive/v1`
- `operation`: `archive`
- `record_type`: `thread`, `task`, `handoff`, or `execution`
- `record_id`: exact path/CLI record ID
- `expected_event_id`: latest direct event, including read markers
- `source_event_id`: original creation event for that record
- `target`: immutable thread target, task owner, handoff recipient, execution target
- `history_sha256`: SHA-256 of the concatenated exact JSONL bytes for that record,
  preserving original whitespace and newlines (not a projected snapshot digest)
- `related_revisions`: object mapping **every** related record ID to exactly
  `{ "expected_event_id": "...", "history_sha256": "..." }`
- `category`: `operator_cancelled_no_longer_needed` or `historical_alert_obsolete`
- `reason`: exact, nonempty, trimmed decision, at most 1024 characters
- `approval_reference`: real supplied task/request/conversation reference, at most
  1024 characters; not an invented external message identifier
- `approval_quote`: actual quoted approval, at most 1024 characters
- `approval_sha256`: SHA-256 of UTF-8 `approval_quote`
- `evidence_references`: 1–32 distinct nonempty bounded references
- `terminal_event_id`: empty for honest cancellation; exact latest terminal
  execution event for historical-alert obsolescence

Each evidence reference is secret-shape screened as well as length/shape checked
before authority append. Work Board retired cards withhold full disposition
requests and evidence-reference names; the authorized archival authority still
retains the exact request. Task archival preserves the original creator and
validates the proposed history before append, including for exact retries.

The request hash and observed creation flag (`missing`, `false`, `true`) are
stored separately from current operator identity. Null/nonboolean flags are
malformed, not missing. Original raw bytes, messages and acceptance/ACK events
remain in the append-only authority.

Prepare requests from a fresh **full offline authority snapshot**, never from a
redacted inventory or an older pending-delivery list. Public Python helpers
`history_digest(state, id)` and `related_records(read_events(state), id)` expose
the exact byte digest and conservative linked closure. Preparation does not
establish eligibility: run the domain dry-run before reviewing an apply request.
The full closure includes structured references, reverse links, source/terminal
joins, and record IDs embedded in prose. Unresolved or ambiguous references
block rather than being guessed away. New links and relevant revisions conflict
under the same state lock as claims. Unrelated ordinary events do not stale the
request. Duplicate JSON keys and malformed authority bytes fail closed.

## Supported dispositions and deliberate limits

- Open/ACKed threads and open/accepted handoffs become `retired`; open tasks
  become `retired`. ACK actor/time, accepted-by, messages, ownership and evidence
  contracts survive. Terminal/reviewed subjects cannot be reinterpreted.
- Historical-alert category is limited to untouched operator-targeted watchdog
  blocker creation, exact HOLD/title/body/terminal execution join, no own root,
  and no active or unknown linked work. A missing creation identity flag stays
  `missing`. Existing strict retirement still requires explicit false.
- Separately selected unleased pending/held/dead-lettered executions may become
  `closed` with `no_longer_actionable`, under exact record and linked CAS. Their
  subject and operator watchdog alerts may remain open: this operation does not
  resolve either. Leased, paused and successful executions reject. Original
  hold/attempt history remains. Explicit operator closure cannot later reconcile
  itself to success.
- Creation-rooted and historical `thread.acknowledged` / `handoff.accepted`
  execution roots are supported for cancellation only. Local writer history
  (`09cd0d5`, `00f75c5`, `61fc38e`, then assignment-root switch `9184377`)
  uses the same SHA-256 subject-type/NUL/subject-ID/NUL/target ID algorithm.
  ACK/accept sources must join the unique original subject, exact owner and
  recorded ACK/accept actor; creation must precede ACK/accept, which must precede
  the execution root. Root `created_at` must equal the source event timestamp.
  Known marker-less source snapshots remain unknown; explicit false/null source
  flags reject legacy root binding. This validates a historical relationship,
  not authenticated execution authority or business completion. No normalization
  of owner spelling or alternate guessed ID algorithm is attempted.
- Archival-only thread structural validation accepts a missing ACK identity key,
  retaining its exact owner/actor and lifecycle checks. Null/nonboolean flags
  reject; missing DONE identity still rejects. The strict retirement validator
  is unchanged. Handoff acceptance requires a recorded exact recipient actor,
  even when there is no existing execution. All raw bytes stay unchanged.
- Subject archival requires linked executions already closed/completed and
  linked ownership records already terminal. It does not silently close held
  work. Rebuild the manifest after every preceding disposition. If an active
  owner and its active watchdog alert reference each other, neither archival
  operation may bypass the active-related-record guard; that dependency cycle
  remains blocked pending separately reviewed disposition. Support for an
  already-retired owner does not authorize making that cycle terminal.
- Delivered transports (including execution wake history) are preserved, not
  interpreted as business success or independent provider confirmation. Resolved
  dead letters and cancelled transports can remain linked. Active, ambiguous,
  unresolved or malformed transport blocks archival. Late target receipts for
  an archived subject are rejected; historical receipt evidence is retained.
- Continuation/session-return relationships and execution steer histories are
  deliberately unsupported and block. Replayed transport histories whose roots
  are not original enqueue events also block. These require separate work, not
  a relaxed validator. No notification cancellation surface is added: the fresh
  inventory has no pending/leased outboxes. Legacy `thread.notification_sent`
  or `thread.notification_failed` history also blocks: that notifier writes a
  claim before provider I/O outside the state lock and has no settled-send fence.
- The known separately governed publisher gate cannot be waived by this lane.
  Approval references neither authorize publishing nor erase other business
  approval obligations. Other purpose adjudication remains a human duty.

Exact retries must match the full original request and related history. Only
harmless thread readback after archival is permitted; original raw-history
rewrites, other lifecycle changes and changed reasons/approval references
conflict. Retrying an execution closure after separately archiving its subject
therefore conflicts: that is an intentional changed-related-revision fence.

## Inertness and views

Retirement is separate from DONE/completed/delivered. Canonical thread/task/
handoff projections, SQLite and Control Center use the distinct retired lane.
Execution projection/cache retain operator closure metadata. Archive events are
not success reconciliation, notification or continuation sources. Historical
creation/ACK/accept roots are suppressed before execution materialization and
exact claim. Outbox backfill checks archival authority independently of cursors,
bootstrap watermarks and route availability. Direct enqueue, replay and receipt
entry points also refuse archived subjects. No prior execution/outbox is needed
for suppression. Ordinary ownership mutations reject retired state.

SQLite migration adds retirement metadata to tasks/handoffs and acceptance
history to handoffs; derived schema is version 2. Projection checkpoint schema
is version 2. Authority is never deleted or rolled back.

## Dependency token classification

Discovery still uses conservative undirected transitive closure. Full
`session_return_…` identifiers are retained (and unsupported histories still
block), rather than inventing a `return_…` suffix reference. Other embedded and
Unicode-adjacent references retain the prior conservative substring behavior.
In narrative fields
only (`body`, `text`, `title`, `message`, `detail`, `reason`), the explicit
`PROSE_SYMBOLS` set classifies documented MCP method and field names as code
symbols, not record references. An identifier with actual authority history
always overrides that classification. Values in structured or unknown fields
remain conservative, including symbol-shaped values. Unrecognized, shortened,
and unresolved IDs remain blocking; this is not a canonical-ID-only regex or a
filter against existing records. No unknown link is silently dropped to make a
request eligible. Sharing an actual record ID in prose still connects records.

This parsing correction does not authorize cancellation of a connected active
owner/alert cycle, continuation, ambiguous transport, or protected publisher.
A sealed-snapshot preparation rejection is not a successful domain dry-run.

## Deployment and rollback boundary

This patch is local-only. Install compatible readers on **all** API, dispatcher,
worker, watchdog and maintenance paths before enabling writes. An old reader
ignoring archival can resurrect old roots. Rollback must keep compatible readers
or keep dispatch and workers paused/fenced. Never restore an older authority
snapshot to erase archival, subsequent receipts or other legitimate events.
A paused dispatcher does not prove all other writers or in-flight I/O are drained.
No deployment, service change or production apply is part of local verification.


The operator watchdog body policy is shared with strict retirement and the producer:
accept the complete canonical `target=... subject=...; <recorded HOLD reason>`
text or that complete text plus exactly one historical producer period. Punctuation
inside the recorded reason is retained. No trimming, prefix acceptance, extra
periods or guidance suffixes are accepted. Identity, provenance, terminal evidence,
raw revision/hash fences and each operation's existing eligibility rules still apply.
Strict retirement requires the source identity flag to be explicitly false;
generic archive remains disabled unless explicitly enabled in that process.
