# Explicit watchdog notification dismissal

Authority prerequisite: set `ARVYX_VAULT` to the actual configured absolute vault path. Do not derive it from the state path or leave it empty. The global `--authority-vault` option precedes the subcommand.


`operator-alert-dismissal/v1` is a separate current-operator decision to abandon
one obsolete watchdog **notification**. It neither completes nor cancels the
originating business obligation, grants linked authority, authenticates a
historical actor, nor certifies that the full narrative graph is resolved.
Generic `archive_record` eligibility and its strict closure are unchanged, but
its function/API/CLI are disabled by default behind the explicit process gate
`ARVYX_ENABLE_OPERATOR_ARCHIVE=1`. Leave that flag unset for this dismissal-only
release. Alert dismissal remains separately enabled and operator-authenticated.

## Boundaries

- Only an untouched `thread.created` (plus harmless reads), type `blocker`,
  actor `arvyx-watchdog`, target `operator`, exactly bound to an earlier HOLD's
  execution/title/body is eligible. Missing historical identity stays missing.
- The originating execution and its structural authority neighborhood must be
  known and validate. Executions must be closed/completed with no lease;
  transport must be delivered/cancelled or explicitly terminally resolved.
  A selected alert with its own execution or transport is not notification-only
  and is rejected even if that runtime appears terminal.
- Unknown structured links, malformed raw history, continuations/session returns,
  legacy notifier histories without settled dispatch fences, live/held/paused
  runtime, ambiguous transport, and protected publisher authority are blocked.
  Invalid historical ACKs or lifecycle transitions stay blocked; cancellation
  does not repair old evidence.
- Structural links are discovered in both directions, including unknown fields
  and event source references. Explicit narrative string slots do not create
  executable authority edges. Their reference tokens remain in `audit_references`
  and the original exact raw histories remain untouched. An object nested in a
  narrative slot is not silently treated as prose. This classifier is local to
  notification dismissal and must never be used to claim generic archival.
- Active business threads can remain active when their runtime is terminal:
  dismissal does **not** authorize, dispose, ACK, or finish those threads.

## Canonical surfaces and authority

`POST /operator-alert-dismissal/{exact_thread_id}` requires the authenticated
operator identity and control-write scope. The HTTP operation journal and audit
wrapper still apply. There is no agent/MCP tool. `dry_run` defaults to `true`;
only the JSON boolean `false` applies. Spoofing an approval quote is not authority.

The local CLI follows the existing OS-operator trust boundary: local access to
write the authority file is operator access, not an agent identity choice:

```sh
arvyx --authority-vault "$ARVYX_VAULT" operator-alert-dismissal EXACT_THREAD_ID --state AUTHORITY.jsonl \
  --manifest exact-request.json --json
arvyx --authority-vault "$ARVYX_VAULT" operator-alert-dismissal EXACT_THREAD_ID --state AUTHORITY.jsonl \
  --manifest exact-request.json --apply --json
```

`--apply` and `--dry-run` together are refused. The manifest must use exact
`schema=operator-alert-dismissal/v1`, `operation=dismiss_watchdog_alert`,
`disposition=notification_only_not_lineage_completion`,
`category=historical_alert_obsolete`, `record_type=thread`, `target=operator`,
and empty `terminal_event_id` (there is no terminal-success claim).

The authenticated domain helper `prepare_alert_dismissal(state, record_id=...,
identity=..., reason=..., approval_reference=..., approval_quote=...,
evidence_references=[...])` prepares a read-only request after the same checks.
It binds the exact creation and latest revision, selected history hash, complete
structural revision/hash map, originating execution, retained narrative audit
references, and **whole authority SHA-256**. It does not auto-approve a decision.

Any authority append or raw byte change after preparation, including unrelated
watchdog ticks, makes the request stale. Re-prepare and re-review; do not alter
the digest in an old manifest to bypass the check. Preparation, validation and
append use the same state lock as execution/outbox writers. A successful apply
appends exactly one `thread.operator_archived` event with
`retirement.operation=operator_alert_dismissal`, `status=retired`, `pending=false`,
no DONE fields and explicit false lineage-completion/authorization assertions.
Connected records are not modified.

An identical immediate retry is idempotent, including selected-thread readback
markers. The original authority prefix is hashed again. Any other subsequent
authority activity makes an old retry fail closed; inspect the recorded exact
action rather than inventing another cancellation or declaring failure to have
applied. Verify each exact apply readback before proceeding to the next record;
never retry an older request after another record has been applied. CLI decisions
have durable domain audit but do not use the HTTP journal.

## Projections and resurrection

The event uses the already supported non-success retired lane, not a new success
state. JSONL/full/cold/checkpoint/SQLite projections retain the metadata. Existing
historical-source materialization, exact execution claims, outbox creation,
thread mutation, and queue-health gap guards treat the alert as inert. Watchdog
escalation deduplication continues to recognize the original creation for the
same HOLD. A genuinely new HOLD remains a new obligation and is not suppressed.

## Verification and deployment boundary

All repository fixtures are synthetic. Sealed live histories and per-record
requests/results belong outside public paths in restricted local evidence.
Rehearse preparation, dry-run, exact apply, retry and authoritative readback on
copies. Blocked cases are not successes and must retain their exact reasons.
Passing tests/rehearsal is not production authorization or independent review.
No live cleanup, deployment, credential change or publisher approval is implied.


The operator watchdog body policy is shared with strict retirement and the producer:
accept the complete canonical `target=... subject=...; <recorded HOLD reason>`
text or that complete text plus exactly one historical producer period. Punctuation
inside the recorded reason is retained. No trimming, prefix acceptance, extra
periods or guidance suffixes are accepted. Identity, provenance, terminal evidence,
raw revision/hash fences and each operation's existing eligibility rules still apply.
Strict retirement requires the source identity flag to be explicitly false;
generic archive remains disabled unless explicitly enabled in that process.
