# Runbook: delivery dead-letter recovery

Authority prerequisite: set `ARVYX_VAULT` to the actual configured absolute vault path before using these commands (for the maintained V2 host units, `/srv/arvyx-v2/data/vault`). Do not derive it from `--state`; state may be outside the vault. An empty variable is not a valid configuration. Global `--authority-vault` precedes the CLI subcommand; the standalone dispatcher uses `--vault`.


For a fleet with unresolved delivery dead letters accumulated during a period
of target unreachability (route down, tunnel offline, machine away). The goal
is zero *actionable* dead letters without erasing evidence and without blind
replay.

Preconditions: operator identity, the control API reachable, and the target's
route **currently healthy** - never replay into a route you have not just
probed. Delivery health must show a fresh dispatcher tick.

## 1. Confirm current reachability first

Historical dead letters say nothing about the present. Prove the target is up
before touching the queue:

```bash
arvyx --authority-vault "$ARVYX_VAULT" execution watchdog --state <state> --routes <routes> --probe --json
```

`reachability.<target>.ok` must be true. If it is not, stop: fix the route,
not the queue.

## 2. Inventory and classify

```bash
# operator identity
GET /deliveries/dead-letter
```

Every record now carries `replayable`, `replay_blocked_reason`, and any prior
resolution. Classify each dead letter into exactly one bucket:

| Bucket | Test | Action |
|---|---|---|
| still actionable | the subject (thread/handoff) is still open and the work still matters | replay (step 3) |
| superseded | a newer delivery or subject replaced this one | resolve as `superseded` |
| obsolete | stale canary, retired flow, subject no longer relevant | resolve as `obsolete` |
| terminal elsewhere | the subject already reached an authoritative DONE through another route | resolve as `terminal_elsewhere` |

Check the subject state with `GET /threads` / `GET /handoffs` before deciding.
Record the decision in the resolution detail - it is the audit trail.

Some records arrive already classified and need no action (their
`resolved_by` says who classified them):

| Record | Arrives as | Meaning |
|---|---|---|
| session return whose fenced attempt is gone (`failure_detail` contains `execution attempt is no longer live` or `lease has expired`) | `superseded`, `resolved_by=dispatcher` | the attempt can never become live again; the owner's live attempt may request its own return |
| session return whose subject already has an authoritative DONE | `terminal_elsewhere`, `resolved_by=dispatcher` | nothing left to deliver |
| execution wake (`payload.delivery_mode=execution`, ID `execution_delivery_*`) that was rejected or never finalized | `superseded`, `resolved_by=execution-worker` | the execution lineage owns redelivery; look at the execution, not the wake |

Session returns and execution wakes have extra rules:

- **Never replay a session return whose attempt is no longer live.** The API
  refuses it (`session return replay refused`): the replayed copy carries the
  same fenced `attempt_id` and would dead-letter at the same dispatch gate. If
  the work still matters, the owning execution's live attempt must request a
  new return; if the execution is held, replay the *execution* (see
  `docs/durable-agent-execution.md`).
- **Execution wake records are never replayable** (`replayable=false`); to
  retry, replay the execution.
- **A session return whose target does not own the execution** (`does not
  own` in `failure_detail`) or names an unknown execution is never
  auto-classified and was never sent to anyone. Treat it as an incident:
  find the source `execution.session_return.requested` event, confirm how it
  was written, then classify it (`obsolete` or `superseded`) with that finding
  in the detail. Do not replay it.
- **Legacy `execution attempt is no longer live` dead letters** written before
  automatic classification (empty `resolution_category`) usually are the same
  case as the first row above, but the old gate used that one message for an
  owner mismatch and an unknown execution too. For each record, read its
  `payload.execution_id` from `GET /deliveries` (the dead-letter listing omits
  payloads), then confirm with `GET /executions/<execution_id>` that the
  execution exists and its `target` equals the record's `target` (otherwise
  handle it as the non-owner case above). Then confirm the execution has a
  newer attempt, is held, dead-lettered, or paused, and resolve as
  `superseded` - or as `terminal_elsewhere` if the subject is DONE.

## 3. Resolve the non-actionable records

```text
POST /deliveries/<id>/resolve
{"resolution_category":"<bucket>","detail":"<why, secret-safe>"}
```

Append-only: the dead letter keeps its status and evidence. Same-category
repeats are idempotent.

## 4. Replay the still-actionable records, exactly by ID

```text
POST /deliveries/<id>/replay
```

Replay mints an `epoch+1` sibling with the identical payload; the original
record is untouched. Replay is refused while the target is missing from the
authoritative route map. Replay one record, watch it deliver and receipt
(`seen -> accepted -> completed`), then continue - do not fire all replays and
hope.

## 5. Fresh canary through the full lifecycle

After the queue is clean, prove the target end to end with new work, not a
replay: create a thread targeted at the agent and require

```text
authenticated ACK -> live execution with heartbeat -> target-authored DONE
```

Verify with `GET /executions/health` (no gaps, no dead letters, no holds) and
`GET /deliveries/health` (`unresolved_dead_letters: 0`, `ok: true`).

## 6. Close the held executions that will never run again

`GET /executions/health` counts `held_count`, and a held execution stays in that
count until it is replayed or a real terminal event arrives - so a fleet whose
remaining holds are superseded canaries can never report a clean queue. Resolve
them explicitly instead of leaving them:

```text
POST /executions/<id>/close
{"resolution_category":"superseded","reason":"superseded by <fresh subject id>"}
```

Allowed categories: `superseded`, `obsolete`, `terminal_elsewhere`,
`no_longer_actionable`. Only `held` or `dead_lettered` executions can be closed;
replay first if the work still matters (a `paused` execution must be resumed or
held first). Closure is idempotent for the same category, append-only, and keeps
the original hold/dead-letter evidence in the log; a repeat that names a
different category is refused instead of silently keeping the original one.

Verify with `GET /executions/health`: `held_count: 0`,
`assigned_without_live_execution_count: 0`, and `closed_count` equal to the
number you resolved. `held_count > 0` is always either live debt or work you
have not triaged yet - never a cosmetic value.

## 7. Definition of done

- zero unresolved dead letters that remain actionable;
- every resolved record carries a category and a reason;
- every non-actionable held execution is closed with a category and a reason,
  so `held_count` reflects only real, unresolved operator work;
- one fresh canary completed with authenticated lifecycle events;
- no new dead letters during the observation window.
