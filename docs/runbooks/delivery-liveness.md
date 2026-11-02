# Runbook: delivery liveness probe, dead-man switch, and canary

Authority prerequisite: set `ARVYX_VAULT` to the actual configured absolute vault path before using these commands (for the maintained V2 host units, `/srv/arvyx-v2/data/vault`). Do not derive it from `--state`; state may be outside the vault. An empty variable is not a valid configuration. Global `--authority-vault` precedes the CLI subcommand; the standalone dispatcher uses `--vault`.


Agent delivery can fail silently in two ways that nothing inside the control
plane notices:

- the **transport** dies (a tunnel, a route endpoint, a webhook receiver), so
  every wake fails or dead-letters while the queue keeps accepting work;
- the **tick** never runs (a timer stops, or a `docker exec` tick targets a
  container that was just recreated), so there is no failure event at all,
  only silence.

In both cases the usual escalation path (watchdog threads, outbox delivery)
is the thing that is broken, so the alarm dies with the patient. This runbook
covers the three independent out-of-band signals that close that gap:

| Signal | Runs | Wakes an agent? | Alerts through |
|---|---|---|---|
| `arvyx --authority-vault "$ARVYX_VAULT" delivery probe` | every 5 minutes | no, read-only | notifier config + dead-man ping |
| dead-man check | external service | no | the external service, when pings stop or `/fail` arrives |
| `arvyx --authority-vault "$ARVYX_VAULT" delivery canary` | once a day, explicitly | yes, one marked `ask` thread | notifier config + its own dead-man ping |

The probe and canary both run from the host virtualenv, not through
`docker exec`, so an API container recreate cannot silence them.

## Tick liveness records

Every dispatcher tick (`python -m arvyx_control.dispatcher --vault "$ARVYX_VAULT"`) and every
execution-worker tick (`arvyx --authority-vault "$ARVYX_VAULT" execution worker`) overwrites one small JSON
record in `liveness/` next to the state file:

```text
<state dir>/liveness/state-<state_id>/dispatcher.json
<state dir>/liveness/state-<state_id>/execution-worker.json
```

`state_id` is SHA-256 of the resolved state filename encoded with the filesystem encoding. The containing state directory scopes this identity; shared host/container mount prefixes and symlink aliases resolve to the same telemetry. Sibling state filenames use separate namespaces. Old flat records are ignored; wait for a fresh worker tick rather than copying unbound records.

Fields: `state_id`, `component`, `finished_at`, `result` (`ok` did work, `idle` nothing
to do, `error` the tick ran and failed), a short redacted `detail`,
`route_revision`/`route_sha256` when the route document is versioned, and
`code_version` (plus `build_id` when `ARVYX_RELEASE_BUILD_ID` is set).

- Written with write-temp-then-rename, so readers never see a torn record.
- A write failure prints one `warning: liveness record ... not written` line
  to stderr and is otherwise ignored: telemetry never changes a tick's exit
  code or slows it down.
- A dispatcher `--dry-run` does not write a record.
- Records are operational telemetry, not domain events: they never enter the
  append-only control log, and the V2 snapshot excludes `state/liveness/`
  from its stable cut.

## The probe

```bash
arvyx --authority-vault "$ARVYX_VAULT" delivery probe --state <state> --routes <routes> --json \
  [--notify-config <notify.json>] [--deadman-url-env VAR | --deadman-url-file PATH]
```

Exit codes: `0` ok, `1` degraded or failed, `2` usage or configuration error
(bad flags, unloadable routes or notifier config, invalid dead-man URL). The
JSON verdict is `ok`, `degraded`, or `failed`, the worst severity among the
findings, with per-target detail under `targets`.

### What each check means and what to do

**Transport (`transport_unreachable`, `route_config_invalid`; failed).** One
bounded TCP connect per route (the same probe as `arvyx routes doctor
--probe`, at most 5 seconds each). Only `hostname:port` is reported, never
the URL.

- Run `arvyx routes doctor --routes <routes> --probe --json` from the same
  host and environment to confirm.
- Fix the endpoint or tunnel. Do not replay dead letters into a route you have
  not just probed (see `dead-letter-recovery.md`).
- `route_config_invalid` means the probe's environment cannot resolve a route
  reference: the probe unit is missing the delivery EnvironmentFile, or a
  reference really is unset.

**Tick staleness (`tick_missing`, `tick_stale`, `tick_unreadable`; failed;
`tick_error`; degraded).** A record older than `--stale-multiplier` (default
3) times the expected interval (`--dispatcher-interval-seconds`,
`--worker-interval-seconds`; defaults 10 and 5, matching the timers) is
stale. A missing record means the tick has not finished once on this build,
or cannot write its `liveness/` directory.

- `systemctl status` and `journalctl -u` for the dispatcher or worker unit.
- For the worker: check whether the API container was recreated and the
  `docker exec` tick is failing (this is the silent-failure mode the check
  exists for).
- `tick_error` means ticks run but report failures: read `detail`, then the
  tick's journal. Configuration errors (a stale bootstrap watermark, an
  invalid route) surface here.
- A oneshot timer only restarts after the previous tick finished, so the real
  period is the timer interval plus the tick's own runtime. If slow ticks make
  the check flap, raise the expected interval to the measured period rather
  than the multiplier.

**Delivery flow, per routed target over the window (default 60 minutes).**
Counts `outbox.enqueued`, `outbox.delivered`, `outbox.attempt.failed`, and
`outbox.dead_lettered` events inside the window, the oldest item still
`pending` or `leased`, and the top failure details.

| Finding | Severity | Means | Do |
|---|---|---|---|
| `no_delivery_in_window` | failed | work was enqueued (at least `--delivery-grace-seconds`, default 300, ago) and nothing was delivered in the whole window | check transport first, then dispatcher ticks; this is the signature of a silent transport outage |
| `dead_letter_ratio` | failed | unclassified dead letters are at least `--max-dead-letter-ratio` (20%) of outcomes, given `--min-outcomes` (4) | read `top_failures`; a 4xx pattern usually means a receiver or credential change |
| `failure_ratio` | degraded | retried failures plus dead letters are at least `--max-failure-ratio` (50%) of outcomes | transient trouble; watch the next runs |
| `undelivered_too_old` | failed | the oldest undelivered item is older than `--max-undelivered-age-minutes` (30) | inspect the item (`GET /deliveries?target=`); a stuck backlog with a healthy transport points at the dispatcher |

Dead letters the dispatcher itself classified (a session return whose attempt
is gone) are counted as `dead_lettered_refused` and excluded from the ratios.
Execution-wake records are counted in the flow; an unfinalized one is reported
as `unfinalized_execution_wakes` and never judged as a stuck delivery, because
the execution lineage owns its redelivery. Targets that are not in the route
document are reported with `routed: false` and never produce findings.

**Execution flow (`lease_expiries_without_completion`; degraded).** Per
target: executions created and completed in the window, lease expiries (an
attempt reclaimed or dead-lettered after its lease ran out), dead letters,
holds, and the live count. Lease expiries with zero completions mean targets
are being woken but never heartbeat or finish.

- Look at the target's runtime: is it receiving wakes, and does it call
  `control.execution_heartbeat`?
- The watchdog report (`arvyx --authority-vault "$ARVYX_VAULT" execution watchdog ... --json`) lists leased
  executions without a recent heartbeat.

**Scan bounds.** The event log is streamed line by line: at most
`--max-scan-mib` (512) from its tail, lines longer than 1 MiB skipped and
counted, and only outbox and execution events decoded. `scan.truncated: true`
means the log outgrew the budget; window counts are still exact for a window
that fits in the budget, but undelivered items older than the scanned tail are
invisible. Archive or compact the log, or raise the budget.

### Alerts

With `--notify-config`, the probe sends through the existing notifier adapters
(`stdout`, `file`, `webhook`, `telegram`) and their existing gates, including
the telegram `api_base_url` exfiltration guard. The config names the adapter
and the environment variables holding secret values, never the values:

```json
{"adapter": "telegram", "bot_token_env": "ARVYX_PROBE_TELEGRAM_TOKEN", "chat_id_env": "ARVYX_PROBE_TELEGRAM_CHAT"}
```

A `file` config names its JSONL `path`; `webhook` names `url_env`
(`examples/notifiers/`).

- Alerts go out on a verdict change (ok to degraded or failed, degraded to
  failed and back) and on recovery to ok.
- While the verdict stays non-ok, the alert repeats every `--realert-hours`
  (default 6).
- Dedupe state lives in `liveness/state-<state_id>/delivery-probe-alert.json`. It records the
  verdict the last *successful* alert announced, so a notifier outage delays
  an alert to the next run instead of losing it.
- Alert text is short, redacted with the shared secret redaction, and never
  contains tokens or credential-bearing URLs.
- A notifier failure never changes the verdict or the exit code; it is
  reported under `alert.status`/`alert.detail`.

### Dead-man switch

With `--deadman-url-env VAR` (or `--deadman-url-file PATH`), every completed
probe run POSTs a short summary to the healthchecks-style URL, and a `failed`
verdict POSTs to `<url>/fail`. A run that refuses to start (exit 2) also pings
`/fail` when the URL itself is valid. The URL must be `https`, carries no
credentials, is read by reference so it never appears in a process listing,
is never printed, and each ping has a bounded timeout and follows no
redirects.

Configure the external check with a period equal to the probe timer (5
minutes) and a grace of about two periods. Then the external service alerts
when the probe host, its timer, or the probe itself dies, the one failure the
probe cannot report on its own.

## The canary

```bash
arvyx --authority-vault "$ARVYX_VAULT" delivery canary --api <control api> --auth-env <VAR> --target <agent> \
  --state <state> --timeout-seconds 900 --json \
  [--notify-config <notify.json>] [--deadman-url-env VAR]
```

The canary proves the whole chain once a day with a real, identity-bound
wake. It posts one `ask` thread titled `[arvyx-canary] delivery chain check
<run id>` to the target, then waits for each leg:

1. `thread_created`: `POST /threads` with the canary agent's own token and an
   idempotency key; the created event must be identity-bound.
2. `execution_created`: the assignment materialized an execution.
3. `wake_delivered`: the worker's wake delivery record exists and reached
   `delivered` (a rejected wake is reported with its failure detail).
4. `target_heartbeat`: the target heartbeated the attempt under its own
   identity.
5. `execution_completed`: the execution completed from an identity-bound
   `thread.done` written by the target.
6. `thread_done_readback`: the canary author reads the thread back through
   `control.thread_get` as done by the target.

The creation event must bind the returned thread ID, author and requested
target, not merely contain a true identity flag. Completion requires the exact
`terminal_event_id` to reference an observed target-authored, identity-bound
`thread.done` for this thread. Readback also checks the exact thread ID and
requires that observed bound DONE; a status/actor label alone is not identity
evidence. The log is trusted canonical authority, not an independent signature
verifier. Rotation or incomplete observation can leave the canary unqualified.

The report names `stopped_at`, the first leg that did not happen, with detail.
A held, dead-lettered, closed, or paused execution ends the wait early.
Completion without a target heartbeat is `degraded`; any other gap is
`failed`. Exit codes match the probe.

Why legs 2 to 5 come from the control log: the canary's agent token can only
read threads it authored. Execution, delivery, and heartbeat records belong to
the target and fail closed for other identities by design, and the canary
never borrows another credential. It reads those legs read-only from the log,
starting at the byte offset the log had before the canary thread existed.

- **`--auth-env` must be the canary agent's own token**, never the operator
  secret. An operator-authored thread is not identity-bound, so no execution
  materializes. The canary refuses and says so.
- Issue that agent `control.read` and `control.write`, with a TTL you rotate
  (`arvyx auth issue <canary agent> --scope control.read --scope control.write
  --ttl-days 365`). An expired token shows up as `stopped_at:
  thread_created` with `HTTP 401`.
- `--api` must be `https` unless it is a loopback address, because the token
  rides along. Redirects are never followed and no proxy is used.
- A canary that stops leaves an open thread and a live execution behind. The
  normal lineage applies (retry, dead letter, watchdog replay, then HOLD and
  one operator escalation). Close leftovers with `arvyx --authority-vault "$ARVYX_VAULT" execution close ...
  --resolution-category obsolete` once diagnosed.

## Operator deployment checklist

1. Deploy the build to the host virtualenv that the dispatcher already uses.
   Within one timer period, `liveness/state-<state_id>/dispatcher.json` and
   `liveness/state-<state_id>/execution-worker.json` appear next to the state file.
2. Create the notifier config (non-secret) and the probe EnvironmentFile
   holding the dead-man URL and the variables the notifier config names.
3. Create two external checks: the probe (period 5 minutes) and the canary
   (period 1 day, grace a few hours). Put their URLs in the EnvironmentFiles.
4. Run the probe once by hand and confirm `verdict` and `deadman.status`.
5. Enable the probe timer. Enable the canary timer after the first manual
   canary run succeeds.

## Ambiguous alert delivery

The canary's `POST /threads` response uses the REST `{status, body}` envelope;
thread identity and the identity-bound creation event are read from `body`.
MCP thread readback remains a raw JSON-RPC response. Router-based fixtures must
use the same serializer as the HTTP writer rather than returning unwrapped REST
domain dictionaries. A malformed explicit `body` is not bypassed using outer
thread fields. Source repair and fixture synchronization do not imply a live
canary has run or the delivery chain is accepted.

Only confirmed notifier results advance `alerted_verdict` and `last_alert_at`:
`sent` for remote delivery, `printed` for the configured stdout adapter, or
`recorded` for the configured local file adapter. Local completion is not proof
that an external person received a page. Dry-run and unknown results do not
advance the successfully announced verdict.
An `ambiguous` result persists `uncertain_verdict` and `last_uncertain_at`
without claiming success. The same verdict is suppressed until the configured
re-alert interval, then retried with reason `uncertain_realert`; this bounded
at-least-once policy can duplicate an accepted alert. A changed verdict, including
recovery, is announced immediately. A confirmed send clears uncertainty. Other
statuses do not prove delivery. These integration changes have static evidence
only; runtime checks were not executed.


The checked-in probe and canary units provision `state-77e58efcd4ce6f43da1cd8d7d746928e1a23840d543b441b0dd1dbdf3e439aa3`
for the exact `control-events.jsonl` basename. Before separately authorized deployment,
verify the configured state name, UID 10001 ownership and effective systemd/Docker
mount permissions. A changed state basename requires a separately reviewed unit
path. These source tests do not establish live unit permission acceptance.
