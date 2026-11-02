# AMC local error diagnostics

## Activation (operator-owned; not performed by this change)

No vendor account or third-party export. Set `ARVYX_DIAGNOSTICS_DB` to an absolute
SQLite filename in an existing private (0700) operator-owned local persistent
state directory. Set the same path/mount for API, execution worker, dispatcher,
watchdog and local MCP/CLI services. Do not use a business control-event filename.
New database files are 0600; non-regular or group/world-accessible existing files
are refused. Keep the directory inaccessible to untrusted writers. SQLite is a
local-filesystem sink, not a network-filesystem coordination service.

The target filename must not exist on first activation (do not `touch` it). The
writer builds a private temporary SQLite database and atomically publishes it
without overwriting an existing path. Dedicated identity is SQLite application ID
`0x414D4344`, schema version 1, and the exact diagnostics schema. Existing empty,
foreign, or legacy unidentified stores are refused before writable PRAGMAs/schema
operations; no adoption or migration is performed. Failures increment
`sink_failures`; reads expose `available=false` and `read_failed`. Choose a new
filename instead of changing identifiers on an existing store. Concurrent first
creators converge on the completed identified file; normal writers serialize
transactions and retain bounded retries/retention.

Set `ARVYX_RELEASE_BUILD_ID` explicitly to an immutable deployment artifact ID
(e.g. a commit or image build identifier). It is sampled once per reporter and
must match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. Unset uses the package version;
invalid input becomes the fixed `invalid-build-id` sentinel, never raw env text.
No other environment values are included in event metadata.

Unset variable means disabled, explicitly visible in operator status. Restart
processes after configuration changes. All diagnostics HTTP paths require an
operator identity even in demo mode; agent scopes do not grant diagnostic access.
Local CLI reads use OS file permissions, like existing AMC local operator tools.
On the current production host, API, dispatcher, worker and watchdog all run in
`arvyx-v2-api` as UID/GID 10001. Run observer commands through `sudo docker exec
arvyx-v2-api python -m arvyx_control.diagnostics ...`, so readers use that same
UID and `/data/state/error-diagnostics.sqlite`. Do not run a host-user CLI against
the container's 0600 store. The host monitor's separate SQLite metadata query is
read-only under root. Verify these effective identities and the created file's
owner/mode before enabling notifications; do not chmod the database broadly to
work around a mismatch. Normal short writer contention is bounded by a 200ms
read timeout; a failed read still reports unavailable, never an empty success.
`status`, `list`, and `feed` construct read-only observers: no daemon, database
creation, health write, or heartbeat refresh. Query-only integrations must use
`Reporter(path, observer=True)`, not the producer factory. Missing sinks stay
missing and report read failure. API/background producer reporters remain writable.

```
python -m arvyx_control.diagnostics status
python -m arvyx_control.diagnostics list
python -m arvyx_control.diagnostics feed --after 0
python -m arvyx_control.diagnostics canary
```

The canary **always uses disposable synthetic state, loopback ephemeral HTTP and
a temporary database**, ignoring the configured sink. It injects real exceptions
at the API and worker boundary, submits a browser-shaped report, flushes and reads
all groups through authenticated HTTP. It cannot target production. It does not
prove production arrival or external alert delivery. IDs/timestamps vary; the
scenario and expected aggregate counts are deterministic.

## Operator surfaces and notification integration

- `GET /diagnostics`: bounded group list plus sink status.
- `GET /diagnostics/groups/<64-hex-fingerprint>`: retained group detail.
- `GET /diagnostics/status`: read-side health.
- `GET /diagnostics/feed?after=<cursor>`: at most 100 NEW/REGRESSED group events.
- `POST /diagnostics/client`: operator-authenticated, 2048-byte HTTP cap, fixed
  event-kind allowlist; global process budget 20/minute. Browser also caps at
  10/minute with one in-flight request and 5-second timeout. Client reports carry
  `untrusted-client`; server generates trace identity, ignoring supplied IDs.
- Dashboard expandable diagnostics panel shows status, counts, safe stack frames,
  first/last timestamps, trust, fingerprint and latest trace.

NEW means a group first appears in retained storage. REGRESSED means another
occurrence after an hour without that group. This is inactivity-based recurrence,
not a human-resolved issue workflow. Repeats increment count without a new alert.
Feed entries carry trust, component, current count, release, trace and a detail path; pruned groups are explicitly unknown. The `checkpoint` aliases `cursor`.
Feed IDs are SQLite AUTOINCREMENT monotonic within this database. The consumer
must atomically persist the returned `cursor` as its checkpoint **only after**
acknowledged delivery to the existing authenticated operator notification channel.
Do not auto-advance on failed delivery. Deduplicate by database identity + cursor.
A `gap` signals pruning since the checkpoint; re-list current groups and notify
that evidence was lost. Database deletion/restoration requires an explicit cursor
reset. This engine creates no tasks/threads, does not send webhooks, and does not
claim an alert arrived. Parent deployment must route the feed and record an actual
synthetic alert receipt before declaring operational monitoring complete.

## Privacy and failure isolation

No exception message/repr, URL, request/response body, header, token, local variable,
source line or absolute filename is captured. Frames contain only AMC module,
function and line metadata (16-frame cap). Fingerprints include component, fixed
context code, exception class, frames and validated deployment release. A request ContextVar
correlates nested capture and deduplicates the same propagating boundary fault; generated `X-AMC-Trace-ID` is returned on HTTP responses.
Browser-provided message/stack/trace data is discarded, not placed in the business
journal. Browser text is never rendered; server fields render with textContent.
This is a separate best-effort telemetry lane, not the audit authority.

The read-model app remains read-only **for business state**, not globally
side-effect-free: its import fence explicitly permits only `TRACE` and `capture`
from diagnostics. No Reporter/store writer or whole-module import is permitted.
Capture queues allowlisted fault metadata to the dedicated sink; it cannot append
vault/control/audit records. A synthetic projection/auth-fault regression snapshots
every business fixture path, content hash, size and mtime before/after and proves
only the separate diagnostics sink receives those faults.

Capture queues metadata with `put_nowait` into a 256-item queue. Only its daemon
writer does disk I/O; SQLite writer contention waits at most 200ms in that daemon.
SQLite BUSY/LOCKED is retried up to three attempts (at most 600ms lock wait in
the daemon), with a visible retry count; permanent I/O errors are not retried.
Out-of-order producer timestamps preserve minimum first-seen and maximum last-seen.
Queue overflow, sink failure, capture failure, expected refusal, browser throttling
and disabled capture are counted, not recursively reported. Normal process exit
allows a bounded two-second flush; abrupt exits may lose queued evidence.
Read-side failures are explicit, never an empty healthy verdict. Counter snapshots
are retained per process (max 128, seven days); live counters are marked
`this-process`, persisted counters aggregate retained snapshots. During a sink
outage its own failure counts cannot be persisted: monitor live status plus stale
`last_sink_heartbeat`. Parent must also monitor absent/misconfigured producers;
a healthy API writer is not proof the worker uses the same configuration.

## Retention and sizing

Defaults: 512 groups, seven-day inactivity retention, 1024 feed transitions,
256 queued metadata records, at most 16 frames/event. Database cap 4096 SQLite
pages (16 MiB at default 4 KiB pages), plus a bounded rollback journal; reserve
at least 32 MiB for this sink. Deleted pages are reused; file size need not shrink.
Pruning occurs during writes, old groups are hidden on reads, and idle health
snapshots are attempted every ten seconds. Keep backups private and apply the
same retention to them. This is lossy operational telemetry, not forensic audit.

## Coverage matrix (source-level scope, not a claim of universal interception)

| Surface | Wired | Limitations / host responsibility |
|---|---|---|
| API HTTP | Handler boundary, auth-store exception, audit/journal handled failures | Transport/body refusals remain HTTP responses; process startup below Python requires host monitor |
| Read-model API (`apps/control-center-api`) | HTTP boundary, projection and auth-store handled faults | Remains read-only; diagnostic retrieval stays on the operator API, sharing the configured sink |
| MCP | Explicit handle_request boundary; expected refusal count; handled secret-audit failures | Errors already converted to non-exception business results require their domain health metrics |
| CLI | Explicit main boundary | Legacy command-specific handled validation/error outputs are not all converted; no blanket global hook |
| Execution worker | Tick boundary; handled wake failure | Liveness record remains independent authority; lease/refusal semantics unchanged |
| Dispatcher | Tick boundary; setup I/O, adapter, deferral, continuation, finalization catches | Expected lost leases remain business decisions |
| Agent delivery | Transport exception and HTTP error classification | Non-exception provider refusals remain delivery health data |
| Liveness | Swallowed tick-record write failure | Does not replace host monitoring of missing ticks |
| Watchdog | Tick boundary and swallowed TCP probe failure | Existing escalation policy unchanged; this sink adds no escalation threads |
| Dashboard | error, unhandledrejection, failed API fetch and 5xx; group/status panel | Offline/browser-close losses unavoidable; client reports untrusted, not server evidence |
| Secrets | Generic API audit failures retain metadata-only capture | Separate secret-delivery receiver/protocol swallowed catches not instrumented in this patch; host monitor plus existing secret audit required |
| Other tools/importers/replica | Unhandled errors reaching CLI/MCP/API boundaries | Inner swallowed fallback failures outside listed paths are not exhaustively instrumented |
| OOM/SIGKILL/interpreter crash/systemd startup/container exit | NOT caught | **Host monitor required**, including health endpoint failure, stale worker/watchdog tick, disk pressure and absent diagnostic heartbeat |

Expected ValueError at decorated entrypoints and explicitly handled API/MCP
validation/refusal paths are suppressed, not incident groups. Unhandled filesystem
PermissionError/FileNotFoundError remain incidents; they are not authentication
refusals. Explicit infrastructure catches (audit, network, store) are incidents
even when a domain refusal shares an exception class. Do not
infer all ValueErrors are harmless; investigate existing domain health evidence.

External Sentry/OpenTelemetry may be added later as an independently reviewed
optional adapter. Neither is installed or impersonated here.
