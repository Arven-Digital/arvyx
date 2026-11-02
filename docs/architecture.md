# Architecture

## Integrated source checkpoint — 2026-10-29, not runtime approval

Review50 integration also seals the current process generation into native
lifecycle receipts, rejects consent prepared for a prior same-session process,
and requires attachment validation on native-leased reads, including the native
interactive client. Session-member termination uses stable pidfds, not a numeric
PID after membership inspection; unavailable pidfd support refuses acknowledgement.
Leader/group signaling and cross-platform process-tree qualification remain limits.

Authenticated remote-fence responses require strict framing/completion and use
the minimum of transport allowance and the inherited owner exchange budget.
At nonce capacity, new admission refuses but exact retained-witness settlement
and read-only status remain available; terminal outcomes cannot be changed.
Explicit operator `configure_remote_delegation(..., recovery_only=True)` retains
old private trust for settlement only, separate from execution provisioning.
It cannot authorize new effects or adopt copied/rebound stores. Same-boot source
recovery is implemented; cross-boot trust lifecycle remains unresolved. Lost leaf
completion replies still lack an exact durable-result readback protocol: listing
the latest 100 records or replaying execution is not a recovery mechanism.

Standalone pairing approve/deny now requires `--review-snapshot` containing the
exact selected pending record, including stable claim_id; never refresh a
fingerprint-only selection at decision time. MCP export authorization is refreshed
per resource. The source repairs and their unexecuted acceptance cases are listed
in the private integration supplement; they do not qualify runtime behavior.

Receiving-leaf identity is separate from logical machine/agent/session identity.
The leaf derives `receiving_leaf` from its durable incarnation, host boot,
database path/device/inode and provisioned owner/profile/workspace lease. Exact
capabilities discovery feeds preparation and its digest; commit seals that same
binding in the organizer ticket. The authenticated forwarding receiver and final
leaf compare it again before admission. Reprovisioning requires a new review;
an old preparation cannot silently follow a replacement logical endpoint.
Shared-authority non-root forwarding discovers the final leaf using the exact
request target. Independently provisioned cross-host forwarding additionally
retains the existing coordinator and receiver binding. Discovery is not consent,
enrollment or effect authority. Timeout is uncertain effect, not cancellation.
Running-effect revocation semantics and independent-host acceptance remain open.

Offload continuation is NOT retained-generation storage authority. A directory
inode and a saved traversal cursor cannot prove an earlier visited bundle still
exists. SUP-04/L4 and REV-0512/0544 remain OPEN/HOLD; do not rely on segmented
verification to authorize production pruning, relocation or history retention.
No retention protocol or automatic cleanup is supplied by this checkpoint.

Bundled Paperclip schemas do not establish AMC dispatch authority. The G28 FQDN,
G30 gateway-header and G32 provider-config patch claims remain conditional: no
maintained corresponding evaluator/forwarder/persisted-state merge consumer was
established. Hostname syntax is not resolved-address policy; static gateway
credentials are not caller passthrough; partial updates cannot validate effective
provider state without the stored provider. No speculative schema restriction or
new consumer was invented. Original NOT_SAFE verdicts remain original verdicts.

G50 remains PARTIAL: the legacy single-suggestion HTTP/MCP/CLI interface enforces
size/tag/secret limits but carries no batch future-job/quality evidence. Promotion
is separate. This compatibility boundary is not quality unification or clearance
of the original claim; changing it requires an explicit API/caller migration.

Current per-item source dispositions and exact static evidence are maintained in
`reviews.md`, `fix-reviews.md` and the private integration packet. Syntax and hash
checks are not behavioral acceptance, SAFE or permission to release.

Arvyx is a self-hosted control plane for multi-machine agent
teams.

The core flow:

```text
agent / harness
  -> MCP or HTTP API boundary (per-agent bearer tokens, scoped tools)
  -> governed memory vault + persistent BM25 index
  -> token-bounded recall / cited excerpts (secret shapes redacted)
  -> suggest -> refine -> promote write lane (pending, refining, notes lanes)
  -> hash-chained audit log + control-center visibility
```

## Layers

The existing layers below describe current code. The explicitly marked external-agent delegation section defines an approved target contract, not an implementation or security-completion claim.

1. **Identity:** agents, machines, runtimes, and projects in the registry;
   per-agent bearer tokens (`arvyx auth issue`) whose scopes
   (`memory.read/suggest/curate`, `control.read/write`) gate every API route
   and MCP tool. Authenticated identity overrides claimed actor names.
2. **Memory:** curated project docs, agent memory, imported material
   (recallable but ranked below curated), and a pending suggestion lane that
   is excluded from recall until promoted.
3. **Search/Recall:** BM25 over an mtime-invalidated on-disk chunk index;
   optional embeddings (any OpenAI-compatible endpoint) for hybrid and
   semantic modes, plus an opt-in temporal-decay knob. Always
   citation-backed and token-bounded. See [retrieval.md](retrieval.md).
4. **Control:** tasks, approvals, handoffs, and bus events in an append-only
   JSONL log with SQLite projection.
5. **Safety:** secret linting at import and suggest time, secret-shape
   redaction on recall/excerpt/bridge output, a pointer-based secret broker
   (`secret://` references resolved at access time, never stored — see
   [secret-broker.md](secret-broker.md)), forbidden-lane enforcement,
   hash-chained server audit log, and the safe MCP bridge with tool and
   method allowlists.

Every layer is reachable through CLI, HTTP, and MCP, so any harness (Hermes,
OpenClaw, Claude Desktop, Codex) gets identical governance — see
[harnesses.md](harnesses.md).

## Public cockpit journey — approved target architecture

This section specifies the complete approved target. The current local
composition described below implements part of it; metadata-scale tests and
proof-backed pairing do not establish native execution or full acceptance. The complete journey and
25 discovery/adapter research candidates, including primary sources for the fifteen
additional candidates, are in [product.md](product.md#public-self-hosted-journey--approved-target-not-shipped-capability).
Current governed API availability above does not prove native harness integration.

- **Deployment and surfaces:** public self-hosting on a personal desktop or VPS;
  web and terminal have full functional parity over shared authority, consent and
  lifecycle operations. Initial organizer setup can be skipped without selecting
  an organizer automatically or blocking later connection/creation.
- **Bounded discovery:** inspect only known installation/profile locations for
  limited metadata. Present each found profile and path with an individual
  Connect / Skip choice. Discovery never authorizes connection, workspace reads,
  identity import, recursive scans, migration or restart; nothing is preselected.
  Keep manual-location and remote-machine entry available. The 25-target catalog
  is research scope, not an implemented-support matrix.
- **Machine enrollment:** install locally on the remote machine or through the
  user's explicitly chosen SSH installation, then run `amc -confirm CODE` on that
  machine (target command contract). Bind an expiring, single-use pairing code to
  the intended enrollment and require separate main-instance confirmation before
  activating authority. Expired/reused codes or missing confirmation fail closed.
  Local-network and Tailscale membership provide transport, never authorization.
- **Native routing:** agents and workspaces stay on their original machines.
  Address machine + immutable agent/profile identity + exact native session;
  never reroute by display-name similarity, clone a workspace locally, or attach
  a different session as a fallback. Show Last 5 sessions, New, and All; support
  1,000+ sessions with paginated/searchable lightweight metadata, not eager
  transcript/workspace loading. Opening a session requires its own authorization.
- **Workspace creation:** New uses an existing workspace, chooses another, or
  creates one on the agent machine. A new agent workspace needs a unique nonempty
  name and distinct immutable identity. Require selected approved identity
  instruction copying or a clean isolated profile; copying instructions does not
  copy principal identity, memory, sessions or credentials. Never delete the
  source or silently overwrite a destination. Preserve native harness setup.
- **Separate authentication from identity:** authorized reuse of an existing
  provider login is independent of agent identity/profile creation. Resolve
  secrets through isolated credential handles, never memory or copied identity
  instructions. Future multi-account rotation is only a provider-supported
  possibility, not implemented functionality or a delivery promise.
- **Execution authority:** AMC-launched agents explicitly choose sandbox,
  ordinary host-user, or advanced root/admin execution with risk acknowledgment.
  Main organizer is the supreme AMC role: it can create/manage agents and
  exercise remote agents' root authority on enrolled, authorized machines where
  that OS authority actually exists. Enrollment and organizer assignment expose
  this power explicitly; skipping setup does not delegate it implicitly. Audit
  attributable delegation with organizer, executing agent, machine, exact session,
  authority, requested operation and outcome. This role does not expand external
  collaborator grants or grant unenrolled machines any authority.

## Local identity registration and connection selection

The attach-only local listener supports explicit human registration of a fresh AMC
agent/runtime pair for exact owner-observed native facts. It requires an already
registered matching machine, generates fresh IDs, grants no scopes or credentials,
and never edits existing actors or the native owner database. A separate explicit
binding confirmation is required before first-connected main-agent election.
Registration alone does not elect. Registry publication is serialized by the vault
lock. A signed enrollment journal commits before files are created; incomplete
publication is hidden from binding and recovered on reopening. Recovery removes
only exact journal-matching new files and fails closed on replacement conflicts.
Successful enrollment audit and journal completion commit together. This is
recoverable publication, not a filesystem/SQLite atomic-visibility guarantee for
unrelated readers that bypass this authority.

Main-agent selection covers the whole Cockpit. Changes are user-only under the
existing same-UID/operator capability trust boundary. Disconnect retains selection.
No root/organizer/provider privilege is created by that role. See
the local enrollment record (private engineering record) for the current local workflow and limitations.

## Current local onboarding and connection election

The real-local listener now composes the public onboarding services and Paperclip
setup UI under its existing browser capability and rechecked operator identity.
`amc setup --url` calls that same authority. An explicit discovery root enables
bounded metadata discovery; manual Hermes profile access requires an exact
registered machine/agent/runtime association and individual human confirmation.
Read-only metadata access is distinct from evidence of a running connection.
Optional pairing reuses the proof-backed machine-pairing state machine and separate
main-instance approval. Instruction preview and creation reuse the existing
allowlisted, digest-approved `AgentCreation` implementation. Metadata creation uses
an expiring, single-use consent record; no runtime execution authority is inferred.
See [public-onboarding-integration.md](public-onboarding-integration.md).

First election occurs in a successful validated connection event. Human binding
and first election share one SQLite rollback-journal transaction across the
binding and primary stores. Native organizer startup publishes its running state
and election in one transaction across the owner and primary stores. FULL
synchronization and DELETE journals are required; unsupported journal modes fail
closed. This supplies SQLite super-journal crash recovery, not a promise about
filesystems that cannot honor SQLite durability requirements.

Presence reads never invent historical connection order. A separate process-shared
observation lock serializes sampling/publication without holding the primary
SQLite write lock during owner socket I/O. This avoids an owner/primary lock
inversion. Primary registration, connection election and explicit human selection
retain a single serialized authority. Disconnect never clears selection or causes
failover. Legacy already-running connections without a recorded election are
visible but are not automatically assigned a fabricated historical priority.

Session pagination freezes the first-request collection and ordering for a bounded
TTL; it does not recalculate offset ordering on each page. Selection still checks
the exact current connection and session at dispatch. The candidate native mouse client now consumes these same metadata/consent APIs
behind a separately required artifact capability. The trusted legacy binary does
not have that capability. Full native runtime/execution parity remains an
acceptance blocker; source compilation is not native acceptance.

## Curated memory relations

Closed-schema batch suggestions may carry at most 20 `relations`. Each relation
names an existing parent with an explicit
`projects/<project>/notes/<file>.md` source path and has exactly one type:

- `updates`: the parent remains current while the suggestion is pending or
  refining. Promotion marks the parent `superseded`, records the replacing
  source path, and removes the parent from current recall/index results. The
  historical note stays at its original path for exact excerpt requests.
- `extends`: promotion adds the child while leaving the parent current.
- `derives`: records an inferred conclusion and is accepted only when the
  suggestion explicitly sets `inferred: true`.

The refiner and promotion boundary revalidate persisted relation metadata, so
imported or manually staged files cannot bypass the relation contract.

### Frontmatter invariants

- **JSON-in-YAML**: `tags`, `inferred`, and `relations` are persisted as a
  single-line JSON value inside the YAML frontmatter (e.g.
  `relations: [{"type": "updates", "parent_source_path": "projects/p/notes/x.md"}]`).
  Readers parse these fields with `json.loads` on the raw scalar — never a
  YAML collection. Writers must keep each field on one line with no embedded
  newlines, or the frontmatter block is rejected as invalid metadata.
- **Status quoting**: the indexer and promotion boundary strip one matching
  pair of YAML quotes before comparing `status` to `superseded`, so
  `status: "superseded"` is excluded from current-truth recall exactly like
  the bare value.
- **Promotion rollback safety**: promotion stages the target and every parent
  without opening curated parents for writing. A durable journal under
  `.arvyx/promotions/` retains exact original bytes (including line endings),
  modes and staged inode/content identities before publication. Rendering and
  backup share the same pending-byte snapshot; a changed pending version is
  rejected before publication. Parent status is revalidated from the same original
  byte snapshot used for staging and backup. New targets require absence and use exclusive
  link publication so a concurrently created target cannot be overwritten. Pending removal
  is last; failures after its removal restore it from the durable original.
  Rollback atomically replaces only exact files published by this transaction.
  Durable restoration identities make interrupted rollback repeatable even after
  restored files acquire new inodes. Each restoration attempt uses a fresh stage,
  so partial staging failures can be retried from the separate original backup.
  The commit marker is staged before atomic publication; a partial marker write
  cannot turn an incomplete rollback into a committed transaction. A failed commit
  acknowledgement revokes the marker before rollback; if revocation fails, the
  complete journal is retained and rollback does not start.
  Replacement conflicts and rollback I/O failures retain the journal and originals
  for recovery; the next public promotion recovers before validating relations.
  A conflict requires human reconciliation rather than overwriting unrelated bytes.
- **External-edit TOCTOU**: staged originals are checked against their captured
  identities before publication, and rollback rechecks identities after staging
  restoration. Ungoverned same-UID writers can still race between a final check
  and an atomic filesystem operation; there is no mandatory filesystem-wide CAS.
  Governed mutations retain the vault lock. The journal is recoverable publication,
  not a cross-file atomic snapshot for readers bypassing this authority.

## Exact configured Hermes resume

Configured `NativeRuntime.plan` and history launch share `HermesProfile`. They bind
one canonical `PROFILE/state.db`, capture profile-directory/database identities,
reject changed or symlinked identities, require one exact existing session row,
and refuse recorded workspace mismatches and compression-parent redirects before
process creation. The launch environment sets both HOME and HERMES_HOME to the
explicit profile. No credential files are read or copied by this resolver.
Tests of actual `LocalCockpit.start_native` replace the process boundary with a
recorder; they do not prove provider or native runtime execution.

Frontend creation and attachment share the historical mouse artifact policy and
exact binding digest check. Older non-mouse creation pins are no longer admitted.
A new local build's provenance does not authorize its digest: the retained
unreviewed binary remains rejected by both routes. Byte verification and mocked
process-boundary tests do not authorize or establish native runtime acceptance.

## External-agent delegation — approved target, implementation in progress

External agents (including cloud and local Grok Bot, each a separate principal)
receive no ambient squad membership. Default deny applies across HTTP, MCP,
search, file access, events and task APIs. Tailscale connectivity grants no authority.

A grant names its recipient, issuer, explicit resources, permitted operations,
creation/expiry timestamps, revocation state and provenance. Resources may be one
prompt, task, SKILL.md, selected artifacts or an entire named project workspace.
Example: read-only access to a named workspace for 24 hours for review. Reading
never implies write, shell execution, delegation or access to adjacent projects.

Only the owner and explicitly authorized squad issuers may grant access. Issuers need
both resource authority and separate export/delegation authority; their ordinary
read permission is insufficient. Child grants cannot expand scope, operations or
expiry. Secret/private-family exclusions cannot be silently overridden by a broad
workspace grant. Unavailable/excluded content must be reported as incomplete review.

Enforce grants server-side on every request, including exact-ID lookups, list,
search, excerpts, downloads, subscriptions and result submission. Use bounded
workspace snapshots/manifests with content hashes as the initial export boundary;
reject traversal, symlink escape and out-of-root access. Never grant direct host
filesystem or broad squad tokens. Authentication alone cannot enumerate resources.

Check expiry and revocation at access time. Record grant creation, access decisions,
revocation and scoped deliverables in auditable records. Authorized squad observers
may inspect delegated work, submitted progress and artifacts; external agents may
inspect only explicitly assigned work. Do not expose private model reasoning or
claim visibility into unrelated personal Grok activity. Revocation stops future
access; already disclosed bytes cannot be recalled or guaranteed erased.

MCP task collaboration and native terminal/desktop attachment are distinct abilities.
A registered external agent must not be labeled live without current evidence;
unsupported interactive access remains unavailable rather than simulated.

## Non-Goals

- It is not an agent framework.
- It is not a hosted SaaS-first product.
- It is not a raw Obsidian wiki clone.
- It is not a transcript database.


## Reviewed workspace and delegation chains

Workspace preparation shares exact `AgentSessions` targets, configured directory
roots and expiring single-use SQLite consent across web/text/native clients.
Preview and commit compare root/parent/leaf identities; directory effects are
recorded as ambiguous before mutation. No native ID is synthesized. Metadata,
sandbox, host and root remain distinct boundaries; a prepared directory confers
no execution privileges. See public-onboarding-integration.md for the current
routes and unfulfilled New/runtime requirements.

Optional organizer persistence preserves the existing policy without deriving
roles from main-agent presentation or transport enrollment. A process-shared file
guard serializes all governed policy instances, with SQLite FULL synchronization
and ordered decision records. Decision checkpoints persist before endpoint effects. The sender releases its
guard before transport; the final owner retains either the shared local guard or
an authenticated durable remote permit through fork, acknowledgment and publication. Local request, remote request and
remote-link ledgers retain attribution and ambiguity independently; no distributed
exactly-once or cross-file atomicity is claimed. Missing roles/endpoints, stale
consent, changed endpoint incarnations and revocation fail closed.

The native overlay is maintained as frontends/arvyx/amc_sessions.rs and
amc_session_rpc.rs, copied by the explicit offline builder after the pinned base
patch. The server-owned native runtime protocol is unchanged. The client uses the
existing human-authenticated onboarding HTTP API and only presentation state;
there is no network I/O in render. Historical binaries/receipts remain immutable,
and candidate artifacts do not enroll themselves into the shared trust policy.

Current engineering interfaces and their remaining acceptance criteria are in
the pass-2 engineering record (private, not exported).


## Pass-3 integrated consumers

The authenticated onboarding extension now owns `NativeLifecycle`, using the same
exact metadata target and canonical consent rows as workspace/profile actions.
`OwnerProducer`/`SocketOwnerProducer` call the existing private owner. The owner
implements lifecycle, effective execution policy, immutable native binding,
revocation and live lease checks. `NativePresentation` adds a separately admitted
native artifact/pane producer; the web, text and Rust clients share reviewed routes.
The leaf executor has its own authentication, fixed action grammar and durable
attempt fence. It does not receive arbitrary shell commands from organizers.

Compatibility views migrate eight journals into the shared attempt schema within
each existing trust domain; they do not merge organizer, operator or external roles.
An explicit offline topology coordinator captures all declared stores under derived
owner/state/vault locks and SQLite writer fences. Restored state remains quarantined
and cannot manufacture bearer or incarnation authority. Native restart leases use a
verified new kernel boot and retain their original expiry, with no input replay.

Independent external issuer authority can be mounted in the real-local handler.
Reviewed governed-memory artifacts, grant-bound manifest pages and file chunks share
the isolated MCP/export policy; ambient recall and squad context remain outside it.
Source-level native provisioning still depends on separately admitted artifact bytes
and platform support. Full details and honest runtime limits are in
the pass-3 engineering record (private, not exported).


## Completion-fix4 integrated contracts

This source repair is private and awaits the parent's transport exercise, source
freeze and independent exact-source review. Original REQUEST_CHANGES verdicts
remain unchanged. A release still requires the exact-tree candidate verdict (docs/release-gate.md).

A reviewed Hermes connection retains its canonical profile path, original profile
directory and database identities in `onboarding_connection_pins`. The leaf executor
requires the exact agent and serialized target pin on construction, request admission
and final effect admission. Its durable lease includes the original snapshot.
Legacy unpinned connections and changed leases require explicit review/provisioning;
migration and main-agent presentation grant no authority.

The legacy pilot `serve --execution-policy /absolute/private-policy.json` forwards
the owner's explicitly configured `ExecutionPolicy`. Omission denies launches.
`start SID`, `new NAME --title TEXT`, and `native resume SID` require an explicit
`--environment sandbox|host|root`. Root also requires `--root-acknowledged` for that
operation and a separately root-authorizing owner policy with effective root.
Host requires the configured unprivileged effective UID. Sandbox requires its
explicit installed launcher and kernel sealing. Provider sandbox admission remains
unsupported and refused; there is no host fallback. `--allow-provider` remains a
separate provider-launch gate. Synthetic acceptance scripts with shell launches
require the explicit `AMC_EXECUTION_POLICY` file; running those scripts is a separate
acceptance action and was not performed in this repair.

Local source-created sessions retain their archive rows and show attention when
shared archive attribution is unavailable. Such exports remain explicitly refused.
Ordinary work capture continues through its existing authenticated delivery path.
Restore replay requires both receipt and source-directory durability barriers and
retires only its owned witness; arbitrary hardlinks remain ineligible for export.

Changing a reviewed workspace/document/memory manifest requires a new grant after
explicit review. Existing grants remain bound to their original manifest across
metadata, content, downloads, pagination and MCP routes. An independently authorized
same-task observer can read submit-only results without giving the recipient read
permission. A lost-acknowledgement test forwards the exact reviewed snapshot and
fails after publication, retaining ambiguity and prohibiting replay.

Execution-managed direct assignment notifications, including queued historical
ones, carry informational response contracts and accept delivery receipts only.
Only the canonical execution wake binds actionable execution/attempt authority.
Telemetry and alert dedupe use the exact state namespace. The probe/canary unit
source provisions and writes only that namespace; no unit was deployed or restarted.

The known maintained scanner occurrences were reconciled with path-and-text-bound
synthetic fingerprints and a noncredential variable-name clarification. Historical
receipts and generated outputs were preserved. Real private denylist, final indexed
release inventory and separately authorized CI remain missing prerequisites;
no complete source scan or release acceptance is claimed. Descriptors do not supply
missing native protocol, admitted artifact, provider or installed-runtime evidence.


## Pass 5 authority, archive and publication contracts

Fully rendered UTF-8 memory must fit the shared 1,048,576-byte reader/writer bound
before publication, including metadata and superseded parents. Fixed-prefix UUID
staging supports filesystem-limit ASCII/UTF-8 basenames without changing legacy
manifest, original inode/hash or rollback authority. Mutation key admission rejects
literal secret shapes before journals or domain effects. A journal's first claim
binds the exact configured vault/state; populated unbound history requires explicit
reconciliation and is never adopted by an ordinary retry.

Original consent survives snapshot validation, transaction waits, metadata reads
and owner RPCs. Profile creation rechecks before mkdir and final publication.
Trusted injected adapters/connectors must accept and invoke `publication_guard`
after their own blocking preparation and immediately before their final effect.
Pairing decisions consume the exact stable claim ID and reviewed snapshot in the
transaction; ambiguity remains a refusal. Selected grant operations are advertised,
issued and read back exactly, and submission authority requires an explicit task.

Capture and native imports persist versioned, bounded delimiter syntax with no
body tails. Unversioned or invalid contexts, including legacy False clearance,
are quarantined without advancing cursors or changing retained archive rows.
Explicit digest-bound recovery retains the old context and history. Capture needs
a stopped/ended process with no live or unresolved cleanup ownership and a separate
clean-stream attestation. Native recovery rescans from zero in a new event namespace.
Atomic cursor provenance distinguishes a newly selected conversation from unknown
legacy session-wide cursor state. Safe new versioned streams remain deliverable.

Offload binds path/device/inode and verifies the complete durable chain before
releasing local rows. Confirmed exact-head adoption/relocation is exposed only by
the private owner facade/RPC. Explicit bound-chain copying retains the source.
Unresolved restore-pointer durability or teardown leaves production admission
blocked and both volumes retained; blocked restart differs from attempted restart
failure. A committed candidate is not automatically rolled back after health failure.

Independent source/receiver policies use the authenticated final-effect permit
protocol in [remote-effect-fence.md](remote-effect-fence.md). Unsettled permits survive
timeouts and expiry and prevent completed-revocation claims. The original attempt,
actor, root acknowledgment, expiry and exact receiver incarnation remain unchanged.
Shared-file guards remain supported. Focused tests with process recorders establish
source behavior; parent-host transports, rendered synthetic browser QA, TLS/physical
hosts, native/provider/container qualification and exact-source independent review
remain distinct evidence boundaries. A release still requires the exact-tree candidate verdict (docs/release-gate.md).

## Pass-5 integration boundaries

Authenticated independent-host effect permits retain original consent, attempt,
expiry, actor, exact receiver and independent mode/root policy through final owner
admission. Unsettled permits block completed revocation until authenticated
settlement; sender timeouts are not cancellation. See
[remote-effect-fence.md](remote-effect-fence.md).

Sandbox workspace mounts require a separately provisioned byte-pinned launcher
implementing `arvyx-directory-fd-v1`. Its `--bind-fd FD DEST` extension must consume
the inherited directory descriptor directly, keep it through mount admission,
and close it before the untrusted command. Ordinary bubblewrap does not advertise
this extension and is refused; neither cwd nor a canonicalized pathname is proof
of the reviewed incarnation. The owner passes the held FD through actual exec.
Kernel sealing and supported installed launcher acceptance remain prerequisites.
No launcher was installed or executed in this repair. Host/root flows retain
their own effective UID and explicit policy gates.

External expiry, observer membership, exact claims and consent boundaries are
documented in [public-onboarding-integration.md](public-onboarding-integration.md).
Bounded offload verification and safe legacy-context recovery are documented in
the local slice record (private, not exported); import/composition witness handling
is documented in [importers.md](importers.md).
