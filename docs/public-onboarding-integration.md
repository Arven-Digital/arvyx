# Public onboarding integration

## Current local composition

`arvyx web` serves the bundled Paperclip UI and `/api/public-onboarding/` from
`cockpit_local.build_local_server`. The browser uses the existing presentation
capability; every onboarding operation also rechecks the server-held operator
identity. No operator secret is returned to the browser. Host, mutation Origin,
JSON framing, duplicate fields and request size are checked. Both onboarding and
the local listener bound worker count to 16 and idle sockets to three seconds.

The listener attaches to an explicitly configured existing owner. This code does
not start, restart, send input to, or migrate that owner. Local identity registration
and human binding remain separate confirmations. Metadata-only profile access
never elects a live main agent.

Start through the installed package with an existing-owner connection file and
private capability delivery, adding `--discovery-home /explicit/home` to enable
bounded known-location discovery. Without that explicit option discovery reports
incomplete with `discovery_root_not_configured`; it does not scan an ambient home.
The separate fixture composition remains labelled `fixture_only`.

## Available operations

- Discovery reports truncation and unreadable locations. Each candidate retains
  its safe home-relative location and an honest adapter-availability reason.
- Manual Hermes metadata connection requires an immutable registered agent ID,
  matching machine/runtime registration, explicit profile directory and separate
  confirmation. It reads the selected profile's existing SQLite session metadata,
  preserves the agent/profile association, and creates a fresh connection
  incarnation on reconnect. This is human-approved metadata access, not proof of
  a running agent. Other harnesses remain unavailable without a compatible adapter.
- Last 5, All and title/ID search share `AgentSessions` and `HermesHistory`.
  All freezes membership, order and displayed metadata on its first request for
  120 seconds. At most 64 collections are retained; expiry/eviction requires a
  reload. Activity cannot shift offsets. Selection revalidates current existence
  and the exact connection; it returns metadata, not a running terminal attachment.
- Clean profile creation and reviewed instruction copying share `AgentCreation`.
  Only its closed instruction allowlist can be previewed from an explicitly
  connected source. Preview shows contents and SHA-256; changed files are rejected.
  Prepare records the exact name, harness, metadata environment and selected hashes.
  Commit requires its exact consent ID/digest within five minutes and cannot replay
  an attempted operation. The durable attempt is marked ambiguous before creation,
  following the pattern used by `cockpit_consent`; ambiguous results require human
  reconciliation. The real-local `/agents/create` fallback now returns 409; all
  real-local creation requires reviewed prepare/commit consent. Only the explicitly
  labelled fixture retains direct clean creation.
- Optional `--enable-pairing` composes the existing `PairingTransport` and
  `PairingStore`, requiring the approved cryptography extra. The authenticated main
  UI/CLI issues an expiring code, lists proof-backed claims and separately approves
  or denies the exact fingerprint. Remote `amc -confirm CODE --url LOOPBACK_URL
  --name NAME` uses `/challenge` and `/prove`; these endpoints grant no main-side
  administrative capability. Use an independently approved SSH tunnel between
  machines. Pairing does not enable remote task, workspace or root execution.

`amc setup --url http://127.0.0.1:PORT` is the terminal client of these same services.
It prompts privately for the existing browser capability and offers discovery,
manual connection, instruction review/creation, session metadata and pairing.
`amc history --hermes-home /explicit/profile` exposes read-only history separately;
it supplies no launch authorization. The original standalone `onboard`/`status`
commands retain their own explicitly selected state directory.

## Verification and remaining product requirements

Current evidence is in the authorized implementation pass's `implementation-01`
artifact directory, not an ephemeral URL or a running-process claim. It includes
RED/GREEN service regressions, byte-stream tests of the actual HTTP handlers,
disposable Hermes-format SQLite collections with 1,205 sessions, proof-backed
pairing, frontend tests/typecheck/build and packaging receipts. Socket binding in
the CLI sandbox was denied; byte-stream handler tests were not a substitute for
network acceptance. The parent subsequently verified installed disposable-owner
IPC/HTTP and all seven exact asset hashes outside that sandbox, with zero native
processes started (`parent-verification/installed-http-parent-execution.json`).
Those results supplement the retained blocked runs; they do not prove browser or
native runtime acceptance. The dependency continuation preserves the old evidence
and creates separate fixed-backend package artifacts.

The complete product contract remains open. No approved sandbox/host/root harness executor, new provider session, or provider
authentication is supplied by the default listener. These remain full-contract
requirements. The candidate native client now calls shared metadata/consent APIs;
its new capability remains unapproved and cannot run through the trusted legacy
binary gate. Compilation and fixture RPC tests do not establish native acceptance. A local source build does not prove clean-machine
native installation or actual native runtime behavior. Public release still needs
strict tracked-boundary, security, dependency/license and independent review gates.


## Fix-03 New workspace preparation

An operator may pass repeatable `--workspace-root /absolute/directory` options to
`arvyx web`. Those explicit roots are the only filesystem authority granted to
workspace preparation. With none configured, the UI advertises no preparation
capability. Browser paths cannot enable a root or an executor.

The web **Prepare New session** panel and `amc setup` session menu use the same
`sessions/workspaces`, `sessions/prepare`, and `sessions/commit` routes. Choose a
session's recorded current workspace, an existing folder relative to an approved
root, or a new private folder. Each preview binds the exact target incarnation,
root/parent/destination identities and requested path. Commit requires the exact
expiring, single-use digest and fresh confirmation. Descriptor traversal rejects
symlinks and traversal. Current workspace may equal its authorized root. Changes
require another review. Existing folders are never rewritten; new folders are
created exclusively with mode 0700.

The service persists an ambiguous attempt before creation. An I/O failure or
process death after the effect cannot replay it; the private journal supports
human reconciliation. A completed result is `workspace_ready`, with
`native_session_created:false` and `execution:false`. It never invents a native
session ID. This is a functional workspace preparation chain, not completion of
New native runtime execution. Sandbox/host/root requests are refused without an
approved executor, and metadata preparation grants no process permissions.

## Candidate native shared client

`amc terminal --url http://127.0.0.1:PORT` privately requests the existing setup
capability and requires the `onboarding-v1` native artifact capability. The current
historical mouse pin lacks it and is refused; a new source build is not enrolled
by its receipt or digest. No trust pin was advanced in this round.

The source client obtains destinations from the same authenticated `targets`
route, requires explicit destination selection, and requests Last 5 or searchable
All in 20-record pages using the shared snapshot cursor. Selection revalidates the
exact route at the service. Metadata results do not focus a guessed pane, inject
input, resume a provider or fabricate reachability. New workspace controls use the
same reviewed preparation chain. Page errors clear the client result instead of
falling back to startup metadata. Network operations occur only on explicit input,
with bounded literal-loopback HTTP, no redirects, bounded request/response sizes
and deadlines. Rendering performs no network or workspace I/O.

The legacy attach-only mode retains existing native pane focus. The candidate's
history mode remains metadata selection until an approved exact runtime adapter
can prove attachment/launch. Native onboarding for instruction copying, pairing,
agent creation and complete execution parity still requires substantive integration
and acceptance; the existing shared text/web clients do not stand in for it.

## Durable organizer and explicit remote dispatch

`OrganizerAuthority(database=PRIVATE_PATH)` persists its existing trusted identity,
organizer, machine and executor attestations and ordered decisions. The no-database
mode remains isolated. Reopened authorities create local handles; a trusted
credential resolver must bind authentication to them. A submitted principal name,
main-agent election, pairing result or root availability is never authentication.
Only existing create/manage/invoke_root policy decisions are implemented.

Trusted composition may inject `DelegationService` into `LocalOnboarding.delegations`.
The default listener does not configure it; `local_composition` accepts an explicit
trusted `delegation_config` and uses `delegation_runtime.load_delegations` to load
existing authority and closed leaf/remote endpoints. This is composition, not
installation or provider provisioning. Exact machine/agent/session endpoint
bindings must be supplied by the operator's existing authority. Prepare/commit
bind operation, goal, execution environment and endpoint incarnation. Root needs
fresh risk acknowledgement as well as existing organizer/enrolled-executor root
attestation. Replaced endpoints or service restarts invalidate prepared consent.
Decisions commit durably before effects, under a process-shared policy guard;
revocation and dispatch serialize. The attempt ledger commits ambiguity before
calling an endpoint. Lost replies never trigger an automatic retry. Allowed and
denied decisions remain auditable even if a request transaction rolls back.

`RemoteDelegationEndpoint` uses the existing literal-loopback authenticated client
through an independently approved tunnel, with a two-second total request deadline. It
starts no SSH process and derives no execution authority from pairing. It checks
the exact remote machine and the independently authenticated remote organizer,
forwards the original sealed attempt to `delegations/fenced-execute`, rather than
creating a new remote review. It durably records local-to-remote request IDs before
forwarding. `recover` queries the exact retained attempt through
`delegations/result`; uncertainty never authorizes replay.
Both sides must already have explicit roles, credentials and exact executor
bindings. No credential, role, provider or OS privilege is provisioned by transport.

The verified effect in this round is an explicitly disposable fixture file. Real
sandbox isolation, ordinary host/root harness execution and live remote/provider
acceptance remain required; fixture success does not approve them. Only closed deadline-bound executor transports are admitted under the policy guard; arbitrary callbacks are refused. See the pass-2 source contract for current boundaries.

## Further engineering continuation

Pass-2 interfaces and evidence (private engineering record, not exported) supersede the older
generic Boolean-only confirmation and arbitrary-endpoint descriptions. They add
durable generic review, direct discovered Hermes metadata connection, separate
host/sandbox attestations, and selected prompt/skill/artifact MCP exports. Native
New, effective OS executors, remote installation and full acceptance remain open.


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


## Pass 5 exact authority and final publication

`delegations/prepare` returns the exact `execution_binding` for review along with
its existing digest/expiry. `delegations/fence` advertises a shared fence and, only
when explicitly provisioned, the remote coordinator ID and exact receiver binding.
`delegations/fenced-execute` accepts the original closed ticket/attempt/expiry;
it never starts another review. The trusted `delegation_config` factory parameter
and private configuration files are not request fields. See remote-effect-fence.md.

Reviewed agent creation checks original consent after validation/SQLite admission,
before mkdir and before metadata publication. Session selection checks after
metadata reads. Injected mutating connectors/adapters receive `publication_guard`
and must invoke it at final publication after their own waits. Pairing snapshot and
claim ID comparison remain transactional. Grant issuance/readback must match the
selected advertised operations exactly; a non-task resource cannot receive submit.
The real React native component remounts on exact target/owner/attachment identity
and discards late responses. Persisted owner sessions use native/sessions and fresh
reviewed native/open. The explicitly synthetic component QA page is separate from
production presentation and has only in-memory callbacks.

## Pass-5 final publication and external authority

Workspace commit carries its original absolute consent through validation, the
transaction wait, mkdir and completion. Blocking injected connectors/adapters must
call the supplied publication guard at their own final effect. Terminal pairing
selects the exact pending claim ID, fingerprint, name and expiry; a fingerprint
alone is insufficient. Native pane bridges carry the original expiry to the
receiving owner's final attach and cannot renew it.

Issuer-selected expiry is sent as `expires_at`, must be future and at most 24
hours from the server's current clock, and must match authoritative readback
exactly. Operations and reviewed manifests remain exact. Production export
configuration may include an `observers` list containing only separately
provisioned observer principals. Omission grants no observer membership.

History New, named-profile New and cold resume require an explicit private
`--execution-policy`, `--execution-mode` and, for root,
`--root-risk-acknowledged`, in addition to existing launch/default-profile consent.
The same effective UID/root policy is checked again after profile reservation;
workspace descriptors remain held through dispatch. Sandbox provider profiles
remain unavailable without a separately supported adapter; no host fallback occurs.

The explicit metadata snapshot route is
`GET /external/grants/<exact-id>/audit?limit=50&cursor=...`. It is grant/principal
bound and reauthorizes every page. Original issuers need current whole-scope export
authority; configured observers also need a live whole-grant lifecycle. Recipients
and foreign issuers refuse. Legacy unindexed audit history remains retained and
is not guessed into the feed. The connected issuer panel loads snapshots only on
an explicit click; it clears failed/stale responses and does not claim live
subscriptions or complete pre-migration coverage. Details are in
the external onboarding ledger record (private, not exported).


## Focus75 agent07: exact remaining acceptance gaps

This offline source pass does not close REV-0107, REV-0108, REV-0111, REV-0112
or REV-0114. It corrects stale composition descriptions; no product runtime,
provider, credential, trust-pin or deployment changes were performed.

- **REV-0107:** Pairing proves possession and enrolls an identity only. The
  `/challenge` and `/prove` listener does not install a remote service, resolve
  credentials, establish isolation or create an executor binding. A separately
  approved installation and exact remote-owner execution journey is still needed.
- **REV-0108:** `AgentCreation.create` publishes a private instruction directory
  and immutable `metadata_only` record. An opaque `provider_auth_handle` is not
  resolved. `local_composition` installs an empty `AgentSessions` adapter map;
  profile creation does not configure or launch a harness. Secure credential
  resolution, explicit launch consent and verified exact runtime connection remain.
- **REV-0111:** Explicit delegation configuration exists, but is not a remote
  installer or a source of executor roles. Existing durable policy, exact leaf
  endpoints and (for independent remote authority) coordinator/receiver binding
  must be provisioned separately. End-to-end host/sandbox/root effects and
  revocation/lost-reply acceptance remain unperformed. Do not replace these with
  permissive callbacks, role auto-enrollment or a root shell.
- **REV-0112:** The older assertion that real-local external integration is
  entirely disabled is stale: `cockpit_local.build_local_server` accepts
  `external_config`, `external_presentation.load_presentation` composes an
  existing export authority, and `main.tsx` renders `ExternalAuthorityPanel` in
  real-local mode. The browser proxy deliberately exposes issuer configuration,
  grant issue/readback, audit and revoke only. Recipient resources/MCP remain on
  the separately authenticated ExternalAPI; mounting the shared MCP router here
  would violate the boundary. Prompt/skill/artifact export primitives do not
  establish complete product authoring units or installed collaborator acceptance.
- **REV-0114:** Two exact digests are admitted: the historical `mouse-existing`
  artifact and the reproducibly built onboarding-v1 artifact whose receipt is
  `frontends/arvyx/receipts/onboarding-v1-linux-x86_64.json`. `verify_native_bytes`
  checks the requested capability against the matched digest, so the historical
  bytes still cannot open onboarding-v1. Runtime acceptance of the chooser on a
  real terminal is not claimed by the receipt.

### Unexecuted acceptance scenarios

All scenarios below are NOT_EXECUTED and require separate authorization; they
are acceptance specifications, not passing tests or implementation evidence.

1. Pair a disposable remote host; verify approval alone starts no process and
   grants no filesystem/root access. Separately install an approved service and
   exercise exact owner identity, isolation and revocation.
2. Create a clean and reviewed-copy profile; verify no launch or auth resolution
   occurs. Then exercise the separately implemented credential-resolution and
   explicit-launch journey, including changed instruction hashes and refused consent.
3. Provision exact sender/receiver authority and executor identities; exercise
   host/sandbox/root admission, revocation at final effect and lost-reply
   reconciliation without replay across independent hosts.
4. Exercise configured and unconfigured real-local issuer presentation; verify
   recipient credentials cannot access shared memory/MCP, scoped export MCP
   refuses revoked/changed manifests, and complete product units work in the
   installed collaboration journey. Fixture UI is not this acceptance.
5. Verify old bytes refuse onboarding-v1 and candidate bytes remain refused until
   independently approved. After authorized approval, exercise exact installed
   artifact onboarding; a build receipt alone must never admit it.
