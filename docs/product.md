# AMC product contract

Integration checkpoint (2026-10-29): reviewed delegation now carries a distinct
receiving-leaf incarnation through preparation, ticket, forwarding and final
admission. Logical endpoint equality is insufficient after reprovisioning. This
source contract does not qualify independent-host execution or settle running-
effect revocation; a timeout never means cancellation. Explicit local human
approval remains authoritative, without an invented second remote-human gesture.
Retained-generation offload storage authority remains unresolved (SUP-04/L4,
REV-0512/0544). Bounded verification progress is not safe history pruning or a
completed capacity-recovery product. Tests, builds, CI and native/runtime
acceptance for the integrated bytes remain unperformed; a release still requires
the exact-tree candidate verdict and the maintainer's approval.

Status: approved direction; external-agent delegation is under implementation,
not an available or security-approved product claim. Existing product context:
the control-plane product brief (private, not exported).

## Native product experience

Use the actual Arvyx terminal frontend and Paperclip web components on AMC authority.
Preserve native sessions, mouse, tabs, scroll and resize. Show useful agent/task
views rather than raw debug JSON. Use supplied Arvyx brand assets. Synthetic demos
must be explicit; registered identity must not imply verified live reachability.

## Public self-hosted journey — approved target, not shipped capability

AMC is a public self-hosted product for a personal desktop or a VPS, not a
squad-specific setup. Web and terminal must have full functional parity for
onboarding, discovery, pairing, agent/workspace management and session navigation,
using the same authority and consent records. Organizer setup may be skipped:
explore first, then connect or create agents later. Do not auto-select an organizer.

Current local implementation composes authenticated web setup and `amc setup`
over shared onboarding services: bounded discovery with an explicit root, manual
Hermes metadata access for a registered identity, per-profile history, reviewed
instruction copying, clean metadata profiles and optional proof-backed pairing.
The next candidate also adds reviewed workspace preparation, a shared native
metadata client, and optional durable organizer/remote request dispatch. These
remain bounded implementation evidence: preparation does not create a provider
session, and new native capability/runtime approval remains outstanding.
Metadata access is not verified live reachability or runtime execution. Native
chooser parity, New, approved sandbox/host/root execution, remote runtime control
and clean-machine native provisioning remain required, unfulfilled acceptance
criteria. See [public-onboarding-integration.md](public-onboarding-integration.md).

### Discover, then connect each profile

Discovery is limited to metadata at known harness installation/profile locations.
Show the harness, machine, profile and location; ask **Connect / Skip** individually
for every found profile. Finding a profile is not consent to connect it, read its
workspace, import identity, or restart/migrate its runtime. No recursive home or
workspace scan and no preselected profiles. Offer manual location and remote-machine
entry when bounded discovery finds nothing or the user wants another location.

The following **25 discovery/adapter research targets** are a candidate inventory,
not 25 implemented integrations. A product's existence does not establish compatible
profile discovery, session APIs, native attachment or AMC support. Verify each
adapter independently and expose unsupported capabilities as unavailable. The first
ten are required named targets; the remaining fifteen link primary project/vendor
sources consulted for candidate discovery (redirected sources use their current
canonical destinations).

| # | Target | Primary source / status |
| --- | --- | --- |
| 1 | Hermes | Required target; adapter capabilities must be verified |
| 2 | OpenClaw | Required target; adapter capabilities must be verified |
| 3 | Pi | Required target; adapter capabilities must be verified |
| 4 | Claude Code | Required target; adapter capabilities must be verified |
| 5 | Codex | Required target; adapter capabilities must be verified |
| 6 | Cursor | Required target; adapter capabilities must be verified |
| 7 | VSCode-Copilot | Required target; adapter capabilities must be verified |
| 8 | OpenCode | Required target; adapter capabilities must be verified |
| 9 | Gemini | Required target; adapter capabilities must be verified |
| 10 | Cline | Required target; adapter capabilities must be verified |
| 11 | Aider | [Project](https://github.com/Aider-AI/aider); research candidate |
| 12 | Roo Code | [Project](https://github.com/RooCodeInc/Roo-Code); research candidate |
| 13 | Continue | [Project](https://github.com/continuedev/continue); research candidate |
| 14 | OpenHands | [Project](https://github.com/OpenHands/OpenHands); research candidate |
| 15 | SWE-agent | [Project](https://github.com/SWE-agent/SWE-agent); research candidate |
| 16 | Goose | [Project](https://github.com/aaif-goose/goose); research candidate |
| 17 | Tabby | [Project](https://github.com/TabbyML/tabby); research candidate |
| 18 | Plandex | [Project](https://github.com/plandex-ai/plandex); research candidate |
| 19 | Qwen Code | [Project](https://github.com/QwenLM/qwen-code); research candidate |
| 20 | Amazon Q Developer CLI | [Project](https://github.com/aws/amazon-q-developer-cli); research candidate |
| 21 | Zed | [Project](https://github.com/zed-industries/zed); research candidate |
| 22 | Kilo Code | [Project](https://github.com/Kilo-Org/kilocode); research candidate |
| 23 | Refact | [Project](https://github.com/smallcloudai/refact); research candidate |
| 24 | Amp | [Vendor](https://ampcode.com/); research candidate |
| 25 | Devin Desktop | [Vendor](https://devin.ai/desktop); research candidate |

The bounded discovery catalog now marks these exact 25 families with
`product_target:true` and retains eight additional historical metadata families
under their original IDs (33 entries total). VS Code editor settings remain a
separate observation from VSCode-Copilot; they do not prove Copilot presence.
The eight newly represented product references have no guessed probe paths and
remain unavailable for detection until verified. The original 25-family fetched
research receipt is preserved as historical evidence; it does not attest these
additional references. This catalog correction supplies no missing runtime
adapter, native attachment, or execution authority.

### Pair a remote machine

The user installs AMC locally on that machine, or explicitly chooses installation
via their own SSH access, then runs `amc -confirm CODE` there. The command uses the existing proof-backed pairing transport when the main
listener explicitly enables pairing; it does not provide remote execution. Pairing requires an
expiring, single-use code and a separate confirmation on the main AMC instance
showing the intended machine. Code expiry, reuse, or absent main confirmation must
not enroll a machine. Local-network or Tailscale connectivity grants no authority.

### Open the exact native session

Connected agents remain on their original machines and in their original
workspaces. Route to the exact machine, immutable agent/profile identity and native
session; never substitute a similar name, another session or a local clone.
Show **Last 5 sessions**, **New**, and **All**. All supports 1,000+ sessions through
lightweight metadata, pagination and search, without loading every transcript or
workspace. Load authorized session content only when the user opens that session.
New can use an existing workspace, choose another workspace, or create a new one
on the agent's machine.

### Create without replacing identity

Creating a new agent workspace requires a unique, nonempty name, a distinct immutable
identity, and an explicit choice: copy selected, approved identity instructions or
start with a clean isolated profile. Show what instructions will be copied; copying
instructions is not cloning the source identity, credentials, memory or sessions.
Never delete the source, silently overwrite a destination, or reuse its identity.
An existing provider login may be reused separately with authorization where the
provider supports it; provider authentication is not agent identity. No secrets go
into memory, identity instructions or copied workspace material.

Each AMC-launched agent explicitly selects sandbox, ordinary host-user execution,
or advanced root/admin execution with risk acknowledgment; AMC installation alone
does not enable root. Fresh harness setup follows its native setup flow.

### Main organizer and authority

The main organizer is explicitly the **supreme AMC role**, not merely a reader or
task dispatcher. On enrolled, authorized machines it can create/manage agents and
exercise remote agents' authorized root authority. This does not manufacture OS
privileges: root must actually be available and authorized on the enrolled machine.
The user's explicit local approval is authoritative for that exact remote target;
no second remote-human approval is required. The receiving authority must verify
the original authenticated local-human approval bound to the exact remote target,
command/payload digest, workspace/owner incarnation, privilege, expiry and single-use
attempt. This is not an environment Boolean or permission to auto-enroll, borrow
credentials or expand scope. Cross-host approval transfer and final admission/
revocation remain unimplemented capabilities; local approval does not waive them.
Delegation is attributable and audited, recording the initiating organizer, delegated
agent, machine, session, authority and action/result. Enrollment and organizer
assignment must make this authority explicit. Skipping organizer setup grants none
of it to an automatically chosen agent. External collaborators remain limited to
their explicit grants; organizer power is not ambient external-agent access.

Future multi-account rotation is only a possible provider-supported direction,
using isolated credential handles and respecting provider rules. It is not an
implemented feature, a delivery promise, or a way to bypass provider restrictions.

## Connected main agent — current local contract

The first explicitly identity-bound connected agent becomes the main agent for the
whole Cockpit area, not a project or workspace filter. Only the user can change
this selection through the human control surface. Connection-event election is durable before any primary read. Presence reads do
not infer historical priority. Disconnect preserves selection and never triggers
failover. This presentation coordination role does not grant OS,
provider, organizer-root or registry permissions. It is distinct from the future
supreme organizer authority described above.

## External collaborators

the operator or an explicitly authorized squad agent can assign cloud/local Grok Bot (or
another external harness) only the information and permissions intentionally given.
Cloud and local instances have separate identities and independently revocable grants.
Authorized squad members can see delegated assignments, progress, access records and
submitted results; the collaborator cannot browse the squad, other projects or memory.
This visibility covers delegated work, not unrelated personal activity or hidden reasoning.

Supported delegation units: prompt, task, SKILL.md, selected artifacts, and a full
named project workspace. A workspace can be opened read-only for 24 hours for a
complete review; this does not open the host filesystem or grant execution/write.
A skill's links and parent directory confer no implicit access.

The issuer selects recipient, resources, operations and expiry; a preview shows
exact included/excluded content. Only separately authorized issuers can export data.
Grants default deny, expire automatically, can be revoked early and cannot be expanded
by the recipient. Excluded secrets/private material remain excluded and review coverage
must reflect omissions. Access revocation does not erase previously disclosed copies.

## Acceptance examples

- Grok receives task A: lists/searches/exact lookups reveal no task B or squad memory.
- A squad reader without export authority cannot create external grants.
- Grok cloud cannot use a local Grok grant or claim another actor identity.
- Read-only workspace review can retrieve all permitted manifest files, not secrets,
  adjacent paths, symlink targets outside scope, or arbitrary shell execution.
- Expired/revoked grants deny new reads and writes, including existing subscriptions.
- Authorized observers see progress/results; collaborator sees only granted work.
- MCP connection does not automatically promise native terminal or desktop access.

## Release boundary

Local implementation and tests first. No new provider spend, production exposure,
squad configuration mutation or external credential provisioning is authorized by this
contract. Existing release/security failures remain open until evidenced closed.

The shared reviewed-action lifecycle, explicit executor transports and five external
export units have further local source implementation; see
the pass-2 engineering record (private, not exported). This does not satisfy
the outstanding native, installed executor or complete-product acceptance criteria.


## Pass-3 source integration boundary

The current source now has reviewed owner session creation, the explicit Hermes
New ID correlation adapter, effective local-shell executor plans and leaf service,
expiring attachment/input consent, native pane presentation, preserving attempt
migration, reboot leases, capture offload, offline composition restore quarantine,
remote installation plans/receipts and production issuer/memory/export composition.
See the pass-3 engineering record (private, not exported) for the implementation and execution limits.
These source repairs supersede earlier statements that New only prepares a folder.
They do not admit a new native artifact or satisfy the complete product acceptance
contract. The other required harness families remain individually unsupported where
verified profile/history/attach/New protocols and approved fixtures are absent.
Created empty profiles still require independently authorized native provider setup;
metadata creation never impersonates authentication or a configured native agent.
