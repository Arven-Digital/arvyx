# Threat model

This public threat model describes the shipped repository and synthetic topology only. It does not describe a live deployment. Abuse cases are defensive risk statements, not exploitation instructions. The model uses STRIDE categories: spoofing, tampering, repudiation, information disclosure, denial of service, and elevation of privilege.

## Security invariants

1. Append-only JSONL is authoritative; SQLite/search indexes are rebuildable projections.
2. Untrusted imported or pending text cannot become curated current truth without the governed promotion path.
3. An identity is authorized by its authenticated identity and scoped capability, not by an actor field supplied in a request.
4. Consequential commands require exact command-hash approval consumption and audit evidence.
5. Direct stdio MCP is read-only unless an explicit operator profile is selected; HTTP control surfaces authenticate and bind to loopback by default.
6. Replica sync never overwrites a primary-looking vault. Writable promotion is refused on manual, forced and automatic paths until matching journal/effect authority is replicated and qualified. Freshness and peer reachability are not promotion authority; DNS/proxy cutover remains external.
7. **B7 binding is authority-scoped, not machine-name-scoped.** Every off-host backup has an authenticated, versioned binding to its exact bytes and authority ID. An unrelated authority or wrong key fails before Docker inspection/extraction. A legitimate failover deployment with the same authority ID and independently provisioned binding key can restore it. Binding does not grant failover authority and never auto-activates a restored node.
8. Runtime bearers, binding keys, and private topology are not backup payloads or public documentation.

## Actors

| Actor | Intended capability | Threat posture |
|---|---|---|
| Local reader | Recall curated, scope-visible memory | Untrusted input; must not gain write/control tools |
| Scoped agent | Use capabilities assigned in registry | May be buggy, compromised, or prompt-injected |
| Operator | Govern writes, approvals, restore and failover | Privileged; mistakes and credential theft are high impact |
| Importer/contributor | Supply files, packages, or changes | Content and dependency input is untrusted |
| Replica identity | Read full vault for replication | High-confidentiality bearer; no mutation/promotion right |
| Release automation | Build/test/package candidate | Supply-chain and artifact-substitution boundary |
| Backup custodian | Store encrypted archives and manifests | Storage is untrusted for integrity; plaintext access is sensitive |
| External caller | Reach an exposed API/proxy | Unauthenticated and potentially abusive |
| Host/root administrator | Control process, files, and service manager | Outside application containment; actions must remain detectable/recoverable |
| Dependency/CI provider | Supplies packages, Actions, runners | May be compromised or unavailable |

## Assets

| Asset | Why it matters | Required property |
|---|---|---|
| Curated vault and append-only control/audit logs | Source of truth and accountability | Confidentiality, integrity, durability, ordering |
| Pending/raw/archive/import lanes | May contain sensitive or adversarial content | Isolation from recall and promotion controls |
| Identity registry and scope assignments | Authorization source | Integrity, least privilege, auditable changes |
| Approval records and exact command hashes | Authority evidence | One-time consumption, exact binding, non-repudiation |
| API, MCP, replica, and operator tokens | Bearer authority | Confidentiality, narrow scope, expiry/revocation |
| Backup archives, checksums, B7 manifests | Recovery source | Authenticity, completeness, authority binding |
| B7 binding key and runtime control secret | Root security material | Host-private storage, rotation, never archived/logged |
| Replica markers/freshness/failover record | Prevent wrong-target overwrite and unsafe promotion | Integrity, fail-closed unknown state |
| Release source, lock/build inputs, artifacts, SBOM | Determines shipped code | Provenance, immutable inputs, reproducibility evidence |
| Availability of primary, replica, storage, DNS/proxy | Enables service and recovery | Bounded failure and deliberate recovery |

## Trust boundaries and data flows

```text
untrusted files -> importer -> pending/import lane -> governed review -> curated vault
local user/agent -> CLI -> policy/authz -> vault + append-only control/audit logs
MCP client -> profile-filtering bridge -> CLI/domain operations
external client -> reverse proxy/TLS -> authenticated loopback API -> domain operations
primary -> authenticated replica.read sync -> marked warm replica
source state -> quiesced backup -> archive + checksum + B7 manifest -> untrusted/offline storage
archive -> B7/checksum verification -> isolated candidate -> integrity/acceptance probe -> explicit cutover
source/lockfiles -> CI runner -> tests/scans/SBOM -> release artifact -> operator-controlled release
```

Boundary notes:

- CLI arguments, environment variables, imported paths/content, HTTP JSON, and MCP arguments are untrusted.
- MCP discovery itself is an authority boundary: hidden tools must remain undiscoverable and uncallable.
- `replica.read` crosses a confidentiality boundary because it reads lanes normal recall excludes.
- Backup storage is outside runtime trust. Checksums detect accidental corruption; B7 HMAC authenticates authority and archive identity. Storage encryption and access control remain operator duties.
- Restores occur offline into a new candidate. Verification does not imply promotion.
- Service-manager, host, DNS, proxy, and secret-provider details belong in a private operator runbook, not this repository.

## Concrete threat and regression matrix

Test names are exact repository commands or unittest selectors. “Residual” is what remains after the listed control.

| ID / surface | STRIDE / abuse case and impact | Controls | Exact regression evidence | Residual risk |
|---|---|---|---|---|
| T1 CLI | E/R: a caller claims another actor or reaches a privileged verb without scope | Registry identity, scope checks, actor binding, append-only audit | `python -m unittest packages.arvctl.tests.test_execution_surfaces packages.arvctl.tests.test_dispatcher -v`; full `make test` | Compromised authorized identity can act within its scope |
| T2 CLI approvals | T/R/E: a command is changed after approval or approval is replayed | Exact command hash, single-use consume, durable events | `python -m unittest packages.arvctl.tests.test_execution_surfaces packages.arvctl.tests.test_operation_journal -v` | Operator may approve a harmful exact command |
| T3 API | S/E/I: exposed or unauthenticated control API leaks/mutates state | Loopback default, bearer auth, route authz, body limits | `python -m unittest packages.arvctl.tests.test_demo_spine packages.arvctl.tests.test_security_posture -v`; `make api-smoke auth-smoke` | Reverse-proxy/TLS policy is deployment-specific |
| T4 MCP | E/I: broad discovery or direct calls expose operator tools | Read-only default profile, explicit allowlist, bridge policy/lint | `make mcp-smoke mcp-control-smoke bridge-smoke bridge-lint-smoke bridge-e2e-smoke` | A deliberately selected operator profile remains powerful |
| T5 import | T/I/DoS: crafted paths, links, oversized/binary content, or prompt text contaminates truth/index | Path/type/size validation, synthetic fixtures, imported lane, explicit promotion, index exclusion | `python -m unittest packages.arvctl.tests.test_demo_spine packages.arvctl.tests.test_security_posture -v`; `make import-smoke` | Human reviewer can promote misleading content; parser zero-days remain |
| T6 vault/state | T/R: log truncation, malformed events, or projection drift falsifies state | Append-only validation, audit hash chain, rebuildable projection, integrity checks | `make store-smoke audit-smoke`; full `make test` | Host/root can alter data and code together unless external evidence exists |
| T7 replica sync | T/I: wrong destination overwrites truth, deletion/divergence propagates, replica bearer leaks all lanes | Replica marker, primary-looking-target refusal, sha256 repair, narrow `replica.read`, freshness state | `python -m unittest packages.arvctl.tests.test_replication -v` | A compromised replica bearer discloses the full vault; sync can copy authorized bad state |
| T8 failover | S/T/DoS: stale or partitioned replica self-promotes, yielding loss/split brain | Writable promotion refused, including manual/force/auto; sync lacks matching journal/effect authority | `python -m unittest packages.arvctl.tests.test_replication -v` (source reference, not a new executed receipt) | Read-only replica recovery is not writable authority; external routing changes cannot establish it; writes after last sync are absent |
| T9 backup/B7 | T/S/I: archive is corrupted, substituted, restored under an unrelated authority, or revives a bearer | Atomic binding-first publication, SHA-256, authority-scoped HMAC manifest, no-follow 0600 key read, bearer excluded | `python -m unittest packages.arvctl.tests.test_backup_restore.BackupRestoreTests -v` | HMAC is not storage encryption; loss of both archive and key prevents recovery; same-authority key compromise permits forgery |
| T10 restore | T/E: unsafe archive paths or unverified candidate reaches production | Safe extraction, offline new candidate, data/audit/SQLite checks, acceptance probe, atomic pointer, retained rollback volume | `python -m unittest packages.arvctl.tests.test_backup_restore -v`; `python scripts/synthetic_backup_restore_drill.py --json` | Application checks cannot detect semantically bad but structurally valid old data |
| T11 synthetic drill | T/DoS: backups exist but cannot survive corruption/loss and restart | Executable backup→loss→offline restore→integrity→fresh-process acceptance; corruption fails closed; measured local fields | `python -m unittest packages.arvctl.tests.test_synthetic_backup_restore_drill -v` | Local timings are not production RPO/RTO and exclude transfer, approval, DNS, and human delay |
| T12 release | T/I: unreviewed/private files, mutable CI dependencies, vulnerable dependency, or substituted artifact ships | Public-boundary scan, secret-shape scan, SHA-pinned Actions, pinned scanner checksum, dependency audit/SBOM, tests | `make ci`; workflow `.github/workflows/ci.yml`; `python scripts/public_release_boundary.py` | Package registries, runners, source-host accounts, and upstream keys remain external dependencies |
| T13 secrets | I/S: token/key appears in args, logs, fixtures, archive, or release | Env/file indirection, redacted diagnostics, private-context scan (secret shapes in every file; untracked private-name denylist in every file except manifest `private-only` paths, failing closed without a valid manifest), backup exclusion, 0600 checks | `make scan`; staged-candidate Gitleaks scan; backup tests above | Pattern scans have false negatives; endpoint compromise can read process-accessible secrets |
| T14 availability | DoS: disk exhaustion, lock contention, malformed input, dependency outage, primary loss | Bounded inputs/timeouts, locks, health checks, warm standby, offline backups, deliberate failover | `make health-smoke`; focused replica/backup tests; full `make ci` | No automatic HA; recovery depends on people and external routing/storage |
| T15 supply chain | T/E/DoS: compromised Action/package/build host alters release or blocks builds | Minimal workflow permissions, immutable Action SHAs, package audit, SBOM, exact-tree scan, artifact provenance workflow | `python scripts/public_release_boundary.py`; CI `test`; `.github/workflows/release-provenance.yml` | Audit databases can lag; compromised trusted signing/build identity can still sign bad code |

If a named test module changes, update this matrix in the same change; stale test references are security-documentation failures.

## Key and token lifecycle

| Material | Issue/provision | Store/use | Rotate/revoke | Backup/recovery |
|---|---|---|---|---|
| API/control bearer | Generate high entropy for one deployment; issue through operator-controlled channel | Host-private file or secret provider; pass by env/file reference; never CLI literal/log | Rotate on exposure, role change, or policy cadence; restart/read back auth behavior; old bearer must return unauthorized | Explicitly excluded from archives; stage the current bearer onto a restore candidate |
| Scoped agent token | Issue to a registered identity with minimum scopes and recorded owner | Consumer secret store; transmit only over authenticated transport | Revoke when agent/host retires or compromise is suspected; reissue rather than broaden | Token hashes/registry state may replicate for continuity; plaintext token never does |
| Replica token | Issue only `replica.read`, uniquely per replica | Backup host secret store | Revoke on replica retirement/exposure; verify sync failure then provision replacement | Never archive plaintext; restore does not create promotion authority |
| B7 binding key | Independently provision at least 32 random bytes to legitimate same-authority primary/failover hosts | Real regular 0600-or-stricter file; no symlinks; read race-free; purpose-separated HMAC | Version and rotate with an overlap plan: create a newly bound backup, drill it on each recovery host, then retire old key | Never place key in backup. Loss means old bound archives cannot be authenticated; unrelated authority keys must fail |
| Release/signing identity | Human/CI identity with least repository/package scope | Protected CI environment/hardware-backed store where available | Rotate on compromise/provider policy; revoke old sessions/tokens and preserve audit evidence | Recovery is provider-specific and private; do not copy credentials into artifacts |

Token hashes are still sensitive authorization metadata. Rotation evidence must prove both acceptance of the replacement and rejection of the retired credential without printing either value.

## Availability and recovery posture

- Source-of-truth loss tolerance is bounded by the last successful, authenticated backup/replica sync, not by schedule intent.
- RPO and RTO are operator-set objectives. The synthetic drill reports `rpo_like_seconds`, `rto_like_seconds`, and `elapsed_seconds` only for its disposable local run.
- Unknown replica freshness fails closed. `--force` does not bypass writable-promotion refusal or establish journal/effect authority.
- A failed/missed restore drill is a durability finding even while service is healthy.
- Keep offline/off-host copies in a separate failure domain. Test loss of the primary, not merely extraction beside it.
- Capacity, pager, DNS/proxy, service manager, key escrow, and actual schedules are private deployment concerns.

## Out of scope / residual assumptions

- A malicious host/root administrator can replace application code, read runtime-accessible plaintext, or falsify local evidence; external monitoring and access controls are required.
- The project does not implement distributed consensus or automatic DNS/proxy failover.
- Encryption-at-rest for backup storage is operator-provided. B7 provides authenticated authority/archive binding, not confidentiality.
- Denial of service against network, package registries, source hosting, or storage cannot be eliminated by application code.
- Human review, approval, and promotion can be wrong. Auditability and rollback reduce impact but do not prove judgment.
- No source-only test proves a particular production deployment uses these controls. Production receipts stay in the private operations lane.
