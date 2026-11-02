# Security Audit

audit-status: complete

This file tracks the security review status of the exact tree under release
review. The status line above is the candidate's claim, not a verdict. The
public-release gate honors it only when `.arvyx/release-reviews/security-audit.attestation.json`
holds a valid receipt for the exact tree: at least two distinct models reviewed
that tree, their reports are hash-bound, the receipt declares
`custody: operator-authored-unsigned`, and disagreements are explicitly
synthesized. Receipts are tree-bound, so a review of an earlier tree does not
carry over, and `arvyx release-candidate` refuses a dirty worktree. The only
release verdict is `arvyx release-candidate --json` on the exact frozen tree.

Arvyx is a solo-operator system: governance comes from model-review diversity,
not from multiple people. Each receipt binds the reviewed Git tree to the exact
bytes of reports stored under the gitignored `.arvyx/model-reviews/` lane.

## Required review areas

- Secret and private-context scanning.
- MCP tool exposure and allowlist behavior.
- Auth header handling and token redaction.
- Append-only event log integrity.
- SQLite projection correctness.
- Dashboard and API input/output safety.
- Importer handling of secret-shaped content.
- Docker and local setup defaults.
- Onboarding and session-metadata adapters: bounded discovery, reviewed consent,
  link refusal, no transcript reads, no implied execution.
- Native artifact admission: digest pinning, sealed execution, capability checks.
- Release provenance, tree binding, and model-review gate behavior.

## Internal evidence command

Run before every release candidate review:

```bash
ARVYX_PRIVATE_DENYLIST=<path to the maintainers' denylist> arvyx audit --json
```

It verifies the repository secret-shape scan with explicit evidence that the
private-name denylist was loaded, the synthetic vault doctor, the end-to-end
demo, the readiness gate score, the `safe-mcp-bridge` policy profiles and the
presence of the release-gate documents. It keeps `public_release_blocked=true`
until both multi-model receipts exist for the tree.

## Scanner boundary

The audit and the standalone private-context scanner share candidate
enumeration: tracked plus unignored files in a Git checkout, or a
directory-pruned walk for an extracted tree. Installed `node_modules` are a
dependency boundary; lockfiles, vendored source and every other candidate file
are scanned. Secret shapes are scanned in every file; private names from the
denylist are scanned in every file the release manifest does not classify
`private-only` (in this repository every path is `public-approved`, so names
are scanned everywhere). A source scan is not package vulnerability, licence,
provenance or compiled-artifact clearance; those remain the dependency-audit,
hashed-lock, SBOM, licence and release checks.

## Dependency assurance

Developer tooling installs from hashed locks (`requirements/dev.lock`,
`requirements/secret-edge.lock`, `requirements/mcp-client.lock`); CI runs the
dependency audit, CycloneDX SBOM generation and licence/NOTICE verification on
every push. An unavailable advisory service is a blocker, not an offline-clean
result. The runtime itself is standard-library only.

## Findings

No valid multi-model receipt exists for this tree until it is recorded for this
exact tree; a receipt is minted per candidate, never carried forward. Residual
coverage limitation, accepted for every candidate: passing scanners and smoke
tests do not prove the absence of defects outside their exercised paths.
