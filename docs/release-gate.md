# Release Gate

release-gate-status: complete

The status line marks this checklist as current and in force for the tree; it
is not a release approval. The gate honors it only when a valid multi-model
review receipt (`.arvyx/release-reviews/release-gate.attestation.json`) is bound
to the exact Git tree under review. The only release verdict is
`arvyx release-candidate --json` run on the exact frozen candidate tree, and
every verdict is per-tree: any later commit invalidates it.

## Enforced by `arvyx release-candidate --json`

`public_release_allowed` stays `false` while any of these is unmet:

- `arvyx audit --json` passes its internal evidence checks (private-context and
  secret-shape scan with the denylist loaded, vault doctor, synthetic demo,
  readiness gate, bridge policy, release docs).
- `arvyx readiness --json` reports a score at or above the private-preview
  threshold. Readiness is structural (paths and status markers), never executed
  evidence.
- `arvyx benchmark recall --json` and `arvyx benchmark recall --retrieval-mode hybrid --json`
  pass the recall golden set.
- `arvyx dogfood self --json` imports this repository's docs and recalls the
  release gate from governed memory.
- A `security-audit` and a `release-gate` multi-model review receipt, each bound
  to the exact tree, each with at least two distinct `provider/model`
  identities, no `block` verdict, and an explicit synthesis.
- Every signature supplied as release evidence comes from a principal named in
  `docs/release-grade-signers.allowed`; `docs/trusted-signers.allowed` decides
  what verifies, the release-grade list decides what may carry a public release.
- `arvyx release-host --require-provenance --provenance-dir <dir> --mcp-client-evidence <file> --json`
  validates signed, release-grade Docker run-provenance for the exact tree.
- Real external MCP client evidence: `git_head` and `git_tree` match the release
  tree, `checked_at` is within 14 days, and the file carries an SSH signature
  from a release-grade signer. Self-attested `arvyx-cli` evidence is rejected.
- `safe-mcp-bridge` end-to-end signed, release-grade run-provenance for the exact tree.
- The private-context denylist was loaded (`private_denylist_loaded=true`).
- The worktree is clean.

## Operator checklist (not read by the command)

- CI green on the release commit, including the platform matrix.
- `make dev-install dependency-audit sbom license-check` green.
- `arvyx evidence export --output tmp/evidence.json --json` produces the review bundle.
- Docker demo verified on a clean machine; `make docker-runtime-smoke` on the release host.
- `make thread-smoke health-smoke notify-smoke` green.
- MCP client examples tested with at least one real stdio client.
- README limitations and non-goals reviewed against the tree.

## How the evidence is produced

Protected `v*` tags run `.github/workflows/release-provenance.yml` in the
`release-provenance` environment. The workflow gates the exact tag SHA against
canonical CI, builds the wheel, sdist and image once, runs the official MCP
Python SDK stdio client against the read-only server and signs that evidence
with the CI principal, signs Docker and bridge run-provenance, generates SBOMs
and hashes, creates GitHub OIDC build attestations and uploads the assets to a
draft release (marked prerelease for alpha, beta and rc tags), which the maintainer
publishes only after the `release-candidate` verdict (see PUBLISHING.md).
Verify a downloaded artifact with:

```bash
gh attestation verify <artifact> --repo Arven-Digital/arvyx
sha256sum -c SHA256SUMS
```

The job that runs the unpinned third-party MCP client is separate from the
signing job; only the single evidence file crosses that boundary. The signing
job itself installs hash-locked Python tooling and the integrity-pinned npm
closure before it signs; a build/sign job split is recorded as future work.

## Multi-model review receipts

```bash
mkdir -p .arvyx/model-reviews
arvyx attest model-review --subject security-audit --provider <provider> --model <model> \
  --verdict approve --scope "release tree" --report .arvyx/model-reviews/security-<model>.md
arvyx attest model-synthesis --subject security-audit --decision approve \
  --synthesizer <provider>/<model> --agreement "..." --disagreement "..." --resolution "..."
```

Repeat for `--subject release-gate`. Each report states the reviewed tree,
provider and model, scope, findings and verdict; the receipt binds the report
bytes and the tree. Receipts carry `custody: operator-authored-unsigned`: they
document which models reviewed the tree, not independent custody. The control is
model diversity, not anti-forgery; `public_release_allowed: true` records that
the documented steps were run, and the publication decision stays with the
maintainer.

## Internal release candidate loop

```bash
make ci
make build dependency-audit sbom license-check
arvyx audit --json
arvyx readiness --json
arvyx benchmark recall --json
arvyx benchmark recall --retrieval-mode hybrid --json
arvyx evidence mcp-client --output tmp/mcp-client-evidence.json --json
python3 scripts/release_candidate_e2e_check.py --run-docker --json
arvyx dogfood self --run-docker --json
arvyx release-candidate --run-docker --json
arvyx release-host --json
```

These are necessary, not sufficient: the receipts, the signed evidence and the
maintainer's explicit approval complete a release.

## Current decision

No verdict is recorded for this tree in this document, because a recorded
verdict goes stale on the next commit. Run the command on the frozen candidate
and keep its output in the release packet.
