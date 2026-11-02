# Evidence Bundle

`arvyx evidence export` creates a single JSON bundle for release-candidate
review.

The bundle is intended for local validation and multi-model release review. It
gathers machine-readable evidence without changing release status.

## Run

```bash
arvyx evidence export --output tmp/evidence.json --json
```

The bundle includes:

- generation timestamp
- repository path and git head
- readiness gate output
- internal audit output
- default recall benchmark output
- recall benchmark outputs by retrieval mode, including lexical and hybrid
- release-host evidence posture for Docker runtime, real MCP client checks, and
  safe-mcp-bridge dogfood evidence
- current release blockers

## Release Semantics

The evidence bundle can prove that internal gates pass. It does not complete the
public release gate by itself. `release_blockers` concatenates what the bundle
actually checked — `audit.release_blockers` (release-doc status markers and their
tree-bound multi-model receipts) plus `release_host.blockers` (docker, real MCP
client, bridge) — and `arvyx release-candidate` adds the denylist-loaded,
clean-worktree, and non-release-grade-signer blockers on top. Distinct model
reviews and their synthesis are one requirement among these,
not the only one; read `public_release_blockers` on the verdict rather than this
paragraph for the current list.

`recall_benchmark` remains the default lexical benchmark for compatibility.
`recall_benchmarks` contains the full mode map so reviewers can compare lexical
and hybrid recall evidence in the same artifact.

`release_host` records evidence that can only be honestly collected on the
release machine. By default it records Docker runtime and real stdio MCP client
checks as blocked until the operator runs:

```bash
arvyx release-host --run-docker --mcp-client-evidence tmp/mcp-client-evidence.json --json
arvyx evidence export --run-docker --output tmp/evidence.json --mcp-client-evidence tmp/mcp-client-evidence.json --json
```

Use `examples/mcp-clients/real-client-evidence.example.json` as the public-safe
schema reference. The release-host command validates that evidence before
marking the real MCP client check complete.

## Synthetic transport evidence (not release-host acceptance)

`arvyx evidence mcp-client` exercises arvyx's own client and records
`client=arvyx-cli`. It is self-attested synthetic transport evidence, not an
external-client run. The release-host gate rejects it even if signed:

```bash
arvyx evidence mcp-client --output tmp/synthetic-mcp-client-evidence.json --json
```

## External-client collection and signing

On the exact release checkout, use the pinned MCP SDK environment from the
release-provenance workflow to collect actual external stdio client traffic:

```bash
python3 scripts/mcp_client_real_evidence.py --output tmp/mcp-client-evidence.json --capture-out tmp/mcp-client-capture.json
```

This records `client=python-mcp-sdk`, not an agent-UI run. Its default vault is
synthetic test data; that does not make the SDK client self-attested. Retain the
capture and collector output; do not relabel arvyx-cli output as external evidence.
Before importing the SDK and collecting traffic, the collector temporarily replaces
its environment with a fixed allowlist and uses separate fresh temporary client
and server homes, XDG directories and scratch storage. The server receives only
that allowlist plus the explicit checkout source path. This also constrains SDK
stdio defaults that merge environment variables. Ambient proxy/provider settings,
shell startup variables and operator HOME are not forwarded. The original process
environment is restored after collection, including on failure. Run this collector
as a standalone CLI, not concurrently inside an environment-dependent application.
This isolates configuration discovery, not filesystem access: the pinned SDK and
explicit repository/vault remain trusted inputs, and no OS sandbox is claimed.
Transfer the evidence to the approved off-host signer and sign with an already
pinned trusted principal (never distribute a signing key to the release host):

```bash
arvyx evidence sign --evidence tmp/mcp-client-evidence.json --key <ssh_key> --principal <id>
```

Return the signed evidence unchanged to the same release checkout and validate:

```bash
python3 scripts/mcp_client_real_evidence.py --check tmp/mcp-client-evidence.json --release
arvyx release-host --mcp-client-evidence tmp/mcp-client-evidence.json --json
arvyx evidence export --output tmp/evidence.json --mcp-client-evidence tmp/mcp-client-evidence.json --json
```

The evidence must match the release HEAD/tree, remain within the validator's age
limit, and carry a valid pinned signature. Public release additionally requires a
release-grade signer; a local drill key is not sufficient. Missing SDK, signer,
matching tree, or passing collection remains a blocker, not permission to fabricate
evidence. Docker and bridge gates remain independent.

Those host-only blockers are included in `release_blockers` so public-release
review cannot miss them.
