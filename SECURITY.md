# Security Policy

Arvyx is alpha software released under Apache-2.0. Treat it as
security-sensitive infrastructure: the deployment boundary assumes an
authenticated API behind a TLS reverse proxy and an operator-controlled data
volume. Alpha status is not a security warranty.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on the repository (Security →
Report a vulnerability) so the report stays confidential until a fix is
released. Include the exact commit, the affected surface (CLI, HTTP API, MCP,
bridge, control room, native frontend) and a reproduction against the synthetic
fixtures; never attach real memory, credentials or production logs. Expect an
acknowledgement within seven days. Do not open a public issue for a suspected
vulnerability.

## Repository policy

- Everything tracked here is synthetic or scrubbed. Do not add real secrets,
  raw logs, private memory, production configuration, private hostnames or
  personal context; use the synthetic fixtures.
- Keep examples runnable without any private infrastructure.
- Preserve provenance for every imported or vendored component (`licenses/`,
  `frontends/paperclip/vendor/provenance.json`, the native build receipt under
  `frontends/arvyx/receipts/`).
- Run the scanners before every push: `python scripts/private_context_scan.py`,
  `python scripts/public_release_boundary.py` and Gitleaks on the tracked tree.

## Detectors and their scope

The private-name policy is a denylist of names, hostnames and identifiers that
is maintained outside the public tree (in hosted CI it arrives as the secret
`ARVEN_PRIVATE_DENYLIST_B64`); `fixtures/private-denylist.example.txt` is the
synthetic example used by fork pull requests and by the test suite. Name
matching uses identity boundaries and known agent or numeric suffixes; the exact
product identifiers (`arvyx_control`, `arvyx-control`, the `.arvyx/` directory
component) are exempt only as whole identifiers, never as whole lines or paths.
Token, literal-assignment, PEM, multiline and reconstructed-constant credential
detectors are mandatory in every file; sanctioned `secret://` broker references
carry no value and are not findings.

## Continuous integration

`ci.yml` runs `security` (strict private-context scan with the real denylist,
release-boundary classification, Gitleaks) and `correctness` (Python, frontend
and npm tests, package smoke, integration gates) as independent jobs, so a
failure in one never hides the other's evidence; the required `test` check
passes only when both succeed, and no timeout is treated as a pass. Node 24.11.1
and Python 3.11 are pinned. A green run is a prerequisite for a release, not
release clearance.

## Public release gate

Before a release, on the exact tagged tree:

1. Source provenance and third-party notices reviewed.
2. Private-context, secret-shape and Gitleaks scans green.
3. Two independent model reviews and a synthesis recorded for `security-audit`
   and `release-gate` (`arvyx attest model-review`, `arvyx attest model-synthesis`).
4. `arvyx release-candidate --json` run by the maintainer with those receipts
   and the signed evidence the release workflow attaches to the draft release;
   the draft is published only when that verdict allows.
5. The clean-clone quickstart verified on a fresh machine.

See `docs/release-gate.md`, `docs/security-audit.md` and `docs/threat-model.md`.
