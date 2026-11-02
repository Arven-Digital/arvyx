# Contributing

Contributions are welcome when they preserve the project's security and privacy
boundaries.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements/dev.lock
python -m pip install --no-deps --no-build-isolation -e .
make ci build sbom license-check
make dependency-audit
```

The final audit requires network access to the vulnerability database and
fails closed when it cannot obtain advisory data. Dependency changes must
update `requirements/dev.in`, regenerate and review `requirements/dev.lock`,
refresh `requirements/THIRD_PARTY_LICENSES.json`, and pass the dependency
contract tests; CI and release workflows may not install Python tools ad hoc.

Windows contributors can run the unit suite directly:

```bash
python -m unittest discover packages/arvctl/tests -q
python scripts/private_context_scan.py --shapes-only
```

## Pull requests

- Keep changes focused and add regression tests.
- Never submit real memory, prompts, messages, logs, credentials, private paths,
  machine names, personal data, or production configuration.
- Use synthetic identities and `example.com`-style infrastructure in fixtures.
- Do not weaken authentication, SSRF, redaction, audit, or release checks merely
  to make a test pass.
- Document persisted-format and operator-facing behavior changes.

Maintainers run an additional untracked private-context denylist before release.
Its contents are intentionally not published. The denylist applies to every
file except paths classified `private-only` in
`config/public-release-paths.json`, which are never exported; secret-shape
checks apply to every file, so use synthetic identities everywhere else.

## Developer Certificate of Origin

This project uses the Developer Certificate of Origin 1.1 rather than a CLA. Add
a `Signed-off-by` trailer to each commit:

```bash
git commit -s
```

By signing off, you certify that you have the right to submit the contribution
under the project's Apache-2.0 license. See https://developercertificate.org/.

## Security reports

Do not open public issues for suspected vulnerabilities. Follow
[SECURITY.md](SECURITY.md).
