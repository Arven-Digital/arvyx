# Publishing Arvyx

Maintainer checklist for a release. Nothing here is automatic: each step is an
explicit human action on the exact candidate commit.

## Repository settings (once)

1. Repository variable `HOSTED_ACTIONS_ENABLED=true` so the Linux platform matrix
   runs (the release workflow requires it). `HOSTED_EXPERIMENTAL_PLATFORMS=true`
   additionally runs the macOS and Windows jobs, which are not required.
2. Secret `ARVEN_PRIVATE_DENYLIST_B64`: base64 of the private-name denylist used by
   the strict private-context scan (one term per line). It is read by the
   `release-provenance` workflow and by the `security` job of `ci.yml`; fork and
   Dependabot pull requests fall back to the synthetic example list, any other
   context without the secret fails.
3. Environment `release-provenance` with required reviewers, a deployment tag rule
   limited to `v*`, and the secret `ARVEN_RELEASE_SIGNING_KEY` (an SSH ed25519
   private key whose public key is pinned as `arven-release-tooling-ci` in
   `docs/trusted-signers.allowed` and `docs/release-grade-signers.allowed`).
4. A tag ruleset restricting who may create `v*` tags.

## Release

1. Freeze the candidate commit; CI (`ci.yml`) must be green on exactly that SHA.
2. Run the local gate on the clean tree and keep the output:
   `arvyx release-candidate --json`, `arvyx evidence export --output tmp/evidence.json --json`.
3. Record the two multi-model review receipts (`security-audit`, `release-gate`)
   with `arvyx attest model-review` and `arvyx attest model-synthesis`; they live
   under the gitignored `.arvyx/` lane and bind the exact tree.
4. Push the protected tag `v<version>` matching `pyproject.toml`. The
   `release-provenance` workflow builds the wheel, sdist and image once, produces
   and signs the real MCP-client evidence, signs Docker and bridge run-provenance,
   creates OIDC attestations and uploads everything to a **draft** release
   (marked prerelease for alpha, beta and rc tags). Nothing is public yet.
5. Download the draft's signed evidence (drafts are visible to maintainers) and
   run the verdict against it on the exact tagged tree, with the receipts from
   step 3 in place:

   ```bash
   gh release download v<version> --dir tmp/release-assets
   (cd tmp/release-assets && sha256sum -c SHA256SUMS)
   arvyx release-candidate --require-provenance --provenance-dir tmp/release-assets \
     --mcp-client-evidence tmp/release-assets/evidence.mcp-client.json --json
   ```

   `public_release_allowed` must be true. A blocked verdict means deleting the
   draft and the tag, not editing the draft.
6. Attach the native frontend artifact `arvyx-linux-x86_64`, its receipt
   `frontends/arvyx/receipts/onboarding-v1-linux-x86_64.json` and the chooser
   acceptance receipt (`native-chooser-pty-acceptance.json`, produced by
   `scripts/native_chooser_pty_acceptance.py` against that exact binary) to the
   release; the binary digest must equal `NATIVE_ONBOARDING_BINARY_SHA256`.
7. Build the npm tarball from the exact tagged checkout, smoke it, record its
   digest in the release notes and publish it under the prerelease dist-tag so
   `latest` never points at an alpha:
   `make npm-package-smoke`, `python scripts/build_arvyx_npm.py --output DIR`,
   `sha256sum DIR/arvyx-<version>.tgz`, `npm publish DIR/arvyx-<version>.tgz --tag alpha`.
   The release workflow does not produce the npm tarball; its binding to the tag
   is this procedure and the recorded digest.
8. Publish the draft release, then smoke the public clone, the npm install and the
   release links before announcing.

A failed post-publication smoke means retracting the release and the package
version, not patching in place.
