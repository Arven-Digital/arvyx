# Herdr upstream source candidate

## Identity and authority

- Arvyx base: remote `main`, `4bf2a4e986517e7ca5951946c7456d2cb4d13711`.
- Candidate upstream: [herdrdev/herdr at ee5bfb5041bb3e4a49d591c72308aae3c81ecdde](https://github.com/herdrdev/herdr/commit/ee5bfb5041bb3e4a49d591c72308aae3c81ecdde).
- Prior admitted upstream: `5bd900d88c80d95f5b145397e45bbeea398b8165`.
- Comparison: [12 commits ahead](https://github.com/herdrdev/herdr/compare/5bd900d88c80d95f5b145397e45bbeea398b8165...ee5bfb5041bb3e4a49d591c72308aae3c81ecdde). The older `v0.9.5` tag is not the update target; the newer source still declares package version `0.9.5`.
- License: Apache-2.0; retain `NOTICE` and `licenses/Herdr-Apache-2.0.txt`.

`frontends/arvyx/candidates/herdr-upstream.json` is the **source build target**, not an artifact receipt or runtime approval. The builder requires a clean Git checkout at that exact revision, including absence of untracked/ignored source files, and records the candidate metadata hash and upstream identity in any new artifact manifest. Git is now a source-validation prerequisite. Supply pristine upstream source, not an already-patched checkout; the builder applies the tracked overlay itself. The builder still binds copied source bytes, tools, offline registry, SDK inputs and overlay hashes. This is not a new claim of hermetic execution or protection against concurrent hostile filesystem changes.

Existing runtime digest policy, admitted receipts and overlay bytes are unchanged. Historical pin references in `NOTICE`, adapter module attribution, prior acceptance scripts and limitations remain historical statements, not alternate candidate targets. No historical receipt is rewritten to describe new bytes.

## Updates included by the source target

The delta includes keeping slow-server sockets rather than deleting them after a connection timeout (`ff5881ef`), preserving saved layout during host shutdown (`6b526626`), sequencing appearance after the matching background (`3f5032c9`), detecting newer Hermes installer launchers (`43b36b68`), bounding Linux clipboard helpers (`de8503c1`), tcsh remote readiness (`65da135f`), and XDG integration configuration (`2713feb5`). The exact commit includes the remaining maintenance/documentation changes too; this is not a hand-picked partial cherry-pick.

## Actual compatibility evidence

- `git apply --check` and GNU `patch --batch --forward --dry-run -p1` succeeded against the exact clean upstream checkout.
- The actual forward patch succeeded for all five patched shell files without rejects, offsets or fuzz. Both Rust overlay modules were copied into the isolated upstream checkout; the builder's module-reachability assertions passed. No overlay conflict or adjustment was needed.
- Static review of upstream changes to shell actions, onboarding configuration writes and clipboard dispatch found no use of the changed configuration callback or clipboard helper APIs in the Arvyx overlay. This is not compilation or runtime proof.
- Focused Python checks: **12 passed**. Coverage includes pin validation, wrong revision, tracked/untracked/ignored edits, malformed revisions, non-root source directories, explicit build inputs, historical receipt binding and unchanged runtime provenance.
- `cargo metadata --offline --locked --format-version 1` resolved **297 packages** from the existing registry. Rust reports `rustc 1.94.1`. No compilation was launched: Zig was not available on PATH, and the reproducible builder requires an explicit Zig executable/cache and complete toolchain/SDK inventory. No installation was attempted.
- `git diff --check` passed for the Arvyx edits and the prepared upstream checkout. Exact historical receipt, overlay, runtime policy, license and NOTICE paths were checked unchanged against the base.
- The focused tracked-path release-boundary checker returned `ok: true`, `release_approved: false` after classifying the five new paths. The final staged-source targeted rerun returned **12 passed in 0.24s**. This was not the full CI, release scan or independent acceptance pipeline.

Receipts: [targeted checks](evidence/herdr-ee5bfb5-targeted-tests.json) and [overlay application](evidence/herdr-ee5bfb5-overlay-compatibility.json). The latter's exploratory `prepared_source_sha256` hashes the whole prepared checkout **including `.git`**; it is not the builder's copied-source hash, a reproducible artifact receipt or an admission input.

During development the new tests first failed twice as intended (missing manifest/helper). An initial combined test invocation could not collect an existing module without `PYTHONPATH=packages/arvctl/src`. A first metadata placement directly under `frontends/arvyx/` triggered the existing overlay-inventory assertion (11 passed, 1 failed); metadata was moved into `candidates/`, preserving the exact admitted overlay inventory. The final focused run passed without weakening existing tests.

## Reproduce the limited checks

From the Arvyx candidate checkout:

```sh
PYTHONPATH=packages/arvctl/src python -m pytest -q \
  packages/arvctl/tests/test_native_source_candidate.py \
  packages/arvctl/tests/test_pass3_native_build_inputs.py \
  packages/arvctl/tests/test_native_receipt_binding.py \
  packages/arvctl/tests/test_pass2_native_provenance.py \
  packages/arvctl/tests/test_focus75_native_provenance.py
```

From a separate pristine Herdr checkout at the candidate SHA, run `git apply --check` and GNU `patch --batch --forward --dry-run -p1 -i` with the absolute path to Arvyx's `frontends/arvyx/amc-native-mouse.patch`. These checks do not compile the overlay. For the later authorized build, use the existing builder's required explicit source/output/tool/cache/inventory arguments, as shown by `python scripts/build_arvyx_native.py --help`; no installer, setup flow or live profile is needed.

## Remaining admission gates — HOLD

1. Independently review the exact Arvyx source candidate. No independent model review has run.
2. Provision approved explicit native toolchain/SDK/registry/cache inputs, reproduce the candidate binary with the builder and retain a new receipt. Do not reuse a historical binary hash.
3. Run the overlay Rust tests and the applicable socket/shutdown/clipboard/detection regressions, followed by exact-binary isolated PTY chooser/onboarding/native API safety acceptance and platform qualification under separate authorization.
4. Obtain explicit authorization before any full CI run. None was started here.
5. Only after reproducible artifact and runtime acceptance, separately review a new admission-policy/receipt change. Public release, push/PR, installation and deployment remain unapproved.

This source change does not update the installed native frontend, mutate existing evening setup, alter profiles, start processes, change npm assets or migrate admission policy.
