# First native session: explicit isolated setup

`amc first-session` initializes a fresh native Hermes home, creates an owner-managed
native session, opens the admitted Arvyx frontend, verifies its exact native pane
binding, and attaches the controlling terminal. This is a separate bounded
bootstrap entry. `amc terminal` remains attach-only and does not discover, create,
resume, or adopt an owner or profile.

## Meaning of readiness

A credential-free first run is deliberately **`setup_required`**, not an
authenticated provider chat. Its screen is the installed Hermes first-run setup
surface (`Run setup now? [Y/n]`). The owner has a real PTY and a real native
session ID; this does not mean a model is configured or inference has run.

The human can explicitly enter native setup from that surface. No setup response,
credential, provider resolution, anonymous/free-tier enrollment, initial prompt,
or model request is supplied automatically. Provider authentication remains a
separate human action. The acceptance harness never answers setup.

The first-session owner is foreground-scoped. `Ctrl+B`, then `q` detaches the
Arvyx terminal and closes **only this bootstrap's** native process, frontend
server, watcher, and owner. All files remain. The saved proof describes the
observed running generation; it is not a reusable attachment capability after
owner shutdown. It does not automatically re-inventory credentials after human setup. If native
setup creates auth/config markers, the final receipt becomes
`setup_outcome_unverified` with unknown authentication/provider status, not a
claim that a saved key works. Existing attach-only frontend behavior still
preserves its preexisting owner on successful detach.

## Explicit invocation

Supply already provisioned, trusted native dependencies and an admitted Arvyx
binary. No component is downloaded, installed, upgraded, or silently discovered
by this command:

```sh
python -m arvyx_control.onboarding_cli first-session \
  --first-session-root /protected/private-parent/new-session \
  --hermes-python /absolute/native/python3 \
  --hermes-source /absolute/trusted/hermes-source-and-dependencies \
  --python-sha256 REVIEWED_PYTHON_SHA256 \
  --arvyx-binary /absolute/admitted/arvyx \
  --execution-policy /absolute/private/execution-policy.json \
  --execution-mode host
```

The root must be absent and short enough for **both** owner and frontend Unix
sockets. Its parent must exist. The command requires a foreground controlling
terminal, an effective unprivileged host policy, the displayed executable digest,
and exact interactive `NEW /absolute/root` confirmation before creation. A policy
example (the UID must match the actual intended unprivileged account):

```json
{"host_uid": 1000, "allow_host": true, "allow_root": false}
```

The policy file uses the existing private-configuration reader. Root and sandbox
first-session modes are refused, with no host fallback. Existing
`--native-owner`, `--frontend-home`, and `--hermes-home` inputs are forbidden in
this mode. Reusing an existing first-session root is also refused: it is never a
resume or a profile-repair operation.

## Native initialization and executable boundary

`first_session.py` implements the explicitly attested
`hermes-isolated-setup-v1` protocol:

1. Validate the terminal, confirmation, effective policy, protected ancestry,
   source reference, reviewed native ELF Python digest, and released Arvyx bytes.
   Create the new root, profile, and workspace exclusively with private modes.
2. Start a bounded isolated process that calls the installed native writer API
   `hermes_state_registry.acquire()` and closes its handle. Hermes creates and
   migrates its own schema. Arvyx does not create SQLite DDL, placeholder files,
   session rows, or invented native provenance.
3. Construct the strict existing `NativeRuntime` **after** successful native
   initialization. The setup adapter requires an empty native session collection
   and no `.env`, `auth.json`, or `config.yaml`. The normal runtime still rejects
   missing `state.db`; the normal titled-chat protocol is unchanged.
4. Explicitly enroll a new isolated local owner using `machine_enrollment.enroll`.
   No pilot/demo fixture, organizer election, existing gateway, or default
   profile is adopted. Invoke the owner's reviewed, single-use New lifecycle.
   Its child uses native `new_session_id`, `create_session(source="cli", cwd=...)`,
   and `set_session_title` APIs, closes the writer, then presents the native
   first-run setup guard. No agent or provider runtime is constructed.
5. Acknowledge the unique correlation title through read-only native metadata;
   resolve the exact native ID and recorded workspace. Verify the actual owner
   incarnation, epoch, and running process generation.
6. Reuse the same admitted `VerifiedNative` object for the real frontend. Read its
   actual snapshot; bind and read back exact owner/native/pane/workspace/tab
   identities. The bridge uses the native lifecycle attachment proof, exact
   target, and original absolute consent expiry, not a generic cold resume.
7. On detach or failure, perform scoped own-process cleanup and retain all state.
   `first-session.json` is atomically published through the pinned root descriptor
   and records `setup_required`, initial authentication/provider status, exact
   proof, pane binding, and the final foreground owner status.

The Python executable is admitted separately from Arvyx's pinned artifact policy.
Its bytes are copied into a sealed Linux memfd, checked against the explicitly
reviewed digest, and that same descriptor is inherited through the final owner
exec. Rehashing a mutable pathname is not the dispatch guarantee. Source/profile
and workspace descriptors are retained through native dispatch; path incarnation
and consent checks are repeated during owner admission. Both `HOME` and
`HERMES_HOME` refer to the isolated home, with a minimal environment and guest
onboarding disabled. The canonical `ARVYX_NATIVE_PROFILE` marker lets existing
cold-start guards recognize the writer even when its native home is fd-addressed.
The fresh adapter holds the ordinary profile-wide writer lock **and** a durable
fresh-launch claim. It does not weaken the normal existing-profile idle scan or
signal unrelated processes.

The installed Hermes Python source, dependencies, and standard library remain an
explicitly trusted dependency closure; they are **not** claimed to be sealed by
hashing Python. Every selected source ancestor must pass the existing no-follow,
non-writable-by-others native path policy. A private source/dependency snapshot
can be provisioned independently without copying identity, credentials, config,
or history. An incompatible Hermes API, missing dependency, interpreter that
cannot locate its standard library when sealed, or unavailable kernel sealing
fails closed with retained-state guidance. No live installation is repaired or
permission-relaxed automatically.

## Retained state and human setup

The root contains the native `profile/`, `workspace/`, newly enrolled `owner/`,
frontend bindings/logs, and `first-session.json` when owner New was acknowledged.
A failed initialization can leave only a partial native home; it is retained,
not relabeled as an initialized or authenticated session. Failed New, frontend
startup, attachment, and cleanup likewise never trigger root deletion or an
automatic launch retry.

The attached native setup wizard is the actionable human setup path. After
leaving it, any later setup or launch must explicitly select this retained
isolated home and separately authorize its lifecycle. This command does not
silently restart the stopped owner, renew expired consent, infer default resume,
copy authentication from another profile, or convert an old running-generation
proof into new authority.

## Executed verification

Initial targeted RED, before implementing this module:

```sh
PYTHONPATH=packages/arvctl/src /usr/bin/python3 -m pytest -q \
  packages/arvctl/tests/test_first_session.py
```

Result: **4 failed** (`ModuleNotFoundError` for the missing first-session module).
Subsequent targeted regression receipts include terminal/consent refusal before
publication, digest/sealed-byte identity, policy refusal, source/root replacement,
retained failed initialization, socket-length preflight, environment isolation,
profile-wide claim exclusion, exact native setup plans, atomic private receipts,
and unchanged attach-only behavior. Fixture schemas and mocked failure/admission
checks are unit evidence, not real native acceptance.

Final targeted GREEN command:

```sh
PYTHONPATH=packages/arvctl/src /usr/bin/python3 -m pytest -q \
  packages/arvctl/tests/test_first_session.py \
  packages/arvctl/tests/test_native_new.py \
  packages/arvctl/tests/test_cockpit_arvyx.py \
  packages/arvctl/tests/test_terminal_onboarding.py \
  packages/arvctl/tests/test_cockpit_native_runtime.py \
  packages/arvctl/tests/test_completion_fix4_C.py \
  packages/arvctl/tests/test_latest15_native_lifecycle.py::test_external_profile_writer_or_unknown_liveness_refuses
```

Result: **104 passed, 12 subtests passed**. The existing multithreaded `forkpty`
deprecation warning remains visible; no fork/process guard was disabled.

The real acceptance harness is `scripts/native_first_session_acceptance.py`.
It runs the actual CLI under a controlling PTY, confirms only the explicitly
selected disposable root, and never sends a provider prompt or answers setup.
It observes the rendered native setup prompt in Arvyx, reads the exact owner and
native frontend snapshot, detaches with the frontend gesture, and checks native
metadata, zero messages, no provider auth/config files, native pane bindings,
closed owner socket, and termination of its recorded native/server/watcher PIDs.
With an explicitly selected installed `strace`, it also rejects any
`AF_INET`/`AF_INET6` connect/sendto/sendmsg in the traced process tree.

The disposable run used the public `v0.1.0-alpha.0` Linux binary, independently
matched to the already admitted SHA-256
`4c29b4d9f65f35c566acadc729d03334be5458520f747db82f8c795ba6d1a3ca`.
It used actual installed Hermes Python source/native APIs plus their required
code dependencies in a protected credential-free source snapshot. No synthetic native writer or mocked process was used for this receipt. The
executed harness returned **PASS** for real PTY/native rendering, exact binding,
attachment/detachment, zero provider messages, verified own-process cleanup, and
no Internet socket calls in the traced process tree. System Python 3.12
provided sealing support; its reviewed executable digest was
`e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f`.
The installed native schema API warned about its linked SQLite version and
selected DELETE journaling itself; this change did not suppress that warning or
modify the installed runtime.

Successful local acceptance establishes credential-free native setup, exact
binding, attachment/detachment, retention, and scoped cleanup—not authenticated
provider compatibility. Independent review, GitHub CI, PR readiness, merge, and
release are separate gates. No local full CI, provider call, paid resource,
production install, live service change, push, PR mutation, or merge is part of
this implementation task.

## P2 review fixes: verified cleanup and final initialization authority

The initialization dispatch now repeats the pinned ancestry/inode, effective
execution policy, and original absolute consent-expiry checks **after** exclusive
root/profile/workspace publication and directory fsync, immediately before the
native initialization subprocess. Expiry or policy changes at that boundary
refuse dispatch; the newly published directories remain for inspection. The same
guard remains active for subsequent native New admission.

Frontend cleanup retains the actual server and watcher `Popen` handles. A failed
or timed-out graceful server stop falls back to terminating/killing and bounded
reaping of those owned handles. A successful stop command alone is not proof of
termination. PID files are observational evidence only, never signal authority.
Unresolved watcher/server cleanup cannot turn successful attach into exit zero.
The first-session owner also accounts for listener-thread and owner-close
failures. Its final receipt contains `cleanup.verified`, `cleanup.unresolved`,
and the frontend cleanup result; `owner_status` is `cleanup_failed`, not `closed`,
when cleanup remains unresolved. Existing attach errors and nonzero statuses are
preserved; diagnostics and the first-session receipt retain cleanup failures.
No cleanup path deletes native state or signals discovered/reconstructed PIDs.

Executed P2 RED (system Python is required for Linux sealing support):

```sh
TMPDIR=/home/clawd/ax PYTHONPATH=packages/arvctl/src /usr/bin/python3 -m pytest -q \
  packages/arvctl/tests/test_first_session.py \
  -k 'final_init_dispatch or owned_cleanup'
```

Result before the production fix: **3 failed, 1 passed, 16 deselected**.
Expiry and policy mutations after workspace publication incorrectly reached the
mocked native dispatch; the cleanup verifier did not yet exist. The ancestry
replacement case already refused dispatch. See the external `p2-red.txt` receipt.

Executed P2 GREEN:

```sh
TMPDIR=/home/clawd/ax PYTHONPATH=packages/arvctl/src /usr/bin/python3 -m pytest -q \
  packages/arvctl/tests/test_first_session.py \
  packages/arvctl/tests/test_deep10fix_07.py \
  packages/arvctl/tests/test_native_new.py \
  packages/arvctl/tests/test_cockpit_arvyx.py \
  packages/arvctl/tests/test_terminal_onboarding.py \
  packages/arvctl/tests/test_cockpit_native_runtime.py \
  packages/arvctl/tests/test_completion_fix4_C.py \
  packages/arvctl/tests/test_latest15_native_lifecycle.py::test_external_profile_writer_or_unknown_liveness_refuses
```

Result: **120 passed, 24 subtests passed**, with the existing multithreaded
`forkpty` deprecation warning. These are targeted regressions, not full local CI.
Failure-path coverage includes successful detach with unkillable mocked watcher,
unresolved server and owner-close failures written to `cleanup_failed` receipts,
expiry/policy/ancestry changes between publication and init, retained native state,
and real owned child reaping when the server-stop command fails. Legacy cleanup
fixtures now explicitly model TTY admission and scalar child PID observations.

The real credential-free PTY/native harness was rerun with the already provisioned
public binary and system Python, using the existing protected Hermes source
snapshot, policy, and installed strace. The new receipt is
`/home/clawd/arvyx-first-session-evidence/acceptance-final7.json`; it embeds the
complete final native first-session receipt. Result: **PASS**, exact owner/native/
pane/workspace/tab binding, attached and detached, zero messages, no auth/config
markers, all owned processes gone, owner socket closed, and no AF_INET/AF_INET6
connect/sendto/sendmsg calls. `cleanup.verified` and frontend verification are
both true, with empty unresolved lists. The retained disposable root is `final7`.
The earlier `acceptance-final5.json` remains historical evidence, not evidence for
this changed candidate. Current source hashes are in the separate external
`candidate-p2.json` manifest. No commit, push, PR, local full CI, provider request,
or live gateway/pilot change was made. GitHub publication/CI remains with the
parent operator.

## CI run 42043984576 repair (PR 10, base `5fb7178`)

The complete failed-log file was parsed programmatically (5,975 lines), deduplicating
all pytest failure node IDs across the matrix and correctness shards. There were
**12 unique failing test cases**, grouped below. No collection/import errors were
present, including on Windows; missing platform markers were not the cause.

| Test in `packages/arvctl/tests/` | Cases | Cause and disposition |
| --- | --- | --- |
| `test_first_session.py::test_failed_native_init_retains_root_without_placeholder_database` | `[False]`, `[True]` | Long runner TMPDIR caused the socket preflight to mask the intended init failure. Use a separate bounded private socket fixture root. |
| `test_first_session.py::test_final_init_dispatch_guard_after_publication` | `[expiry]`, `[policy]`, `[ancestry]` | Same early socket refusal prevented reaching publication. All original mutation and no-dispatch assertions remain. |
| `test_first_session.py::test_existing_root_is_never_adopted` | one | Same early socket refusal; existing-state non-adoption assertion remains. |
| `test_first_session.py::test_policy_denial_precedes_creation` | one | Same early socket refusal; effective policy denial and no-creation assertions remain. |
| `test_first_session.py::test_frontend_failure_retains_acknowledged_native_state` | `[None]`, `[server]`, `[owner]` | Same early socket refusal; retained native metadata, valuable state, and cleanup receipts remain checked. |
| `test_hermes_history.py::test_main_rejects_history_only_terminal_without_creating_onboarding_state` | one | Stale diagnostic assertion. Assert the current attach-only refusal, required flags, separate first-session guidance, and no-provider/owner-start statement. |
| `test_native_new.py::test_empty_placeholder_database_is_not_a_bootstrap` | one | Windows mode bits do not express DACL write permissions. NativeRuntime now uses the existing platform-aware `private_paths.not_writable_by_others` guard (unchanged POSIX bit policy, Windows trusted-SID DACL policy). Fixture executable permissions also use `make_private`, not Windows chmod. |

The Linux 3.11/3.12/3.13 jobs each reported the ten first-session cases and the
history diagnostic case. Correctness shard 2 reported the ten first-session
cases; shard 1 reported the diagnostic case. Windows 3.11/3.12/3.13 each reported
only the empty-placeholder case. The aggregate `test` job failed because
`CORRECTNESS_RESULT=failure`; its security and integration results were success.
These are deterministic failures, not flakes. No workflow or coverage gate changed.

### Fixture architecture and regression evidence

`short_fixture` now deliberately sets an owner-only long private TMPDIR on every
invocation. Its socket tree is independently created with `TemporaryDirectory`
under the short test base `ARVYX_TEST_SOCKET_TMPDIR`, defaulting to the test user's
home. The fixture verifies its private mode and complete longest socket budget,
cleans up only its newly created tree, and never chmods an ancestor. This override
is **test-only**, not a production option. On hosts with long home paths, set it
to an existing short test base. Local execution here selected the designated
scratch directory. The production `<104` encoded-byte guard is unchanged.

`test_short_fixture_preserves_real_socket_budget_under_long_private_tmpdir`
asserts that a real long destination is still refused without publication, then
binds/connects/exchanges bytes on a real AF_UNIX socket at the fixture's longest
frontend pathname. The existing inode-replacement, source/admission, and explicit
overlength tests remain real at their original boundaries. The original
fixture's mocked ancestry admission is unchanged: these tests are **not** proof
of production native ancestry acceptance. No proc-fd aliases or symlinked short
roots are used to hide noncanonical profiles.

Targeted RED with long private TMPDIR, before changing fixture placement:
**10 failed, 13 passed**, all ten matching the hosted runner's socket-budget
failures. A new platform-policy delegation test also failed before the production
change (`DID NOT RAISE` when the platform write policy denied admission). It now
checks both admission and denial. The history assertion was independently RED
before its correction.

Final targeted command (system Python is necessary for executable sealing):

```sh
ARVYX_TEST_SOCKET_TMPDIR=/home/clawd/.hermes/cache/scratch \
PYTHONPATH=packages/arvctl/src /usr/bin/python3 -m pytest -q \
  packages/arvctl/tests/test_first_session.py \
  packages/arvctl/tests/test_native_new.py \
  packages/arvctl/tests/test_hermes_history.py \
  packages/arvctl/tests/test_cockpit_native_runtime.py \
  packages/arvctl/tests/test_verified_private_bytes.py
```

Result: **60 passed, 31 subtests passed**, with the existing multithreaded
`forkpty` deprecation warning visible. `git diff --check` passed. The targeted
runtime tests include real offline child execution; no provider was called.
The ambient agent Python lacks fcntl sealing constants and is not a substitute
for the system Python used by these Linux tests.

A fresh real native acceptance harness invocation was attempted against a new
scratch root with the provisioned public binary, protected native source, and
strace. It **refused before creation** with `unsafe native artifact ancestor`:
`/home/clawd/.hermes/cache` is mode `0775`. No ancestor permissions were changed,
no admission guard was mocked, and no alternate live/default/pilot profile was
used. The previously recorded native acceptance above remains historical; this
attempt is not a new native PASS. A new fully admitted harness run requires an
operator-approved protected short location outside this task's scratch boundary.

External local receipts are `arvyx-ci-failure-inventory.json`,
`arvyx-ci-long-red.log`, and `arvyx-ci-targeted-green.log` in the designated scratch
directory. Windows execution and the full hosted matrix remain unverified until
the parent reviews/publishes and authorized GitHub CI runs. No full local CI,
commit, push, workflow dispatch, live service change, provider call, or paid call
was performed. Release remains HOLD.

Native references: [Hermes sessions](https://hermes-agent.nousresearch.com/docs/user-guide/sessions)
and [isolated profiles](https://hermes-agent.nousresearch.com/docs/user-guide/profiles).
The attested writer/setup API contract is witnessed in the selected installed
Hermes implementation, rather than guessed from an empty SQLite file.
