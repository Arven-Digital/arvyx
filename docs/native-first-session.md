# First native session: blocked bootstrap, not a direct launcher

## Current disposition

**HOLD: a usable fresh owner/frontend bootstrap is not implemented.** The rejected
uncommitted `native_new.py` direct subprocess launcher has been removed, together
with its CLI flags. It did not create an owner or frontend binding, did not seal
approved executable bytes, accepted unsafe parent publication, and could delete
valuable new state after a child exit. None of these defects is an acceptable
substitute for integrating the owner-managed lifecycle.

`terminal` remains attach-only. Its three exact inputs are `--native-owner`,
`--frontend-home`, and `--arvyx-binary`. Telegram conversations, onboarding records,
and imported history are not native PTYs. Missing inputs now explain the explicit
read-only history route and link here. No default-profile resume is inferred.

## Existing integration and why a blank profile cannot use it yet

The reusable lifecycle is real, but is not a turnkey first-session bootstrap:

1. `cockpit.py:LocalCockpit.native_lifecycle` and
   `native_lifecycle.py:OwnerProducer` own launch admission, policy, single-use
   attempts, process generations, incarnation/epoch proofs, and native bindings.
   Hermes New requires an explicitly configured exact runtime, host execution,
   provider-start acknowledgement and the attested `hermes-titled-create-v1`
   protocol. It generates `chat -c` correlation arguments without an initial
   provider message; the conversation ID must be acknowledged in native metadata.
2. `cockpit_native_runtime.py:NativeRuntime.__init__` resolves `store` strictly.
   A freshly created empty profile has no `state.db`, so construction fails
   **before a launch plan or process exists**. `HermesProfile.connection` also
   rejects missing metadata. An empty SQLite file is not an initialization API:
   `plan_new` requires the real `sessions` schema and fails without it.
   Hand-authoring native DB rows/schema would fabricate native provenance.
3. `cockpit_arvyx.py:open_frontend` accepts only already owner-bound sessions.
   It validates/seals the Arvyx artifact using `VerifiedNative`, starts the
   isolated frontend, creates bridge panes and writes `bindings.json`. It is
   not a provider launcher. A new guard now requires real stdin/stdout TTYs
   before owner requests or frontend directory creation.
4. `native_presentation.py:NativePresentation` can present a verified owner proof
   into an already admitted frontend and register exact pane/workspace/tab IDs.
   Its identity check requires an existing binding document. This cannot by
   itself initialize an empty owner and frontend.
5. Owner Hermes launch currently obtains argv from `runtime.plan_new` and hands
   the executable path into `_start`. Rechecking the reviewed identity is not
   the same as carrying `VerifiedNative`'s sealed executable descriptor through
   the final exec. A new entry point must not claim that guarantee merely by
   hashing a path twice. `VerifiedNative` currently admits pinned Arvyx artifacts,
   not arbitrary Hermes launchers and their interpreter/dependency closures.

A separately selected, natively configured fresh isolated Hermes profile can
satisfy the metadata/authentication prerequisites without copying credentials,
but does not remove the executable-binding and first-owner/frontend orchestration
work. This change therefore does not advertise an unverified launch recipe.
Authentication/setup must be completed by the human in that selected isolated
profile; no secret, initial message or provider invocation was supplied here.

## Required integration work before claiming success

Implement and review a bounded native initialization/setup protocol; keep it
separate from conversation launch. Pin private parent/root/profile/workspace
identities through publication and dispatch, rejecting writable or replaceable
parents. Require a real interactive TTY, explicit human confirmation and an
explicit effective execution policy before creation. Retain created roots on
all post-launch outcomes; never infer that a failed leader means no valuable
state or descendants exist. Extend executable admission so approved Hermes
bytes/identity survive final owner exec. Then reuse owner-managed New followed
by `open_frontend` with the same admitted native object and read back exact
owner/native/pane bindings. Do not silently resume a live default profile or
replace the installed gateway/pilot. This is a cross-boundary lifecycle change,
not another direct-launch command.

## Executed evidence for this candidate

Targeted RED command (before removing the launcher and adding the TTY guard):

```sh
PYTHONPATH=packages/arvctl/src python -m pytest -q packages/arvctl/tests/test_native_new.py
```

Result: **2 failed, 2 passed**. Failures demonstrated an owner read without TTY
and exposure of the rejected `native-new` command.

Final targeted GREEN command:

```sh
PYTHONPATH=packages/arvctl/src /usr/bin/python3 -m pytest -q packages/arvctl/tests/test_native_new.py packages/arvctl/tests/test_terminal_onboarding.py packages/arvctl/tests/test_cockpit_arvyx.py
```

Result: **27 passed, 8 subtests passed**. Tests include missing native metadata,
empty-placeholder schema rejection, non-TTY refusal before owner access,
rejected direct command, attach-only diagnostics and existing frontend behavior.
Frontend launch tests use synthetic bytes/process mocks, not a real native UI.
The default agent Python 3.11 lacks `fcntl.F_ADD_SEALS` and the seal constants;
a broader targeted attempt correctly failed artifact sealing there. System
Python 3.12 exposes these constants and ran the final command above. No security
check was weakened or patched to manufacture platform support.

A new real PTY preflight using system Python reported:

```text
PTY stdin/stdout: True True
Retained probe root: <private-probe-root>
FileNotFoundError: [Errno 2] No such file or directory: '<private-probe-root>/profile/state.db'
Native executable dispatched: False; state.db created: False
PTY child exit: 0
```

The probe passed `/usr/bin/true` as a never-executed executable reference; it did
not launch Hermes, authenticate, or render Arvyx. This is real PTY evidence of
blocked native-runtime construction, **not evidence of a working native session**.
The private empty probe root is retained. Earlier direct-launch setup-screen
observations are not acceptance evidence for this candidate.

No CI/full suite/build, provider prompt, paid call, install, live mutation, push,
PR, merge or deployment was performed. The diff is uncommitted. Parent review
and any draft PR must state the bootstrap blocker, not describe this as a
completed first-session fix.
