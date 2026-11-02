# Local quickstart (verified journey)

This is the exact local journey exercised end to end on a clean Linux user account
on 2026-10-31 (headless Chromium via Playwright, synthetic Hermes metadata only).
It is the verified operator journey, not an install promise for platforms whose
receipts do not exist yet.

## 1. Install

From a checkout, into a new private virtualenv (Python 3.11+):

```sh
python3 -m venv ~/arvyx-venv
~/arvyx-venv/bin/pip install setuptools==84.2.1 wheel
~/arvyx-venv/bin/pip install --no-build-isolation .
```

Build the browser frontend once (Node 24.11+):

```sh
(cd frontends/paperclip && npm ci && npm run build)
```

The local npm tarball path (`scripts/build_arvyx_npm.py`, `arvyx setup/doctor/web`)
is covered by `make npm-package-smoke`.

## 2. Enroll this machine (once)

```sh
python3 -m arvyx_control.machine_enrollment --home ~/arvyx-home \
  --machine my-laptop --confirm-local-enrollment
```

This creates a new private owner home with a vault, an event log, the machine
record and a local operator secret (`runtime/operator.secret`, mode 0600).

## 3. Start the owner (foreground)

The owner's `--root` is the home's `runtime` directory:

```sh
umask 077
printf '{"host_uid": %s, "allow_host": true}\n' "$(id -u)" > ~/arvyx-home/runtime/policy.json
python3 -m arvyx_control.cockpit --root ~/arvyx-home/runtime \
  --vault ~/arvyx-home/vault --state ~/arvyx-home/events.jsonl \
  --host my-laptop --execution-policy ~/arvyx-home/runtime/policy.json serve
```

Omit `--execution-policy` to deny every launch. `allow_host` lets explicitly
requested host-user shells run; it never grants root or sandbox.

The pilot live dashboard (`arvyx-cockpit web --live`) shows Tasks, Approvals and
Memory only when the owner was started with an explicit team credential: add
`--operator-credential-file ~/arvyx-home/runtime/operator.secret` to the `serve`
command above (the same private file the control room takes), or export an
existing agent token in `AMC_COCKPIT_AUTHORIZATION`. Without either, those
controls stay "unavailable or unauthorized" by design; nothing is inferred.

## 4. Open the web control room

```sh
printf '{"home": "%s"}\n' ~/arvyx-home > ~/arvyx-home/runtime/connection.json
python3 -m arvyx_control.cockpit_local \
  --connection ~/arvyx-home/runtime/connection.json \
  --frontend frontends/paperclip/dist \
  --operator-credential-file ~/arvyx-home/runtime/operator.secret \
  --discovery-home ~ --workspace-root ~/work --open
```

`--canary` validates the owner read-only without starting a listener. The
browser receives a one-time capability in the URL fragment; it is never printed.
On a shared host prefer `--browser-connection-out FILE` to `--open`: the browser
launcher's command line is visible to other local users.

## 5. Connect an existing agent

1. Click **Connect local real workspace**, then **Find local agents**. Discovery
   reads only known marker files (Hermes, OpenClaw, Claude Code, Codex, Cursor,
   Gemini, ...). Detection is not connection.
2. For a Hermes profile, a Claude Code state root (`~/.claude`) or a Codex state
   root (`~/.codex`) with no registered identity yet, enter a name under
   **No registered identity for this profile yet?** and click **Register new
   identity**. Review and confirm. This writes a fresh registry identity with no
   permissions for this machine; it does not connect, start or authenticate
   anything. The manual form below the list does the same for an explicit
   directory; choose the harness first.
3. Tick **Allow connecting this profile only**, click **Connect profile**, review
   and confirm. One profile binds exactly one identity.
4. Under **Sessions**, choose the destination, then **Last 5** or **All
   sessions** (search and pagination). **Inspect session metadata** is a reviewed
   read; it never opens a conversation or attaches a terminal.

The terminal path offers the same steps: run `amc setup --url http://127.0.0.1:PORT`
against the same listener (or `arvyx amc --prefix VENV setup ...` from the npm
package) and choose `discover`; leave the agent ID empty to register a new
identity.

## Current limits (not hidden)

- Hermes, Claude Code and Codex have read-only metadata connection adapters:
  session lists come from the harness's own store (Hermes `state.db`; Claude Code
  `projects/<project>/<uuid>.jsonl` and Codex `sessions/YYYY/MM/DD/rollout-*.jsonl[.zst]`
  file names and timestamps only), and **Inspect session metadata** reads a
  bounded prefix for routing fields. No transcript content is read or shown, and
  there is no launch, resume or attach for Claude Code or Codex. A compressed
  Codex rollout reports its working directory as unavailable. Other discovered
  harnesses show "No compatible local connection adapter is configured".
- "Create new agent" makes an isolated metadata profile only; sandbox, host and
  root runtime launch from onboarding remain unavailable.
- Opening the exact native session (terminal attach) needs the admitted
  onboarding-v1 native artifact (Linux x86_64; installed with `arvyx setup
  --native-binary ... --native-receipt ... --native-capability onboarding-v1`);
  other platforms report it as unavailable.
- Pairing a remote machine needs `--enable-pairing` and the approved
  cryptography extra.
- Organizer delegation needs separately provisioned authority.

Deployments created before the Arvyx rename follow their operators' private
migration runbook; a fresh installation needs none of it.
