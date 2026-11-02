# arvyx (npm)

The `arvyx` npm package carries the Arvyx Python wheel and the built web control
room, with a small Node launcher. Prerequisites: Node 24.11 or newer and Python
3.11 or newer with `venv` and `ensurepip`.

```bash
npm install -g arvyx
arvyx setup --prefix ~/.arvyx-venv
arvyx doctor --prefix ~/.arvyx-venv
arvyx web --prefix ~/.arvyx-venv --connection ~/arvyx-home/runtime/connection.json \
  --operator-credential-file ~/arvyx-home/runtime/operator.secret --discovery-home ~ --open
```

`web` needs an enrolled owner home (`~/arvyx-home` above) whose owner is running.
The enrollment and owner commands are in the repository README and in
`docs/local-quickstart.md`; they run with the venv's Python
(`~/.arvyx-venv/bin/python -m arvyx_control.machine_enrollment ...`).

- `setup` creates a new private virtual environment at the prefix and installs
  the bundled wheel offline, without dependencies, recording the setup intent and
  the exact wheel digest. It never overwrites an existing prefix, and an
  interrupted setup is retained as incomplete and refused by `doctor`.
- `doctor` verifies that the installed packages come from the bundled wheel and
  that the packaged web assets are present. It runs nothing else.
- `web` serves the control room on 127.0.0.1 only, with a one-time capability in
  the URL fragment (`--open` launches the browser; the capability is never
  printed; `--browser-connection-out FILE` writes it to a new private file
  instead, for shared hosts where command lines are visible to other users).
  `--discovery-home` enables bounded discovery of known harness profiles;
  `--enable-pairing` needs the approved cryptography extra.
- `amc --prefix PREFIX setup --url http://127.0.0.1:PORT` runs the same setup
  steps in the terminal against the running listener.

Every Python invocation uses isolated mode (`-I`) with the package payload
directory as its working directory.

## Native terminal frontend (Linux x86_64)

The native frontend is not bundled. Download `arvyx-linux-x86_64` and
`onboarding-v1-linux-x86_64.json` from the matching GitHub release and pass them
explicitly:

```bash
arvyx setup --prefix ~/.arvyx-venv --native-binary ./arvyx-linux-x86_64 \
  --native-receipt ./onboarding-v1-linux-x86_64.json --native-capability onboarding-v1
```

Only bytes whose digest is pinned by the shared artifact policy are copied; the
receipt binds provenance and cannot admit a new digest. `doctor` rechecks the
installed bytes without running them. Other platforms report the native
frontend as unavailable.

## Building the package from source

```bash
python scripts/build_arvyx_npm.py --output /absolute/new/directory
```

The builder requires the repository-pinned `setuptools==84.2.1`, builds the
wheel and the frontend offline from the committed lockfiles, and writes the
tarball next to the output directory; the tarball carries `LICENSE`, `NOTICE` and
the third-party notices under `licenses/`. `scripts/npm_package_smoke.py` installs
it into an empty prefix and exercises setup, doctor, refusal paths and web entry.
