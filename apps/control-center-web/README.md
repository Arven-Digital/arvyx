# AMC Observatory — Public-safe synthetic visual twin

A dependency-free local UI that demonstrates governed memory and control concepts without connecting to private infrastructure. Every record is deterministic synthetic fixture data.

## Run

```sh
cd apps/control-center-web
npm ci
npm run build
python -m http.server 4177 --bind 127.0.0.1 --directory dist
# open http://127.0.0.1:4177/?state=full
```

Replay states are selected with `?state=full|empty|loading|error` or the labeled state control.

## Verify and capture

```sh
npm run verify
```

This runs fixture/contract tests, builds a commit-stamped `dist/`, browser-smokes all states with reduced motion at 390px, then captures the full 4-state × 3-viewport matrix under `evidence/screenshots/`. Each image filename includes viewport, state, fixture build id, and commit id. Chrome defaults to `/usr/bin/google-chrome`; override with `CHROME_PATH`.

## Safety boundary

- Static local files and deterministic synthetic records only.
- No API endpoints, credentials, hostnames, private topology, or network writes.
- This is a visual concept twin, not a copy of a private deployment or operational dashboard.
