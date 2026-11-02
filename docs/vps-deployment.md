# VPS Deployment

This runbook deploys the authenticated Control Center API on a single Linux VPS.
The container is published on loopback only; Caddy or another reverse proxy owns
the public TLS endpoint.

## Requirements

- A supported Linux VPS with Docker Engine 25.0+ and Docker Compose 2.20+.
- A DNS record pointing your chosen hostname at the VPS.
- TCP 80/443 open to the internet. Keep 8765 closed externally.
- At least 1 GiB RAM and 2 GiB free disk for a small installation.
- A non-root operator account with access to Docker.

Docker access is effectively root-equivalent. Use a dedicated operator account,
patch the host regularly, and do not add unrelated users to the Docker group.

## 1. Prepare configuration

```bash
git clone https://github.com/Arven-Digital/arvyx.git
cd arvyx
cp .env.example .env
umask 077
python3 scripts/create_secret_file.py secrets/arvyx-control-secret
chmod 600 .env
python3 scripts/docker_preflight.py --secret-file secrets/arvyx-control-secret
```

Before preflight, replace all `change-me` values. Choose a deployment-specific
`COMPOSE_PROJECT_NAME`, generate a unique 8-32 character lowercase
`ARVYX_DEPLOYMENT_ID`, and set
`ARVYX_DATA_VOLUME=<project>_<deployment-id>_arvyx-data`. The preflight rejects
copied placeholders and mismatched volume identities, so two checkouts on one
host cannot silently share a volume. Set `ARVYX_DOMAIN` to your real hostname.
The host bearer file stays operator-private (`0600` via `create_secret_file.py`).
Before starting the API, stage it onto the data volume as
`/data/.arvyx-control-secret` (uid `10001`, mode `0400`) with
`scripts/stage_control_secret.py`. The value is not placed in the container
environment or image. Never commit `secrets/`, paste its value into tickets, or
put the bearer value in a URL.

## 2. Build and initialize persistent state

```bash
docker compose build --pull arvyx-server
set -a; . ./.env; set +a
python3 scripts/stage_control_secret.py \
  --secret-file "$ARVYX_CONTROL_SECRET_FILE" \
  --volume "$ARVYX_DATA_VOLUME" \
  --image "${ARVYX_IMAGE:-arvyx:local}"
docker compose run --rm --no-deps arvyx-server \
  arvyx init /data/vault --json
python3 scripts/stage_control_secret.py \
  --secret-file "$ARVYX_CONTROL_SECRET_FILE" \
  --volume "$ARVYX_DATA_VOLUME" \
  --image "${ARVYX_IMAGE:-arvyx:local}"
```

The explicit project/deployment-scoped volume holds the vault, append-only event
log, audit log, and operation journal. Preflight and backup/restore fail if the
volume name is not scoped to both `COMPOSE_PROJECT_NAME` and
`ARVYX_DEPLOYMENT_ID`; this prevents copied or disposable projects from silently
attaching the production volume. The application container runs as UID 10001, with
a read-only root filesystem, no Linux capabilities, and `no-new-privileges`.

## 3. Start and verify locally

```bash
docker compose up -d arvyx-server
docker compose ps
set -a; . ./.env; set +a
base="http://127.0.0.1:${ARVYX_PORT:-8765}"
secret="$(cat "$ARVYX_CONTROL_SECRET_FILE")"
# Synthetic wrong-credential placeholder for the 401 checks below; kept in a
# variable so the literal `Bearer <value>` shape never appears in this file.
wrong_credential="deliberately-wrong"
curl --fail --silent --show-error "${base}/health" # gitleaks:allow -- documented auth acceptance block
test "$(curl --silent --output /dev/null --write-out '%{http_code}' "${base}/summary")" = 401
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "Authorization: Bearer ${wrong_credential}" "${base}/summary")" = 401
test "$(printf 'Authorization: Bearer %s\n' "$secret" | \
  curl --silent --output /dev/null --write-out '%{http_code}' \
  -H @- "${base}/summary")" = 200 # gitleaks:allow -- operator-provided secret
unset secret wrong_credential
```

The Compose mapping is intentionally `127.0.0.1` only. Do not change it to
`0.0.0.0` to save a reverse-proxy step; that would expose the API over plain
HTTP.

## 4. TLS reverse proxy

Install Caddy from its official packages and write `/etc/caddy/Caddyfile` with
TLS outside and loopback HTTP inside; a minimal, hardened example:

```caddyfile
{
	servers {
		timeouts {
			read_body 10s
			read_header 5s
			write 30s
			idle 2m
		}
		max_header_size 32KB
	}
}

{$ARVYX_DOMAIN} {
	encode zstd gzip
	request_body {
		max_size 2MB
	}
	reverse_proxy 127.0.0.1:{$ARVYX_PORT} {
		transport http {
			dial_timeout 5s
			response_header_timeout 15s
			read_timeout 15s
			write_timeout 15s
		}
	}
	header {
		Strict-Transport-Security "max-age=31536000"
		X-Content-Type-Options "nosniff"
		X-Frame-Options "DENY"
		Referrer-Policy "no-referrer"
		-Server
	}
	log {
		output file /var/log/caddy/arvyx-access.log
		format json
	}
}
```

The body cap sits above the API's own 1 MiB limit so the API, not the proxy,
produces the documented refusal; the Caddy package creates `/var/log/caddy`;
leave `log_credentials` off (the default) so bearer headers never reach the log.

Compose `.env` is not inherited by systemd. Install an explicit root-owned
environment file and service drop-in:

```bash
set -a; . ./.env; set +a
printf 'ARVYX_DOMAIN=%s\nARVYX_PORT=%s\n' "$ARVYX_DOMAIN" "${ARVYX_PORT:-8765}" \
  | sudo tee /etc/caddy/arvyx.env >/dev/null
sudo chmod 0600 /etc/caddy/arvyx.env
sudo install -d -m 0755 /etc/systemd/system/caddy.service.d
printf '[Service]\nEnvironmentFile=/etc/caddy/arvyx.env\n' \
  | sudo tee /etc/systemd/system/caddy.service.d/arvyx.conf >/dev/null
sudo env ARVYX_DOMAIN="$ARVYX_DOMAIN" ARVYX_PORT="${ARVYX_PORT:-8765}" \
  caddy validate --config /etc/caddy/Caddyfile
sudo systemctl daemon-reload
sudo systemctl restart caddy
sudo systemctl is-active --quiet caddy
```

Caddy obtains and renews TLS certificates automatically when DNS and ports
80/443 are correct. If you use nginx, Traefik, or a cloud load balancer, preserve
the same boundary: public TLS outside, loopback HTTP inside.

Verify the public endpoint without printing the secret:

```bash
set -a; . ./.env; set +a
secret="$(cat "$ARVYX_CONTROL_SECRET_FILE")"
# Synthetic wrong-credential placeholder for the 401 checks below; kept in a
# variable so the literal `Bearer <value>` shape never appears in this file.
wrong_credential="deliberately-wrong"
curl --fail --silent --show-error "https://${ARVYX_DOMAIN}/health" # gitleaks:allow -- documented auth acceptance block
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "https://${ARVYX_DOMAIN}/summary")" = 401
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "Authorization: Bearer ${wrong_credential}" \
  "https://${ARVYX_DOMAIN}/summary")" = 401
test "$(printf 'Authorization: Bearer %s\n' "$secret" | \
  curl --silent --output /dev/null --write-out '%{http_code}' \
  -H @- "https://${ARVYX_DOMAIN}/summary")" = 200 # gitleaks:allow -- operator-provided secret
unset secret wrong_credential
```

## Firewall baseline

Allow only SSH from your administration source when practical, plus public
HTTP/HTTPS. Port 8765 must not be publicly reachable. Confirm from another host;
do not rely only on the cloud control-panel rule display.

## Backups

The JSONL event log is authoritative and the vault is ordinary files. Use the
fail-closed utility; it stops writes, streams UID/GID-preserving data from
Docker, verifies state and the audit chain, excludes the staged runtime bearer,
writes an atomic archive plus SHA-256 sidecar, restarts the service in a
`finally` path, and enforces retention. The operator-private host secret is not
backup data; restore stages its current value onto each candidate so an old
archive cannot revive a revoked bearer. `--off-host-dir` must point at an
encrypted mounted remote volume:

Backups and restores require a deployment-authority binding. Set
`ARVYX_BACKUP_AUTHORITY_ID` to the stable identity of the data authority (not a
hardware machine ID) and point `ARVYX_BACKUP_BINDING_KEY_FILE` at a 0600 file in
the existing host-private secret-file lane. The key file must be a real regular
file: symlinked secret mounts (Vault, Kubernetes, Docker Secrets) are rejected
fail-closed because the key is read with `O_NOFOLLOW` and validated via `fstat`
on the opened descriptor; secret managers must materialize a real 0600 regular
file (for example via a mount that writes the file directly, or a small
provisioning step that copies the secret into the host-private lane) before
backup or restore runs. Primary and legitimate failover
hosts use the same authority ID and independently provisioned key; unrelated
deployments use different identities and keys. Each archive gets a versioned
`*.binding.json` HMAC manifest covering its name, SHA-256, source deployment ID,
and authority ID. Off-host publication stages the archive, checksum, and
binding manifest under hidden temp names inside the off-host directory and
commits them with `os.replace` in binding-first order, so a crash mid-publish
never leaves a visible unbound or partially-restorable off-host backup.
Restore authenticates this manifest before any Docker
inspection or candidate creation and reports `restore binding target mismatch`
for a wrong authority. Missing, malformed, unknown-version, tampered, and
unbound manifests fail closed.

```bash
umask 077
set -a; . ./.env; set +a
backup_root="${ARVYX_BACKUP_DIR:-$HOME/arvyx-backups}"
off_host="${ARVYX_BACKUP_OFF_HOST:?set an encrypted off-host mount}"
python3 scripts/backup_restore.py --project "$COMPOSE_PROJECT_NAME" backup \
  --backup-dir "$backup_root" \
  --off-host-dir "$off_host" \
  --retention 7
```

Use `--local-only` only as an explicit disposable-drill override. A backup that
has never been restored is a wish, not evidence.
Run both maintenance commands from the deployment checkout. Load its `.env`
each time: the Python utility reads deployment settings from the exported
environment, and the project must match the scoped `ARVYX_DATA_VOLUME`.
The examples explicitly pass the exported `COMPOSE_PROJECT_NAME`, matching the
CLI's environment-derived default (which falls back to `arvyx` only when absent).
Do not replace the deployment-specific setting with a copied literal project name.
Only source the trusted deployment-owned `.env`; sourcing executes shell input.

### Restore drill

Use a disposable VPS first. Restore copies the archive into a newly labelled
candidate volume and preserves the previous volume. It verifies per-operation
ownership labels before claiming cleanup authority. Staging uses the standalone
`scripts/restore-candidate.private.yml` definition with `network_mode: none`, no
published ports, and no automatic restart. Its API binds to container loopback;
the acceptance probe reaches it through `docker exec`, not a host port. Do not
merge this private staging definition with production Compose.

Staging verifies data-aware health, the `401/401/200` authentication contract,
an idempotent protected mutation, and the audit chain. Restore then removes and
reseeds the candidate from the verified archive so the acceptance mutation is
not promoted, stages the current bearer again, verifies pristine health and the
mounted volume, and tears down staging. Candidate data is fsynced before
production teardown. The cutover atomically updates `ARVYX_DATA_VOLUME` in
`.env`, including file and parent-directory fsync, before production candidate
startup can admit clients. Production restore explicitly selects the maintained
`docker-compose.yml` and this same env file; arbitrary Compose overrides are not
part of this procedure.

Recovery depends on the phase:

- Before pointer commit, no production candidate has admitted clients. Restore
  attempts staging teardown, verifies or restores the previous pointer, and,
  if production teardown began, attempts a verified previous-volume restart.
  Candidate deletion requires proven teardown, pointer recovery, any required
  restart, and exact project, logical-volume, and restore-operation labels.
  Cleanup ownership is revoked before reseed removal and reacquired only after
  exact post-create inspection. Uncertain ownership or failed cleanup retains
  the candidate; `cleanup required` means operator cleanup is still needed.
- After pointer commit, the candidate pointer remains authoritative even if
  production startup, health, or mount verification fails. A failed startup
  command may already have admitted clients and acknowledged writes. Restore
  attempts to stop the candidate and verify it stopped, then raises
  `VolumePointerReconciliationRequired`; automatic rollback and candidate
  deletion are forbidden. Retain the candidate container and retain both volumes.
  Do not repoint `.env` to or restart the previous volume, or delete or reseed
  the candidate before reconciling candidate authority, including acknowledged
  writes. Inspect the durable pointer and actual container mount and prove the
  admission fence before deciding recovery. If stopping fails or cannot be
  verified, isolate the service immediately.
- If the pointer is unreadable, malformed, unexpected, or publication/rollback
  durability cannot be proven, reconcile `.env` and actual mounts before any
  manual restart or deletion. After a crash, retain both volumes and establish
  whether candidate admission occurred before choosing recovery; an old volume
  is not proof that it is still authoritative. The deployment lock coordinates
  cooperating commands in this checkout only. External Docker commands, host
  failure, and uncatchable termination require operator reconciliation.

Failure JSON reports the error type and sanitized `candidate_volume` when known,
`cleanup_failures`, and `restart_failed`. An admission fence failure appears in
`cleanup_failures`; `restart_failed: false` does not establish that the previous
volume is running or that the admission fence succeeded. Treat every retained
candidate as sensitive: it may hold restored data and the current staged bearer.
Resolve the reported failure and authority before retrying restore.

```bash
set -a; . ./.env; set +a
python3 scripts/backup_restore.py --project "$COMPOSE_PROJECT_NAME" restore \
  "$HOME/arvyx-backups/<archive>.tar.gz" \
  --env-file .env \
  --confirm-cutover
```

Record the returned `active_volume` and `rollback_volume`. Run the authenticated
health check again from the operator host. After success, reload `.env` with
`set -a; . ./.env; set +a` before further Compose or maintenance commands so the
shell's exported volume follows the committed pointer. The previous volume is
retained as the explicit rollback volume; returning to it requires reconciling
any writes admitted by the candidate. Delete it only through a separate,
reviewed cleanup step after recovery is accepted.

This gate provides authenticated binding and integrity, not payload encryption.
Confidentiality still depends on the required encrypted off-host mount. AES-GCM
envelope encryption needs a separately governed encryption-key authority,
rotation/recovery policy, and failover key-distribution lane. Deriving a key
from a raw machine ID would break legitimate disaster recovery and is
deliberately not used.

## Upgrade and rollback

Before upgrading:

1. Read release notes.
2. Record the exact current immutable image reference and digest.
3. Take and verify a backup.
4. Run the target image's synthetic demo.

```bash
set -a; . ./.env; set +a
current_image="${ARVYX_IMAGE:?ARVYX_IMAGE must be an immutable digest reference}"
case "$current_image" in *@sha256:*) ;; *) echo 'current ARVYX_IMAGE is mutable; stop' >&2; exit 1;; esac
export ARVYX_IMAGE='<registry>/<image>@sha256:<reviewed-target-digest>'
docker compose pull arvyx-server
docker compose --profile demo run --rm arvyx-demo
```

Before recreating production, persist the reviewed target in this deployment's
trusted `.env`. An export alone is not durable state: a fresh maintenance shell
would otherwise reload the old image. Record `current_image` privately outside
the checkout as the rollback reference. Stop concurrent upgrade/restore commands;
this example assumes a trusted operator-owned directory, not hostile writers.
The following commits only the image line, preserving other deployment settings:

```bash
python3 - "$ARVYX_IMAGE" <<'PY'
import os, re, stat, sys, tempfile
from pathlib import Path
image = sys.argv[1]
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}', image):
    raise SystemExit('a reviewed immutable image digest is required')
path = Path('.env')
if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
    raise SystemExit('deployment .env must be a regular non-symlink file')
lines = path.read_text(encoding='utf-8').splitlines()
matches = [i for i, line in enumerate(lines) if re.match(r'^\s*(?:export\s+)?ARVYX_IMAGE\s*=', line)]
if len(matches) > 1:
    raise SystemExit('duplicate ARVYX_IMAGE assignments require reconciliation')
if matches:
    lines[matches[0]] = 'ARVYX_IMAGE=' + image
else:
    lines.append('ARVYX_IMAGE=' + image)
fd, pending = tempfile.mkstemp(prefix='.env.image-', dir='.')
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(lines) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(pending, path)
    directory = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    if os.path.exists(pending):
        os.unlink(pending)
PY
target_image="$ARVYX_IMAGE"
unset ARVYX_IMAGE
set -a; . ./.env; set +a
test "$ARVYX_IMAGE" = "$target_image"
docker compose config --images | grep -Fx -- "$target_image"
docker compose up -d --no-build --force-recreate arvyx-server
```

Verify the container's configured immutable image and resolved image ID, health,
authentication, persistence and logs; retain that readback privately. If the
pointer committed but startup or readback failed, retain the target selection and
reconcile actual admission before rollback. For a compatible authorized rollback,
set `ARVYX_IMAGE="$current_image"`, run the same atomic `.env` update and fresh
reload/readback above with that prior digest, pull the exact image if necessary,
then recreate. Never leave `.env` selecting B while only the shell selects A (or
vice versa). A format migration or acknowledged writes can forbid rollback.
Compatibility testing must use a
real prior released digest via
`python3 scripts/docker_runtime_smoke.py --image-tag "$ARVYX_IMAGE" --skip-build --keep-image --previous-image "$current_image"`.
If a release changes
persisted formats, follow its migration note and restore the pre-upgrade backup
rather than guessing backward compatibility.

## Logs and privacy

```bash
docker compose logs --since 30m arvyx-server
```

The application is designed to redact literal secret shapes and logs secret
references rather than values. Infrastructure logs can still contain IP
addresses, paths, query strings, and operator timing. Restrict access, set a
retention policy, and never enable request-body logging at the reverse proxy.

## Demo only

The synthetic demo is isolated from the production volume and sends nothing:

```bash
docker compose --profile demo run --rm arvyx-demo
```

Do not copy real memory, production logs, private machine registries, or raw
credentials into the repository or synthetic fixtures.
