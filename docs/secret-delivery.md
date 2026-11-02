# Secret Delivery — private edge adapter, local implementation only

**Not deployed. No live enrollment, credential ingestion, restart, or public release is authorized.**
This is a new private adapter inside `scripts/control_plane_edge_proxy.py`, not an
integration with the external `arvyx-secret` broker. That broker has no verified
write/enrollment contract in this work. The previous standalone browser-client-
certificate dashboard prototype is retired. The browser uses the existing
`https://control.party` origin and never sends the shared V2 operator bearer for
Secret Delivery. The existing non-secret edge authentication path is unchanged.

## User flow

Open the dashboard, connect the approved operator Access session, select a
registered agent/runtime pathway, enter an exact environment key name and a
masked value, then Send. Names are never corrected or normalized. The configured
key allowlist and dotenv syntax must both allow the exact name (including a name
such as `anthtropic_auth`). Existing-name replacement requires a separate browser
confirmation bound to the current target/key/version and session. The receiver
uses compare-and-swap against its prepared destination version.

The browser does not store the value in local/session storage, logs, analytics,
URLs, or pending-operation queues. It clears the input after a successful save.
Status/replay uses the delivery ID, never a value fingerprint. A saved receipt
means a durable dotenv write, not a runtime restart, provider authentication, or
live validation of the new credential. The destination `.env` is intentionally
plaintext and owner-only, not encrypted-at-rest secret storage.

## Trust path

1. Cloudflare Access authenticates a human for the exact application. The
   loopback-only existing edge receives one `Cf-Access-Jwt-Assertion`.
2. Before **any** secret request-body read, the edge consumes the entire reserved
   `/secret-delivery*` namespace. Disabled configuration returns 503 without
   forwarding. Enabled operations verify the assertion every time, including
   bootstrap, prepare, send, and status. Failures return fixed errors and close
   the connection. Secret requests never enter the generic proxy body path or V2
   operation journal.
3. PyJWT + cryptography verifies fixed RS256, configured issuer and application
   audience, and required `iss`, `aud`, `sub`, `exp`, `iat`, `nbf`, and `type` claims.
   Time claims must be integers; there is no expiry leeway. Only `type: app` and
   an exact operator-enrolled subject allowlist are accepted. Service token
   markers (`common_name`, `service_token_id`, `service_token_status`) are denied.
   Email, forwarded user headers, loopback, browser certificates, and the shared
   operator bearer confer **no** secret permission. Enrollment must explicitly
   establish that every allowed subject is a human, not a service identity.
4. Signing keys come only from
   `https://<configured-team>.cloudflareaccess.com/cdn-cgi/access/certs` with CA
   and hostname validation. No token-controlled URL, proxy discovery, redirect,
   embedded JWK, unsigned fallback, or algorithm negotiation is accepted. JWKS
   is limited to 65,536 bytes and 16 RSA signing keys (2048–8192 bits), cached
   at most 300 seconds, with refresh attempts limited to once per 10 seconds.
   Unknown keys may trigger a bounded refresh; invalid/failing refreshes cannot
   extend expired cache entries. Rotation replaces the validated key set
   atomically. Network connect/read timeouts are three seconds; connected I/O
   also has a three-second wall-clock abort timer. System DNS resolution remains
   subject to the host resolver's timeout policy, not a token-selected host.
5. An internal verified principal is passed to the service, binding session,
   CSRF, preparations, receipts, and replay to the stable operator `sub`. Session
   lifetime is at most 15 minutes and never beyond its bootstrap JWT expiry.
   Every subsequent request still needs a fresh valid assertion; possession of
   a live cookie is insufficient. Expiry is rechecked after reading the body.
6. Exact configured Origin, one custom header, same-origin Fetch Metadata (when
   present), host-only Secure/HttpOnly/SameSite=Strict session cookie, session
   CSRF, POST-only routes, JSON-only single length/type headers, and a 98,304-byte
   body cap precede mutation. Dashboard responses include CSP
   `frame-ancestors 'none'` and `X-Frame-Options: DENY`; the edge forwards both.
7. The service uses the existing private mTLS transport with CA, hostname, and
   enrolled destination certificate pin verification **before** HTTP payload
   transmission. No redirects/retries. The stable actor travels inside this
   authenticated envelope, not as a client-selected public actor field.
8. The receiver checks the enrolled sender certificate pin, target/agent/runtime,
   key allowlist, actor-bound preparation and dedupe metadata, then calls the
   existing writer. The writer remains unchanged in this review round.

The private receiver's accept loop never performs a TLS handshake. Handshakes
run inside the eight-worker semaphore with a five-second timeout and silent
close on saturation/failure. A stalled handshake does not serialize other
clients. The sender/receiver still require TLS; no downgrade is introduced.

## Payload, ambiguity, and metadata migration

Values are limited to 65,536 UTF-8 bytes, subject also to the complete JSON body
cap. Browser and sender use compact UTF-8 JSON (`ensure_ascii=False`). The full
outbound envelope, including trusted actor/target metadata and JSON escaping,
is validated **before durable receipt reservation**. An invalid/oversized
outbound envelope does not create a misleading ambiguous receipt.

The ingress and receiver durably reserve metadata-only `ambiguous` receipts
before dispatch/write. Any uncertainty after dispatch remains ambiguous; no
blind resend. Receiver responses are bounded before JSON parsing and accept
only `{exists, version}` for prepare or `{status}` for send. Secrets, value hashes,
raw exceptions, and secret-bearing URLs are never included in receipts or logs.

Both SQLite metadata stores add `actor_bound INTEGER NOT NULL DEFAULT 0` to old
schemas. New rows explicitly set it to 1 and persist the verified subject. Old
rows (including literal `operator`) remain unbound and inaccessible to **all**
new actors; they continue to block ID reuse rather than silently inheriting an
operator's authority. Get, reserve/replay, and finish enforce actor scope. There
is no automatic deletion/migration that grants access to legacy rows.

## Explicit local configuration contract

The edge remains disabled unless started with
`--secret-delivery-config /operator-owned/secret-edge.json`. This is a separate
private, owner-only file, not an environment-based identity shortcut:

```json
{
  "enabled": true,
  "origin": "https://control.party",
  "access_issuer": "https://YOUR-TEAM.cloudflareaccess.com",
  "access_audience": "EXACT_APPLICATION_AUDIENCE",
  "operator_subjects": ["EXACT_ENROLLED_HUMAN_SUBJECT"],
  "manifest": "/operator-owned/secret-destinations.json",
  "vault": "/operator-owned/amc-vault"
}
```

These placeholders are deliberately not a working enrollment. The issuer must
be the exact lowercase HTTPS Access team origin, with no custom path/port/query.
Unknown config fields are rejected. The only accepted public origin is
`https://control.party`. Missing dependency or invalid explicit configuration
fails startup closed, rather than reverting to shared-bearer authorization.

Destination manifest (also private owner-only):

```json
{
  "enabled": true,
  "origin": "https://control.party",
  "receipts": "/operator-owned/metadata/ingress.sqlite",
  "targets": [{
    "id": "enrolled-pathway", "agent": "registered-agent",
    "runtime": "registered-runtime", "url": "https://receiver.internal/v1/deliver",
    "server_pin": "EXACT_ENROLLED_CERTIFICATE_SHA256",
    "ca_file": "/operator-owned/receiver-ca.pem",
    "client_cert": "/operator-owned/sender.pem",
    "client_key": "/operator-owned/sender.key",
    "allowed_keys": ["anthtropic_auth"]
  }]
}
```

Agent/runtime IDs must match the operator-owned AMC registry. No client-provided
host, path, filename, shell command, profile, or enrollment is accepted. Receipt
DB parents must be owner-only. The receiver's separately enrolled private config
supplies `enabled`, `bind`, `port`, `target`, `agent`, `runtime`, `directory`,
`filename`, `owner_uid`, `allowed_keys`, `receipts`, `certificate`, `private_key`,
`client_ca`, and `sender_client_sha256`. Run its existing module only after
separate deployment approval: `python -m arvyx_control.secret_delivery_receiver
--config /operator-owned/receiver.json`.

## Dependency and test lanes

Core project runtime dependencies remain empty. `secret-edge` is the narrowly
scoped optional extra, bounded to PyJWT 2.x and cryptography 50.x; deploy using
`requirements/secret-edge.lock` with `--require-hashes`, not the unrelated MCP
client lock. `SECRET_EDGE_LICENSES.json` inventories its four locked packages.
No live agent virtualenv was changed by this implementation.

Local isolated verification commands:

```sh
python3 -m venv /tmp/amc-secret-edge-review-venv
/tmp/amc-secret-edge-review-venv/bin/python -m pip install --require-hashes -r requirements/dev.lock -r requirements/secret-edge.lock
make ci PYTHON=/tmp/amc-secret-edge-review-venv/bin/python
/tmp/amc-secret-edge-review-venv/bin/python scripts/license_notice_check.py --secret-edge
```

The tests use actual edge handlers, signed synthetic JWTs, injected **test-only**
key sources, localhost TLS receivers, temporary destination files, and no real
credentials. Optional Playwright rendering and actual Hermes loader probes are
separate explicit lanes; unittest skips for those do not count as their PASS.
No test-mode issuer/key/identity bypass is configurable in the production CLI.

## Remaining deployment gates

- Approve exact human Access subjects, team issuer, application audience, and
  effective Access policy. Confirm the deployed assertion's claim contract.
- Approve the optional edge dependency installation and private configuration;
  ensure the edge process can import the installed package while retaining its
  current non-secret launch/auth behavior.
- Enroll each target and sender certificate, CA, hostname, pin, runtime owner,
  allowed keys, registry mapping, receiver binding, and owner-only metadata path.
- Confirm Cloudflare/tunnel/reverse-proxy handling of assertion headers, request
  body/log redaction, origins and anti-frame response headers. No live edge
  validation or restart is part of this local round.
- Review migrations/backups for any prototype receipt stores; legacy rows cannot
  be reassigned to a newly enrolled subject.
- Independent security review remains required. Fable authentication is blocked;
  no paid API or alternate-model review was silently substituted.
- Approve deployment and any later runtime reload separately. Public release HOLD.
