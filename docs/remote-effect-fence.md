# Authenticated remote final-effect authority

`remote_effect_fence.py` transfers one original local human approval to an
independently authenticated receiving owner. The source/coordinator and receiver
have separate policy databases. Root remains an independently attested receiver
mode, and requires the original explicit root acknowledgment. There is no second
human review and no renewal of the attempt or its expiry.

Trusted provisioning binds the coordinator identity and verified HTTPS origin,
an explicit CA file, a separate 256-bit authentication key for each receiver, the
receiver's current owner incarnation/epoch, all four target identity fields,
workspace device/inode, exact leaf session and mode allowlist. The receiver also
pins its own independent policy database and maps the authenticated original
organizer to an independently provisioned local organizer. Pairing, reachability,
a copied SQLite file, a matching UUID or a task-supplied path is insufficient.
Keys stay in private configuration and memory; durable attempt evidence retains
a ticket hash. No real credentials are provided by this implementation.

## Review and final admission

The sender's delegation review includes `execution_binding`, covering the exact
receiver/workspace/owner configuration. The digest and endpoint incarnation change
when that configuration changes. Web and terminal confirmation display this
binding. The original attempt, decision/actor, machine, agent, session, operation,
mode, root acknowledgment and expiry travel unchanged through
`delegations/fenced-execute`, `ExecutorEndpoint`, `LocalExecutorService`,
`OwnerProducer` and `LocalCockpit.native_lifecycle`.

Preflight authenticates the exact original ticket against the separately configured
coordinator. After blocking validation, the owner takes its independent local
policy guard and durably records uncertainty before requesting a permit. The
coordinator atomically consumes the original ticket and records an unsettled permit
before replying. HMAC-SHA256 authenticates the protocol version, coordinator and
receiver IDs, fresh durable nonce, operation and full payload in both directions.
Nonce replay is refused; the bounded nonce store fails closed at capacity.

The owner holds that permit across final admission, actual fork, exec acknowledgment
and publication. Final checks include the original expiry after network/lock waits,
local host/root policy, exact owner incarnation, target and workspace. A transport
timeout does not interrupt a continuing receiver and is never cancellation.
No task can select another coordinator or inject a guard callback.

## Revocation, uncertainty and settlement

A source or receiver policy mutation refuses with `RemoteEffectUnsettled` while
its durable permit is unsettled. It must not report completed revocation. If
revocation advances generation before permit admission, the original ticket cannot
produce a late first effect. With a shared local database, the existing portable
file guard remains supported and waits through admission/acknowledgment instead.

Successful owner acknowledgment sends authenticated settlement. Exceptions, lost
permit responses, lost acknowledgment, deadlines, expired leases and process death
never automatically release, refund or replay admission. Reopening preserves typed
uncertainty. An authenticated explicit reconciliation binds the exact retained
witness digest and settlement evidence. A lost acquire that never reached the
coordinator can be excluded only by atomically cancelling its exact original ticket;
a delayed acquire is then refused. Already settled acknowledgments can be reconciled
without a second effect. Revocation of future admission does not terminate a process
whose first effect has already occurred.

A partition can leave revocation unavailable indefinitely. That is deliberate:
there is no safe timeout that proves whether a remote first effect occurred.
Kernel/filesystem stalls are not claimed to have a hard real-time bound.

## Explicit composition

`delegation_runtime.load_delegations` reads a private owned bounded configuration
with exactly `database`, `authority_database`, `organizer`, `remote_fence_config`
and `endpoints`. It resolves existing identity handles; it never enrolls a role.
Each endpoint has `kind` (`leaf` or `remote`), `machine`, `agent`, `session` and
`configuration`. Remote configuration additionally pins `receiver_binding`,
`coordinator_id` and allowed `environments`. The local onboarding factory accepts
this operator-owned `delegation_config`; request bodies do not.

The private owner RPC `configure_remote_delegation(config, actor, expected,
confirmed)` loads an exact current-incarnation client configuration. Inspect the
running owner's `native_lifecycle` identity first, provision the peer binding
out of band, and confirm that exact identity through the existing owner request
CLI. Existing configuration cannot automatically rebind. The owner CLI's optional
`--remote-delegation-config` also requires an exact incarnation match; a stale
startup file fails closed with a provisioning error. The leaf CLI accepts a private
`remote_fence_config` reference alongside its existing local `authority_database`.

A client configuration has exactly `database`, `origin`, `authority_id`,
`receiver_id`, `key`, `binding`, `authority_database`, `organizer`,
`local_organizer`, `fixture_http` and `ca_file`. The receiver store binds these
settings, its canonical file identity and kernel boot; copying it is not adoption.

The coordinator runs as `python -m arvyx_control.remote_effect_fence --config
<private-config>`. Its existing authority database, vault/state, independently keyed
peer bindings, origin and TLS certificate/private-key references are configured
explicitly. `python -m arvyx_control.delegation_runtime --config <private-config>`
composes the authenticated loopback onboarding listener; approved remote transport
provisioning remains separate. No service is installed or started by a factory.

`fixture_http=true` permits only explicit numeric IPv4 loopback HTTP. Receipts label
it SYNTHETIC; it is not TLS, physical-host or provider acceptance. Production
requires verified HTTPS with the explicitly configured CA and independently keyed
peer identity. There is no reachability or self-reported identity fallback.

## Evidence boundary

The pass-5 focused tests exercise production policy, handlers, durable stores,
forwarding, leaf and final owner guard with harmless process recorders. Host-only
HTTP/Unix cases are separately opt-in and must run outside the sandbox. They do
not start providers or a native shell. TLS certificate deployment, actual independent
machines, containers, native Windows, power-loss behavior, full CI and a fresh
exact-source independent review remain separate acceptance work. No SAFE or release
approval follows from these source tests.

## Transport trust and listener admission

The receiver pins the exact configured CA bytes into both its SSL context and
durable trust fingerprint. Replacing a CA file cannot silently rotate an active
client's accepted issuers. Private configuration permission checks bind the exact
inode/metadata whose bytes were read. Production listener TLS handshakes run only
after bounded worker admission, inside the non-renewable request deadline. An idle
TLS client cannot block the serial accept loop; closing a timed-out connection
still does not cancel, settle or refund a durable effect permit.

The parent-host TLS fixture generates an ephemeral synthetic certificate and
checks idle-client exclusion plus a signed authenticated status request. It is
prepared, not executed here, and establishes no production certificate deployment
or physical-host acceptance.
