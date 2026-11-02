# Backup, restore, health, and warm-standby semantics

This is deployment-neutral guidance with synthetic examples only. Do not paste a live hostname, account, mount, service-unit override, credential location, pager destination, or receipt into this file; those belong in the untracked private operator runbook.

Machine-specific schedules, systemd units/drop-ins, secret-provider wiring, storage mounts, routing cutover, and measured production objectives belong in an untracked private operator runbook. Start from `templates/private-ops-backup-restore.example.md` and store the completed copy outside the public repository.

## Data classes and recovery contract

| Class | Recovery treatment |
|---|---|
| Curated vault, append-only control log, audit log, operation journal | Back up as source-of-truth data; quiesce or use the repository backup command |
| SQLite/search projections | Verify or rebuild from authoritative logs; do not treat projection-only copies as truth |
| Derived projection checkpoint (`<control-log>.projections.json`) | Derived cache beside the log; never restore or archive it as truth — a restored log without it serves, and deleting it is a supported recovery action |
| Runtime bearer and B7 binding key | Never archive; provision current values independently on each recovery host |
| Replica/failover markers | Preserve lineage evidence, but never let restore auto-promote a node |
| Authority evidence in V2 snapshots | Evidence-only bundle; never materialize in ordinary restorable data |

Set RPO/RTO objectives from deployment stakes in the private runbook. A schedule is not evidence: only a successful restore drill provides a recovery receipt.

Malformed or over-depth JSON in the derived control-projection checkpoint is
treated as an unreadable cache, not as corruption of an otherwise healthy
authoritative control log. Normal reads can fall back to the log, and forced
or ordinary checkpoint rebuilds can replace the invalid cache. Static repair
does not certify a current restore drill or executed regression.

## Public synthetic acceptance drill

Container health is not a full-history integrity certificate. Docker polls
`arvyx_control.container_readiness` every five seconds; Compose supplies the same
`/data/vault`, control-event and audit paths to the API. The state check inspects
record shapes only in the last 1 MiB, skips an initial partial record, and rejects
a torn final record. Corruption outside that window can coexist with `ok=true`.
The audit tail and pending-outcome checks are distinct from state-log validation.
HTTP `/health` is API liveness, not a replay of the control log. `serve_api` starts
the listener without a full-history integrity gate; ordinary control reads parse
events when needed and may use incremental/derived caches. Do not infer complete
history validation from startup or healthy polling. Full replay/projection and
backup/restore integrity qualification must be performed separately before
recovery admission or release claims; do not add unbounded replay to the periodic
health probe. These are source contracts, not an executed recovery receipt.

Run the dependency-free, disposable drill:

```bash
python3 scripts/synthetic_backup_restore_drill.py --json
```

It creates a synthetic primary under a temporary directory, writes authoritative sample state, creates an offline archive and manifest, deletes the entire primary, verifies the archive, restores into a new offline directory, compares every file hash, and starts a fresh process that must read the restored truth. A separate regression corrupts the archive and proves restore fails closed.

Receipt scope is explicitly limited to the two-file synthetic archive and a fresh
file-reader process. `restart_acceptance_verified` is a legacy synthetic-probe
field, not a Cockpit service restart. Additive fields
`product_composition_restore_verified`, `product_restart_acceptance_verified`
and `authority_reprovisioning_verified` are always false for this drill. No
successful result from this script closes cross-store product recovery acceptance.
The complete store inventory and quarantine/reconciliation obligations remain in
the cross-store recovery acceptance record (private, not exported).
The Focus75 regression for these scope fields is written but NOT_EXECUTED.

Receipt fields:

- `rpo_like_seconds`: measured time from the synthetic last mutation to backup completion;
- `rto_like_seconds`: measured time from declared synthetic loss through restore, integrity checks, and fresh-process acceptance;
- `elapsed_seconds`: total local drill runtime;
- `metric_scope`: explicitly says these are local synthetic measurements, not production RPO/RTO claims.

Exact regression command:

```bash
python3 -m unittest packages.arvctl.tests.test_synthetic_backup_restore_drill -v
```

## B7 authenticated backup binding

For the Docker backup path, configure an authority ID and an independently provisioned binding key through private environment/file references. B7 semantics are fixed:

1. The manifest authenticates the schema, authority ID, source deployment ID, archive name, and exact archive SHA-256.
2. Off-host publication stages hidden files and commits binding-first atomically; a crash must not expose an unbound archive.
3. Restore verifies binding before Docker inspection, extraction, or candidate creation.
4. A wrong key or unrelated authority fails loudly.
5. A legitimate failover deployment using the same authority ID and independently provisioned key may restore an archive created by another deployment ID in that authority.
6. Binding grants neither runtime authentication nor failover authority. Runtime bearer material is excluded and the current bearer is staged separately.
7. Binding is authenticity/target binding, not backup encryption. Use encrypted storage in a separate failure domain.

Regression evidence:

```bash
python3 -m unittest packages.arvctl.tests.test_backup_restore.BackupRestoreTests -v
```

## Generic warm standby

Use placeholders such as `https://primary.example.invalid` and `${SYNTHETIC_REPLICA_ROOT}` in public examples.

```bash
export ARVYX_REPLICA_TOKEN="<read-from-private-secret-store>"
arvyx replica sync \
  --from https://primary.example.invalid \
  --vault "${SYNTHETIC_REPLICA_ROOT}" \
  --auth-env ARVYX_REPLICA_TOKEN \
  --state-dir "${SYNTHETIC_REPLICA_STATE}"
arvyx replica status --vault "${SYNTHETIC_REPLICA_ROOT}"
```

`replica.read` can read all vault lanes, including lanes excluded from ordinary recall. Give it only to a dedicated replica identity. Sync repairs divergence and propagates deletions, but refuses a target that lacks the replica marker or looks like a primary.

Warm standby remains read-only. Writable failover is refused with
`ReplicaAuthorityUnavailable`: manual confirmation, `--auto`, `--force`, peer
reachability and lineage records cannot supply an independent authenticated
writer-fencing protocol. No command in the current source safely promotes a
replica or repoints routing. Restore produces a quarantined candidate; it does
not grant failover authority. Keep the original primary excluded until a
separately implemented and reviewed writer-authority protocol is provisioned.

Exact failover regression command:

```bash
python3 -m unittest packages.arvctl.tests.test_replication -v
```

## Health and drill acceptance

A private deployment is not restore-proven until its receipt shows:

- immutable archive identity and authenticated B7 binding;
- full manifest/hash and source-log/audit/SQLite integrity pass;
- restore into a new offline candidate, never over the source;
- runtime bearer staged from the current private secret source;
- service restart and authenticated read/write acceptance;
- old bearer rejection after rotation;
- authority evidence absent from ordinary restored data;
- measured backup age, restore elapsed time, and explicit comparison with operator-set objectives;
- retained rollback source until cutover acceptance;
- no promotion or routing change performed by restore.

The repository's V2 root-only snapshot drill remains executable for operators who use that deployment shape:

```bash
sudo python3 scripts/arvyx_v2_snapshot_restore_drill.py <synthetic-snapshot-directory> --json
```

Its `/srv/arvyx-v2` guard is an implementation safety boundary, not a published claim about any live host. Service-manager commands and effective-unit review belong in the private runbook.

## Limits

- Writes after the last successful backup or replica sync may be lost.
- Local synthetic timing excludes human approval, storage transfer, key retrieval, DNS/proxy changes, and production service startup.
- The application does not provide consensus, automatic routing cutover, storage encryption, pager delivery, or host integrity monitoring.
- A host/root compromise can defeat local application evidence; preserve external logs and release provenance privately.


## Pointer reconciliation and capture storage

A rollback must prove both durable previous-pointer publication and completed
candidate teardown before restarting the previous volume. A visible old pointer
still requires its durability barrier. Uncertainty returns typed
`VolumePointerReconciliationRequired`, `restart_blocked=true` and
`restart_failed=false`, retaining both volume identities. A failed attempted restart
is reported separately. Health failure after durable candidate commit keeps candidate
pointer authority, stops admission and retains both volumes for reconciliation.

Capture offload schema 2 binds prepared/stored canonical path, device and inode.
Current schema 3 additionally distinguishes explicit local-archive acknowledgement
from sink delivery. The intended release contract requires retained whole-chain
history through genesis. Segmented directory observations alone do not establish
retention: a previously visited segment can disappear without changing its inode.
The [retained-generation protocol](capture-retained-generations.md) now requires
an independently qualified store issuer's exact signed complete-generation
commitment for acknowledgement and relocation. Human key pinning is explicit;
no ordinary directory or self-signed promise becomes a qualified immutable store.
Storage qualification and the protocol acceptance it needs remain open and
unexecuted. No store was provisioned or physical retention proven.
The private `relocate_capture_offload` RPC implements exact-head confirmed
legacy adoption or chain relocation only with target retention admission.
Optional bound-chain copying retains
the old storage. Missing predecessors, a stale head, replacement directory or
non-operator actor cannot silently rebind. Completed represented runs may release
their charge; empty, interrupted and failed-fork evidence remains retained/charged.
Composition restore preserves these bindings and quarantine rather than adopting
new storage. Disposable recorder tests do not qualify Docker, power loss or live
restore/restart behavior.

## Pass-5 coordinated recovery details

The offline composition cut holds every declared owner/state/vault lock, recovers
inode-bound promotion/import journals on the original filesystem before inventory,
and refuses unfinished forget/restore intents. Completed exact forget witnesses
may be copied into independent singly linked files without changing the original
archive or witness. Other hard links remain forbidden. Retry barriers cover
existing destination ancestors too; existence does not establish durability.
Newline-only event-log recovery repeats the log parent namespace barrier. A known
no-child fork error retains a charged `aborted-before-process` run; ambiguous
post-fork cleanup remains interrupted and cannot be relabeled idle.

Offload storage and bounded continuation are described in
the local slice record (private, not exported). Progress is not archive authority
or automatic storage adoption. Restoration remains quarantined and requires
independent authority reprovisioning before any writer activation.
