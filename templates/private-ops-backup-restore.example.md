# Private backup/restore operator runbook template

> Copy this file to the approved private operations store before filling it in. Do not commit the completed copy. All values below are synthetic placeholders.

## Ownership and objectives

- Service owner: `<private-owner>`
- Incident approver: `<private-approver>`
- Authority ID: `<private-authority-id>`
- Primary / standby inventory references: `<private-inventory-records>`
- RPO objective: `<duration and rationale>`
- RTO objective: `<duration and rationale>`
- Backup, sync, and drill cadence: `<private-schedules>`
- Retention / legal hold: `<policy reference>`

## Host-private inputs

Record references, never values:

- runtime bearer source: `<secret-provider reference>`
- B7 binding-key version/source per legitimate authority host: `<secret-provider references>`
- encrypted off-host mount and failure domain: `<storage inventory reference>`
- release SHA and rollback artifact: `<release receipt reference>`
- service manager unit and approved drop-ins: `<unit inventory reference>`
- DNS/proxy cutover owner and rollback: `<routing runbook reference>`
- alert/pager destination: `<monitoring reference>`

Confirm the runtime bearer and binding key are real regular files with private permissions where the implementation requires it. They must not be in backup payloads, command-line literals, logs, or this runbook.

## Preflight

1. Confirm scope, approver, current release SHA, active data pointer, and authority ID.
2. Confirm the replica is marked, last sync is known, and old primary fencing is possible.
3. Verify current service-manager effective command composition and approved drop-ins using the deployed release's doctor; stop on drift.
4. Verify backup storage is mounted, encrypted, writable, capacity-sufficient, and in a separate failure domain.
5. Create backup; record archive identity, checksum/B7 manifest identity, start/completion time, and source last-write time without recording secret values.
6. Restore offline into a new candidate. Never restore over the active source.

## Restore acceptance record

| Field | Receipt |
|---|---|
| Drill ID / date / operator | `<private>` |
| Release SHA | `<immutable SHA>` |
| Archive + B7 manifest identity | `<non-secret identifiers>` |
| Authority match and binding verification | `<pass/fail>` |
| Source loss/corruption simulated | `<scenario>` |
| Manifest, append-only log, audit-chain, SQLite integrity | `<pass/fail references>` |
| Runtime bearer staged from current source | `<pass/fail; no value>` |
| Retired bearer rejected / current bearer accepted | `<pass/fail>` |
| Service-manager restart and health/auth/MCP acceptance | `<pass/fail references>` |
| Backup age at failure (RPO observation) | `<measured duration>` |
| Failure declaration to acceptance (RTO observation) | `<measured duration>` |
| Objectives met | `<yes/no + comparison>` |
| Rollback source retained and tested | `<reference>` |
| Promotion/routing change | `none during restore` |

## Failover

Writable promotion is unavailable. Manual, automatic and forced promotion all
refuse because the current source has no independent writer-authority transfer
and recovery protocol. Do not use peer reachability or archive authentication
as promotion authority. Preserve replica data and lineage, keep the old primary
excluded, and retain this refusal until that protocol is implemented and reviewed.
A restore drill produces an inert candidate and performs no routing change.

## Key/token rotation

For each rotation record material class, non-secret version, owner, issuance time, deployment targets, old-token rejection evidence, new-token acceptance evidence, and retirement time. For a B7 key rotation, first create and restore-drill a backup bound with the new key on every legitimate recovery host; retain the old key only for the approved legacy-archive window.

## Compose restore authority and recovery

For the maintained Compose utility, follow `docs/vps-deployment.md` from the
trusted deployment checkout, exporting its `.env` before both backup and restore.
Use its `COMPOSE_PROJECT_NAME` and deployment-scoped `ARVYX_DATA_VOLUME`, never a
copied `--project arvyx`. The CLI reads its project default from the exported
environment; loading a Compose env file alone does not export Python settings.

Staging is networkless (`network_mode: none`), without published ports; acceptance
runs through container exec against container loopback. Before pointer commit,
the utility attempts verified previous-pointer recovery and, when production
teardown began, previous-volume restart. Candidate deletion is conditional on
proven teardown, pointer/restart recovery and exact ownership labels, not guaranteed.

After pointer commit or possible production admission, candidate authority is
retained: automatic rollback and candidate deletion are forbidden. Retain the
candidate container and both volumes. Do not restart the previous volume, repoint
`.env`, or delete/reseed the candidate before reconciling acknowledged writes and
proving the admission fence. `VolumePointerReconciliationRequired` reports
`candidate_volume`, `cleanup_failures`, and `restart_failed`; a false restart flag
is not fence proof. If stopping cannot be verified, isolate the service immediately.
Record the durable pointer, actual mount, fence evidence, retained identities and
reconciliation decision without secrets. After success reload `.env` before other
Compose commands. A retained rollback volume is not permission to resume old data.

## Stop and rollback conditions

Stop before cutover on any binding/checksum/integrity failure, unknown authority or freshness, effective-unit drift, inability to reject a retired bearer, failed acceptance probe, ambiguous active-data pointer, or inability to retain the previous source. Keep both candidates when durable pointer state is ambiguous and escalate for reconciliation.
