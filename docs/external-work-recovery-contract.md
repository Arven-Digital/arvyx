# External submission recovery and coverage contract

This supersedes the effect-phase error classification in `deep10fix-08.md`.

The existing additive `external_submission_attempts` table commits the authenticated grant decision, scope, content fingerprint and pending work ID before any work effect. A second grant transaction reauthorizes and serializes against revocation while the separately stored work row and its audit commit. Confirmation follows that commit. Pending means unknown, never failed. Every ordinary exception during this second phase now returns 503 `submission outcome uncertain` with `submission_id`, not a false denial or invalid-request response. This deliberately includes a permission failure between intent and effect; it does not bypass that failure or append unauthorized work. Process-ending BaseException remains unhandled; the pending attempt supports trusted reconciliation after restart.

## Caller and migration contract

- HTTP POST `/external/grants/G/tasks/T/results` accepts the existing closed `kind`, `text`, `source` payload plus optional `submission_id`. ExternalAPI is the only production caller of `ExternalWork.submit` located in the source inventory.
- Retry-capable callers MUST choose and retain a stable submission ID BEFORE sending the first request. Reuse exactly the same ID and payload after response loss or 503. Scope includes authenticated principal, grant and task. Changed content is rejected. Successful retries return the original work ID and timestamp after fresh authority checks.
- Legacy callers without an ID retain distinct append semantics. They MUST NOT automatically retry a lost response. If a 503 response supplies an ID, an explicit retry can adopt it. Complete response loss requires trusted reconciliation of pending attempt IDs against work rows and work-local audit; pending is not absence of an effect. This is a documented compatibility mode, not exactly-once delivery for unkeyed clients.
- Standalone ExternalWork callers retain append semantics without `record_id`; trusted compositions requiring idempotence supply a durable precommitted attempt ID. No preexisting rows move and no historical missing grant decisions are backfilled.
- No startup replay, recovery listener, cross-principal listing, authority relaxation or local user data relocation is introduced.

Pending is sticky without an explicit resolution, not necessarily permanent. A
same-ID retry first rechecks the current grant, then either appends the missing
work ID or verifies every existing scope/content field and returns its original
timestamp before confirmation. Revocation, expiry, exclusion, an ongoing storage
fault or changed content can keep it unresolved; a 503 does not authorize a
fresh-ID retry or bypass. No automatic trusted reconciliation command is shipped.
If the original payload/key is unavailable or authority no longer permits retry,
an operator must preserve and compare the attempt ID, grant/principal/task scope,
fingerprint, work row and work-local audit through a trusted offline investigation.
Do not delete pending intents, infer absence from a lost response, mark confirmed
from an exception alone, or directly edit the databases as routine recovery.

## Workspace consumer contract

Resource DTOs already include `coverage=selection|workspace`. `complete` means no exclusions within that scope, not complete workspace review when coverage is selection. ExternalGateway passes backend mappings unchanged for access and discovery; the listener JSON-serializes them without projection. The inspected Paperclip external HTTP adapter consumes issuer configuration and grant metadata only, not workspace-content DTOs; no corresponding field-stripping parser was found there. Future content consumers must preserve coverage and label completeness within it.

## Verification limits

Regressions extend `test_deep10fix_08.py` for postcommit PermissionError, ValueError and RuntimeError, reopening stores and retrying the same key without duplicate work. The pre-effect revocation test still asserts no work effect and durable pending evidence, but expects conservative 503 after intent rather than false certainty. Existing grant/work audit, revocation, keyed retry and scope regressions are retained. Tests, builds, imports, services, network and CI are NOT_EXECUTED by request. Static syntax inspection only is not runtime proof. Public release classification and integrated review remain parent responsibilities.
