# Watchdog HOLD notification and remediation contract

The producer and all three lifecycle consumers (`operator_alert_dismissal`,
`retirement`, and opt-in `operator_archive`) share `watchdog_alerts.py`.
The canonical body is exactly `target={target} subject={subject_type} {subject_id}; {hold_reason}.`.
The only supported historical alternative omits that one producer-added final
period. Punctuation already in the recorded HOLD reason is preserved. Extra
suffixes, changed reasons, arbitrary punctuation and agent investigation guidance
are not accepted as operator alert bodies. Existing provenance, exact source,
HOLD, terminal evidence, closure, identity and revision checks remain required.
Notification dismissal is not successful work completion or lineage resolution.

For dead-letter remediation, watchdog snapshots the projected execution and the
latest event ID from `EXECUTION_STATE_EVENT_TYPES` in the same state-lock section.
It delegates writes to `execution.remediate_dead_letter(state, execution_id, *,
expected_event_id, actor, max_replays, hold_reason, now=None)`, which owns the
atomic revision/status/terminal/replay-budget check and canonical transition.
The exact revision fences the attempt as well: a fresh claim changes that event
ID. A `changed` result skips only this execution and the remaining tick continues;
watchdog does not broad-catch domain failures to hide invalid state or authority.

Offline targets with a snapshot replay count below the budget are deferred
without writing. Counts are append-only and monotonic; exhausted snapshots still
go through the atomic helper, allowing an offline exhausted lineage to HOLD but
never replaying an unreachable target. The helper must reassess current replay
count under its own state lock rather than trust this observation.

## Verification status

Regression sources cover the actual watchdog-generated page through preparation,
dry-run, application, readback and retry, the undotted compatibility format,
rejected suffixes, and deterministic operator replay/new-claim/closure/completion
interleavings immediately before the conditional helper. They are proposals in
source, not executed evidence. Runtime checks: **NOT_EXECUTED**, by instruction.
Parent integration owns final helper-signature agreement, path classification,
and the fresh complete-scope independent review. A release still requires the exact-tree candidate verdict (docs/release-gate.md).
