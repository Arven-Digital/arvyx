# Local onboarding CLI implementation receipt

## Runnable entrypoints

After installing this checkout, run `amc` (or `amc onboard`). Existing `arvyx`,
`arvyx-cockpit` and `safe-mcp-bridge` entrypoints are unchanged.
Without installation:

```sh
PYTHONPATH=packages/arvctl/src python -m arvyx_control.onboarding_cli --state-dir /absolute/private/amc-state --home /absolute/discovery-home
```

`amc status` reads persisted connections, the explicit organizer assignment and
created agent records. State defaults to `~/.local/share/amc`; the directory must
be private and current-user-owned. This is a local-owner tool, not a network API.

## Implemented flow

Bounded metadata discovery shows every found candidate and asks Connect/Skip
individually. Connect requests a unique display name and persists exact candidate
metadata as `consented_unverified`; it does not read marker contents or restart a
runtime. Optional organizer assignment now requires the exact immutable
`connection_id` shown beside the display name. Persisted v2 organizer references
never contain a display-name principal. See `final-audit-identity.md` for explicit
legacy reconciliation and current source-only verification limits.
Private local provisioning is rehydrated into process-local OrganizerAuthority
handles for creation decisions. Skipping creates no agent organizer authority.
Clean named Hermes creation calls AgentCreation with a separate private profiles
root, distinct immutable identity/session/memory namespaces and no copied files,
credentials or provider calls. The local owner can provision without an organizer.
No runtime is launched; created records explicitly remain `metadata_only`.
Attach selects an exact named connection, but honestly reports native attachment
unavailable rather than fabricating a running session. Session integration belongs
to the separate session module owner. EOF/errors retain previously confirmed choices.

## Explicit isolated first-session entry

`amc first-session` is separate from the metadata-only menu described above. It
initializes native Hermes state using the installed writer API, enrolls a clean
scoped owner, performs owner-managed native New, and attaches an admitted Arvyx
frontend with exact native/pane binding. Credential-free readiness is labeled
`setup_required`, never authenticated chat. It needs an absent protected root,
explicit host execution policy, reviewed executable identity, and controlling-
terminal confirmation. No existing owner/profile is adopted and no credentials
or history are copied. See [native-first-session.md](native-first-session.md) for
the command, boundary, retained-state behavior, and actual PTY/native receipts.
The P2 follow-up revalidates original consent, ancestry, and execution policy at
native-init dispatch after publication/fsync. Scoped cleanup verifies retained
child handles; unresolved cleanup is nonzero with `owner_status=cleanup_failed`
and explicit receipt details, never successful closure or PID-file signaling.

## Deliberate unavailable paths

`amc -confirm CODE` exits 2 before opening any state. Machine pairing primitives
alone cannot prove remote private-key possession, perform a network handshake or
obtain separate main-instance confirmation. The CLI does not convert metadata-only
PairingStore approval into a successful remote connection. Manual custom-location
and remote adapter setup, general cold-profile setup/launch from this metadata menu, identity-copy approval UI,
provider-auth reuse, execution privilege choice and web parity remain unimplemented.
Organizer persistence is local provisioning only, not remote/root execution authority.

## Catalog reconciliation

See `../receipts/onboarding-catalog-reconciliation.json`: both inventories contain
25 entries but are not the same inventory. The implementation splits VSCode-Copilot
and substitutes other families; it does not implement all product research targets.
The product contract and sibling discovery implementation were not overwritten.

## Historical executed checks (not re-executed for identity migration)

- RED: four subprocess tests failed because onboarding_cli did not exist.
- GREEN: `PYTHONPATH=packages/arvctl/src python -m pytest packages/arvctl/tests/test_onboarding_cli.py packages/arvctl/tests/test_agent_creation.py packages/arvctl/tests/test_harness_discovery.py packages/arvctl/tests/test_machine_pairing.py packages/arvctl/tests/test_organizer_authority.py -q`: **74 passed**.
- Tests execute real subprocess menus with isolated HOME/state roots; read state back
  in a second process; verify marker preservation, skip, clean creation and remote
  confirmation refusal without state creation. No real profiles/providers used.
- Editable package install succeeded in a dedicated scratch virtualenv using
  `pip install --no-deps --no-build-isolation -e .`; its actual `bin/amc --help`
  displayed the registered onboarding/status/-confirm command.
- Pinned pstack offline validator passed (129 snapshot files).
- An initial combined pytest invocation lacked PYTHONPATH and failed collection;
  rerunning with the source root above passed. No review, push, deploy, production
  change, owner restart or provider spend was performed. A release still requires the exact-tree candidate verdict (docs/release-gate.md).
