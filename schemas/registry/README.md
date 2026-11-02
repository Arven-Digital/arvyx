# Registry Schemas

Minimal registry contract for the private prototype.

## agents

Required fields:

- `id`
- `display_name`
- `machine_id`
- `runtime_id`
- `scopes`

Optional dashboard presentation hints (operator data, never tracked code):

```json
"dashboard": {"desk": "security", "hidden": false}
```

- `desk`: one of `engineering`, `security`, `research`, `operations`. Seats
  the agent at that War Room desk (sprite, colour and desk label). If two
  agents claim the same desk, the lower agent id wins. Desks nobody claims go
  to the remaining visible agents in stable agent-id order and are labelled
  auto-assigned.
- `hidden`: `true` removes the agent, and every dashboard item that names it,
  from the dashboard. Only the JSON boolean `true` hides. Hiding hides
  presence, never governance: a `requested` approval and a pending thread
  targeted at `operator` stay visible whoever raised or touched them.

Any other value is ignored. `/control-plane` projects these hints as
`agent.dashboard = {"desk": <key or null>, "hidden": <bool>}`.

## machines

Required fields:

- `id`
- `display_name`
- `role`

## runtimes

Required fields:

- `id`
- `display_name`
- `harness`

## projects

Required fields:

- `id`
- `display_name`
- `owner_agent_id`

`arvyx doctor` validates these fields in `registry/*/*.json`.
