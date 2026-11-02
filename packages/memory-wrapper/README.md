# memory-wrapper

Prototype extraction area for the MCP memory service.

The first executable slice lives in `packages/arvctl/src/arvyx_control/mcp.py`
so the repo can dogfood one Python package while the extraction boundaries are
still being shaped.

Current JSON-RPC methods:

- `initialize`
- `tools/list`
- `tools/call`

Current tools:

- `memory.recall`: compact cited answer from curated memory.
- `memory.excerpt`: exact cited lines from an allowed source.
- `memory.context_pack`: compact answer plus exact excerpts for handoffs.
- `control.task_create`: create a task event.
- `control.task_list`: list projected task state.
- `control.task_done`: complete a task.
- `control.approval_request`: request command-hash approval.
- `control.approval_approve`: approve a request.
- `control.approval_consume`: consume an approved command hash.
- `control.approval_list`: list projected approval state.

Design rules:

- Only curated vault paths are readable.
- `raw/`, `archive/`, `pending/`, and `.git/` paths are refused.
- Results include structured content so agent clients can avoid reparsing
  prose.
- Recall returns memory cards before excerpts to keep default token costs low.
- Control tools write only to the configured local event log path.
