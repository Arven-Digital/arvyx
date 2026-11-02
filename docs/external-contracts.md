# External contracts

The committed [machine-readable contract](contracts/external-contracts.json) is generated from the executable HTTP router, CLI parser declarations, MCP tool schemas, profile allowlists, and scope mappings. It is OpenAPI-like rather than full OpenAPI because the current router is a direct Python dispatcher and some response bodies are dataclasses or JSON-RPC envelopes rather than declared HTTP schemas.

## Generate and check

```bash
python scripts/generate_external_contracts.py
python scripts/generate_external_contracts.py --check
make contract-check
```

The first command updates the committed artifact. The latter two are read-only drift checks; `make ci` runs `contract-check`, so route, command, tool, profile, scope, schema-limit, or argument changes fail CI until the reference is regenerated and reviewed.

The JSON contains:

- HTTP methods and paths, including templated identifier routes, required bearer scope, the operator-only authority gate where the router enforces one, observed success statuses, common error envelopes, the 1 MiB body limit, and server worker limit;
- every `arvyx` and `safe-mcp-bridge` parser command with its declared arguments, defaults, choices, and requirements, plus the dispatcher worker's root grammar;
- every MCP profile and tool, its exact input schema, effective auth scopes, profile membership, idempotency requirement, schema limits, and JSON-RPC error shape.

The generated surfaces include `memory.suggest_batch` and its closed quality/relations schema, `memory.forget`/`memory.restore`, HTTP batch/schema/forget routes, and the checkpointed `arvyx index rebuild` and `arvyx index status` commands.

## Trust boundaries

- The generated file is a reference, not authorization. HTTP bearer scopes and MCP profile membership are both enforced at runtime; the effective MCP surface over HTTP is **profile intersect token scopes**.
- `read-only` permits recall and selected coordination reads. `agent` adds identity-bound working-agent writes. `operator` carries curation, approval, and secret authority; do not expose it to an untrusted MCP client.
- `memory.suggest_batch` validates the complete batch atomically. Quality metadata and relations are untrusted input until validation succeeds. Relation targets are constrained by the executable schema and write implementation.
- Forget is soft and auditable. It moves curated material to an excluded archive and writes a tombstone; restore does not erase that history. Use unique idempotency keys for mutations.
- Checkpoint status describes durable local indexing progress, not freshness of every upstream source or permission to promote data.
- HTTP common error entries describe stable envelope categories. Endpoint-specific validation messages remain implementation details and can be added to the executable router/schema before being promised externally.
- Examples and paths in public docs must remain synthetic. Never paste bearer tokens, secret values, private hostnames, customer records, or production memory into requests or fixtures.

## CLI root authority

`root_arguments` apply to every command path and must precede the first
subcommand; they are not options to append after a task action. The extracted
`invocation_constraints` preserve additional parser-error prerequisites beyond
individual argparse `required` flags. In particular, state-only commands need
an explicit vault: use `arvyx --authority-vault VAULT task create TITLE --owner
operator --state STATE --json`. Commands declaring a local `--vault` may use
that explicit option instead; if both vault options are supplied they must
identify the same vault. No vault is inferred from a state path. The dispatcher
has no subcommands: its root command requires `--vault`, `--state`, `--routes`
and `--deliver-after`. These declarations do not grant mutation authority.

## Schema versus transport limits

`memory.suggest_batch` permits at most 100 items, each with at most 100,000
content characters. These are independent schema constraints, **not a promise
that their Cartesian product fits one request**. HTTP additionally caps the
complete encoded request body at 1,048,576 bytes (1 MiB). This applies to both
`POST /memory/suggest-batch` and MCP `tools/call` through `POST /mcp`, including
the JSON-RPC envelope, project/author/idempotency metadata, all items, JSON
escaping and UTF-8 encoding. Character counts are not encoded-byte counts.
The HTTP handler rejects an oversized body with 413 before JSON/schema
validation. Dedicated intake routes can impose smaller caps.

Size the exact serialized HTTP body before sending, and keep each batch within
both bounds. Splitting a batch creates separate operations, not cross-request
atomicity; use a distinct idempotency key per mutation. MCP over stdio is a
separate transport: the HTTP body cap is not a new per-item schema restriction
or a statement of stdio's own framing limits. Schema-valid input still must
pass runtime quality, relation, identity and authority checks.

## Source anchors

- HTTP: `packages/arvctl/src/arvyx_control/api.py::_handle_api_request` and `_required_scope`
- CLI: `packages/arvctl/src/arvyx_control/cli.py`, `packages/arvctl/src/arvyx_control/dispatcher.py` and `packages/safe-mcp-bridge/src/safe_mcp_bridge/cli.py`
- MCP: `packages/arvctl/src/arvyx_control/mcp.py::_tools`, `MCP_PROFILES`, and `packages/arvctl/src/arvyx_control/auth.py::SCOPE_TOOLS`
- Batch quality/relations: `packages/arvctl/src/arvyx_control/writes.py::memory_suggestion_batch_schema`
