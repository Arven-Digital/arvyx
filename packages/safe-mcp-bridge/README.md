# safe-mcp-bridge

Safety-first stdio-to-HTTP MCP bridge for scoped agent access.

The bridge reads JSON-RPC requests from stdin, forwards allowed MCP calls to an
HTTP MCP upstream, filters `tools/list`, blocks disallowed tools before they
reach the upstream, and writes redacted JSONL audit events.

Installed command:

```bash
safe-mcp-bridge doctor examples/safe-mcp-bridge/read-only.json --json
safe-mcp-bridge lint examples/safe-mcp-bridge/read-only.json --json
safe-mcp-bridge run examples/safe-mcp-bridge/read-only.json
```

Repo smoke:

```bash
make bridge-dogfood-smoke
```

The smoke starts the Arvyx Control Center API locally, routes stdio JSON-RPC
through this bridge, verifies read-only memory tools, blocks a control-plane
write, and checks that the synthetic auth value is not emitted.
