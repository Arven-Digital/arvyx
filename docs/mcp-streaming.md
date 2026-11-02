# MCP Streaming Compatibility

Arvyx memory/control uses JSON-RPC request/response transports.
It does not advertise SSE or long-lived streaming MCP transports yet.

## Supported Now

- Direct stdio:
  `python3 -m arvyx_control.cli mcp --profile read-only`
- HTTP JSON-RPC:
  `POST /mcp`
- Scoped stdio-to-HTTP bridge:
  `safe-mcp-bridge run <config>`

These paths are covered by local and CI smoke tests:

```bash
make mcp-smoke
make mcp-client-smoke
make bridge-dogfood-smoke
```

## Not Supported Yet

- SSE MCP transport.
- Long-lived response streaming.
- Partial tool-call result streaming.

Clients that require SSE should use a separate adapter or wait for the
streaming transport slice. Read-only local clients should use the stdio
examples in `examples/mcp-clients/`.

## Compatibility Fixture

The current posture is captured in:

```text
examples/mcp-clients/streaming-compatibility.json
```

Validate it with:

```bash
make mcp-streaming-smoke
```

## Request envelope validation

Both core/stdio and HTTP MCP require `jsonrpc: "2.0"`, a string method and,
when present, object params. IDs may be null, strings or finite JSON numbers;
booleans, arrays and objects are invalid. HTTP validates the original envelope
before mutation classification, idempotency admission or dispatch. Invalid
requests receive HTTP 400 with a top-level JSON-RPC `-32600` response (without the generic API status/body wrapper) and only a valid
correlation ID (otherwise null). Invalid envelopes are never notifications.
Valid notifications still omit replies while retaining governed mutation audit.
