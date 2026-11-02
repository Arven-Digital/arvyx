# MCP Client Examples

These fixtures show how local stdio MCP clients can talk to the Arvyx memory
surface during alpha validation.

## Files

- `codex.toml`: Codex MCP client shape.
- `claude-desktop.json`: Claude Desktop MCP client shape.
- `cursor.json`: Cursor MCP client shape (`.cursor/mcp.json`).
- `openhands.toml`: OpenHands MCP config shape (`mcp.stdio_servers`).
- `langgraph_client.py`: LangGraph / LangChain adapter example
  (`langchain-mcp-adapters`).
- `crewai_client.py`: CrewAI adapter example (`crewai-tools[mcp]`).
- `real-client-evidence.example.json`: public-safe release-host evidence shape
  for a real stdio client run.

Every example launches the same read-only stdio server; only the adapter
differs. Working agents that need control-plane tools use the HTTP API with the
`agent` server profile plus the matching `safe-mcp-bridge` policy and a
least-privilege per-agent token.

Both examples use placeholder paths. Replace `/path/to/arvyx`
with the absolute path to your checkout.

## Expected Command

Both clients run the same local server:

```bash
python3 -m arvyx_control.cli mcp --profile read-only --vault /path/to/arvyx/fixtures/synthetic-vault
```

On Windows the interpreter is usually `python` or `py` rather than `python3`;
set the config `command` accordingly. The server itself runs on Windows,
macOS, and Linux without changes.

Set `PYTHONPATH` to include:

```text
/path/to/arvyx/packages/arvctl/src
```

## Troubleshooting

- If the client cannot find `arvyx_control`, check `PYTHONPATH`.
- If recall returns no sources, confirm the `--vault` path exists.
- If control tools are missing, that is expected for read-only client examples.
- If a working client needs control-plane tools, use the HTTP API with the
  explicit `agent` MCP profile and matching `safe-mcp-bridge` policy instead of
  widening these read-only stdio examples. Reserve `operator` for trusted local
  operator runtimes.

### Trusted operator profile

Direct stdio defaults to `read-only`. The `operator` profile exposes mutation,
approval, curation, and secret-resolution tools. Launch it only for a trusted
local operator client, and opt in explicitly:

```bash
arvyx mcp --profile operator --vault /path/to/arvyx/fixtures/synthetic-vault
```

## CI Fixture Check

The examples are validated by:

```bash
make mcp-client-smoke
make mcp-client-evidence-smoke
```

The check verifies the client command, args, vault placeholder, `PYTHONPATH`,
and absence of private machine paths.

The evidence check verifies that real release-host evidence records:

- stdio transport
- the client name and command
- successful `tools/list`
- successful recall with sources
- no leaked private paths

Before public review, copy the example shape to a private `tmp/` evidence file,
fill it with the actual client run result, then pass it to:

```bash
arvyx release-host --mcp-client-evidence tmp/mcp-client-evidence.json --json
```

You can generate that evidence with the local stdio MCP surface:

```bash
arvyx evidence mcp-client --output tmp/mcp-client-evidence.json --json
```

Then validate it explicitly:

```bash
scripts/mcp_client_evidence_check.py tmp/mcp-client-evidence.json --json
```
