"""Connect a LangGraph / LangChain agent to the Arvyx memory MCP surface.

The Arvyx server is the same read-only stdio process every other client
example launches; only the adapter differs. Control-plane tools stay behind
the HTTP API + safe-mcp-bridge, not this read-only stdio surface.

Requires:
    pip install langchain-mcp-adapters langgraph

Replace /path/to/arvyx with your checkout path. Set
PYTHONPATH to the packages/arvctl/src entry so the stdio server can import
arvyx_control (or install the arvctl package instead).
"""

from __future__ import annotations

import asyncio

from langchain_mcp_adapters.client import MultiServerMCPClient

VAULT = "/path/to/arvyx/fixtures/synthetic-vault"
PYTHONPATH = "/path/to/arvyx/packages/arvctl/src"


async def main() -> None:
    client = MultiServerMCPClient(
        {
            "arvyx-memory": {
                "transport": "stdio",
                "command": "python3",
                "args": ["-m", "arvyx_control.cli", "mcp", "--profile", "read-only", "--vault", VAULT],
                "env": {"PYTHONPATH": PYTHONPATH},
            }
        }
    )
    tools = await client.get_tools()
    print("arvyx tools:", [tool.name for tool in tools])
    # Hand `tools` to create_react_agent(model, tools) to give the graph
    # governed recall over curated memory.


if __name__ == "__main__":
    asyncio.run(main())
