"""Expose the Arvyx memory MCP surface to a CrewAI agent.

The Arvyx server is the same read-only stdio process every other client
example launches. CrewAI's MCPServerAdapter wraps it as CrewAI tools that
an agent can call for governed recall over curated memory.

Requires:
    pip install "crewai-tools[mcp]"

Replace /path/to/arvyx with your checkout path. Set
PYTHONPATH to the packages/arvctl/src entry so the stdio server can import
arvyx_control (or install the arvctl package instead).
"""

from __future__ import annotations

import os

from crewai_tools import MCPServerAdapter
from mcp import StdioServerParameters

VAULT = "/path/to/arvyx/fixtures/synthetic-vault"
PYTHONPATH = "/path/to/arvyx/packages/arvctl/src"

server_params = StdioServerParameters(
    command="python3",
    args=["-m", "arvyx_control.cli", "mcp", "--profile", "read-only", "--vault", VAULT],
    env={**os.environ, "PYTHONPATH": PYTHONPATH},
)


def main() -> None:
    with MCPServerAdapter(server_params) as tools:
        print("arvyx tools:", [tool.name for tool in tools])
        # Pass `tools` to a crewai.Agent(tools=tools, ...) so the crew can
        # recall curated memory during a task.


if __name__ == "__main__":
    main()
