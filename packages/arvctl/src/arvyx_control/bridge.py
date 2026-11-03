from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from .mcp import MCP_PROFILES, TOOL_NAMES

PROFILES = {
    "read-only": {
        "name": "arvyx-memory-read-only",
        "description": "Expose memory recall and exact-source expansion only.",
        "tools": MCP_PROFILES["read-only"],
    },
    "agent": {
        "name": "arvyx-memory-agent",
        "description": "Expose governed memory and non-authority agent coordination tools.",
        "tools": MCP_PROFILES["agent"],
    },
    "operator": {
        "name": "arvyx-memory-operator",
        "description": "Expose memory plus local control-plane task and approval tools.",
        "tools": MCP_PROFILES["operator"],
    },
}


@dataclass(frozen=True)
class BridgePolicyResult:
    profile: str
    policy: dict[str, Any]
    written_to: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"profile": self.profile, "policy": self.policy, "written_to": self.written_to}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def build_bridge_policy(
    profile: str,
    upstream: str = "http://127.0.0.1:8765/mcp",
    auth_env: str = "ARVYX_MCP_TOKEN",
) -> BridgePolicyResult:
    if profile not in PROFILES:
        raise ValueError(f"unknown bridge policy profile: {profile}")
    spec = PROFILES[profile]
    policy = {
        "name": spec["name"],
        "description": spec["description"],
        "target": {"url": upstream, "timeout_seconds": 20},
        "auth": {"header": "Authorization", "env": auth_env, "prefix": "Bearer"},
        "policy": {"mode": "allowlist", "allow_tools": list(spec["tools"])},
        "audit": {"path": "tmp/safe-mcp-bridge-audit.jsonl", "redact": True},
        "redaction": {"fail_on_secret_output": True},
    }
    unknown = sorted(set(policy["policy"]["allow_tools"]) - set(TOOL_NAMES))
    if unknown:
        raise ValueError(f"bridge policy references unknown MCP tools: {', '.join(unknown)}")
    return BridgePolicyResult(profile=profile, policy=policy)


def write_bridge_policy(
    profile: str,
    output: Path,
    upstream: str = "http://127.0.0.1:8765/mcp",
    auth_env: str = "ARVYX_MCP_TOKEN",
) -> BridgePolicyResult:
    result = build_bridge_policy(profile=profile, upstream=upstream, auth_env=auth_env)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result.policy, indent=2, sort_keys=False) + "\n", encoding="utf-8", newline="\n")
    return BridgePolicyResult(profile=result.profile, policy=result.policy, written_to=str(output))
