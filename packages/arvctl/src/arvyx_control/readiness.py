from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ReadinessItem:
    id: str
    label: str
    status: str
    evidence: list[str]
    next_step: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "status": self.status,
            "evidence": self.evidence,
            "next_step": self.next_step,
        }


@dataclass(frozen=True)
class ReadinessResult:
    score: int
    structural_complete: bool
    items: list[ReadinessItem]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "structural_complete": self.structural_complete,
            "items": [item.to_dict() for item in self.items],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def readiness(repo: Path) -> ReadinessResult:
    checks = [
        _check(
            repo,
            "recall",
            "Token-bounded cited recall",
            [
                "packages/arvctl/src/arvyx_control/recall.py",
                "packages/arvctl/tests/test_recall.py",
                "fixtures/recall-benchmark.json",
                "docs/recall-benchmark.md",
            ],
            "Add a real embedding backend option if local hashed hybrid retrieval is not enough.",
        ),
        _check(
            repo,
            "mcp",
            "MCP memory and control surface",
            [
                "packages/arvctl/src/arvyx_control/mcp.py",
                "examples/mcp-clients/codex.toml",
                "examples/mcp-clients/claude-desktop.json",
                "examples/mcp-clients/cursor.json",
                "examples/mcp-clients/openhands.toml",
                "examples/mcp-clients/langgraph_client.py",
                "examples/mcp-clients/crewai_client.py",
                "examples/mcp-clients/README.md",
                "examples/mcp-clients/real-client-evidence.example.json",
                "examples/mcp-clients/streaming-compatibility.json",
                "docs/mcp-streaming.md",
                "scripts/mcp_client_examples_check.py",
                "scripts/mcp_client_evidence_check.py",
                "scripts/mcp_streaming_compat_check.py",
            ],
            "Implement SSE or streaming MCP transport if a target client requires it.",
        ),
        _check(
            repo,
            "control",
            "Tasks, approvals, and append-only control log",
            [
                "packages/arvctl/src/arvyx_control/control.py",
                "packages/arvctl/src/arvyx_control/store.py",
                "packages/arvctl/src/arvyx_control/digest.py",
            ],
            "Add private preference sync if local-only operator settings become insufficient.",
        ),
        _check(
            repo,
            "dashboard",
            "Control Center API and packaged dashboard",
            ["packages/arvctl/src/arvyx_control/api.py", "packages/arvctl/src/arvyx_control/static/index.html"],
            "Dashboard now carries memory-queue, audit-browser, and posture panels; add live streaming/refresh if operators need it.",
        ),
        _check(
            repo,
            "security",
            "Security posture and private-context gate",
            ["SECURITY.md", "docs/threat-model.md", "scripts/private_context_scan.py"],
            "Run multi-model security review before public release.",
        ),
        _check(
            repo,
            "setup",
            "Five-minute local setup path",
            [
                "Dockerfile",
                "docker-compose.yml",
                "docs/quickstart.md",
                "scripts/docker_compose_check.py",
                "scripts/docker_runtime_smoke.py",
            ],
            "Run docker-runtime-smoke on the release host before public release.",
        ),
        _check(
            repo,
            "bridge",
            "safe-mcp-bridge policy integration",
            [
                "packages/arvctl/src/arvyx_control/bridge.py",
                "docs/safe-mcp-bridge.md",
                "fixtures/safe-mcp-bridge/read-only-e2e.json",
                "packages/safe-mcp-bridge/src/safe_mcp_bridge/cli.py",
                "scripts/bridge_e2e_fixture_check.py",
                "scripts/bridge_dogfood_smoke.py",
            ],
            "Add streaming transport support and richer bridge policy diagnostics.",
        ),
        _check(
            repo,
            "importers",
            "Governed markdown import",
            ["packages/arvctl/src/arvyx_control/importers.py", "docs/importers.md", "packages/arvctl/tests/test_recall.py"],
            "Add importer manifests and richer frontmatter conflict reports.",
        ),
        _check(
            repo,
            "internal_audit",
            "Internal release-audit evidence",
            ["packages/arvctl/src/arvyx_control/audit.py", "docs/security-audit.md", "docs/release-gate.md"],
            "Run arvyx audit for each release candidate and preserve reviewer evidence.",
        ),
        _audit_check(
            repo,
            "audits",
            "Multi-model audit readiness",
            ["docs/security-audit.md", "docs/release-gate.md"],
            "Complete multi-model security review and synthesis, then mark audit status complete.",
        ),
    ]
    complete = sum(1 for item in checks if item.status == "complete")
    partial = sum(1 for item in checks if item.status == "partial")
    score = round(((complete + partial * 0.5) / len(checks)) * 100)
    return ReadinessResult(score=score, structural_complete=score == 100, items=checks)


def _check(repo: Path, item_id: str, label: str, required: list[str], next_step: str) -> ReadinessItem:
    evidence = [path for path in required if (repo / path).exists()]
    if len(evidence) == len(required):
        status = "complete"
    elif evidence:
        status = "partial"
    else:
        status = "missing"
    return ReadinessItem(id=item_id, label=label, status=status, evidence=evidence, next_step=next_step)


def _audit_check(repo: Path, item_id: str, label: str, required: list[str], next_step: str) -> ReadinessItem:
    base = _check(repo, item_id, label, required, next_step)
    if base.status != "complete":
        return base
    if _status_value(repo / "docs/security-audit.md", "audit-status") == "complete" and _status_value(
        repo / "docs/release-gate.md",
        "release-gate-status",
    ) == "complete":
        return base
    return ReadinessItem(
        id=base.id,
        label=base.label,
        status="partial",
        evidence=base.evidence,
        next_step=next_step,
    )


def _status_value(path: Path, key: str) -> str | None:
    if not path.exists():
        return None
    prefix = f"{key}:"
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return line.removeprefix(prefix).strip()
    return None
