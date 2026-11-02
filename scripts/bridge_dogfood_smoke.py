from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
PYTHONPATH = os.pathsep.join(
    [
        str(ROOT / "packages" / "arvctl" / "src"),
        str(ROOT / "packages" / "safe-mcp-bridge" / "src"),
    ]
)
AUTH_ENV = "ARVYX_DOGFOOD_AUTH"
AUTH_VALUE = "synthetic-dogfood-auth-value-32b"
READ_ONLY_TOOLS = ["memory.recall", "memory.excerpt", "memory.context_pack"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Dogfood safe-mcp-bridge against Arvyx HTTP MCP.")
    parser.add_argument("--bridge-bin", default=os.environ.get("SAFE_MCP_BRIDGE_BIN"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18765)
    parser.add_argument("--vault", type=Path, default=ROOT / "fixtures" / "synthetic-vault")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()

    bridge_command = _bridge_command(args.bridge_bin)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        state = tmp_path / "events.jsonl"
        audit = tmp_path / "bridge-audit.jsonl"
        delivery_routes = tmp_path / "agent-delivery-routes.json"
        config = tmp_path / "bridge.json"
        upstream = f"http://{args.host}:{args.port}/mcp"
        health_url = f"http://{args.host}:{args.port}/health"
        config.write_text(
            json.dumps(
                {
                    "target": {"url": upstream, "timeout_seconds": 10},
                    "auth": {"header": "Authorization", "env": AUTH_ENV, "prefix": "Bearer"},
                    "policy": {"mode": "allowlist", "allow_tools": READ_ONLY_TOOLS},
                    "audit": {"path": str(audit), "redact": True},
                    "redaction": {"fail_on_secret_output": True},
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        delivery_routes.write_text('{"routes":{}}\n', encoding="utf-8")

        env = os.environ.copy()
        env["PYTHONPATH"] = PYTHONPATH
        env[AUTH_ENV] = AUTH_VALUE
        server = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "arvyx_control.cli",
                "serve-api",
                "--host",
                args.host,
                "--port",
                str(args.port),
                "--vault",
                str(args.vault),
                "--state",
                str(state),
                "--delivery-routes",
                str(delivery_routes),
                "--auth-env",
                AUTH_ENV,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_for_health(health_url)
            doctor = _run([*bridge_command, "doctor", str(config), "--json"], env=env)
            bridge = _run_bridge(bridge_command, config, env)
            audit_events = _read_audit_events(audit)
            result = _validate(doctor, bridge, audit_events)
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)

        if args.json_output:
            print(json.dumps(result, sort_keys=True))
        else:
            print(f"ok={str(result['ok']).lower()}")
            print(f"visible_tools={result['visible_tools']}")
            print(f"audit_events={result['audit_events']}")
            print(f"credential_leaked={str(result['credential_leaked']).lower()}")
        return 0 if result["ok"] else 1


def _bridge_command(bridge_bin: str | None) -> list[str]:
    if bridge_bin:
        return [bridge_bin]
    discovered = shutil.which("safe-mcp-bridge")
    if discovered:
        return [discovered]
    return [sys.executable, "-m", "safe_mcp_bridge.cli"]


def _wait_for_health(url: str) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=1) as response:  # noqa: S310 - local smoke URL only
                if response.status == 200:
                    return
        except URLError:
            time.sleep(0.1)
    raise RuntimeError(f"API server did not become healthy: {url}")


def _run(command: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(command)}\nstdout={completed.stdout}\nstderr={completed.stderr}"
        )
    return completed


def _run_bridge(bridge_command: list[str], config: Path, env: dict[str, str]) -> list[dict[str, Any]]:
    requests = [
        {"jsonrpc": "2.0", "id": "list", "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": "recall",
            "method": "tools/call",
            "params": {
                "name": "memory.recall",
                "arguments": {
                    "question": "which guardrail proxy protects credentials",
                    "project": "demo-agent",
                    "max_tokens": 120,
                },
            },
        },
        {
            "jsonrpc": "2.0",
            "id": "blocked",
            "method": "tools/call",
            "params": {
                "name": "control.bus_post",
                "arguments": {"message": "should be blocked", "channel": "ops", "actor": "demobot"},
            },
        },
    ]
    completed = subprocess.run(
        [*bridge_command, "run", str(config)],
        input="\n".join(json.dumps(item, sort_keys=True) for item in requests) + "\n",
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"bridge failed\nstdout={completed.stdout}\nstderr={completed.stderr}")
    responses = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    responses.append({"_stdout": completed.stdout, "_stderr": completed.stderr})
    return responses


def _read_audit_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _validate(
    doctor: subprocess.CompletedProcess[str],
    bridge: list[dict[str, Any]],
    audit_events: list[dict[str, Any]],
) -> dict[str, Any]:
    by_id = {item.get("id"): item for item in bridge if "id" in item}
    visible_tools = [
        item["name"]
        for item in by_id["list"]["result"]["tools"]
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]
    recall_ok = "result" in by_id["recall"]
    blocked = by_id["blocked"].get("error", {}).get("code") == -32001
    audit_event_names = [event.get("event") for event in audit_events]
    collected_text = "\n".join(
        [
            doctor.stdout,
            doctor.stderr,
            *(json.dumps(item, sort_keys=True) for item in bridge),
            *(json.dumps(item, sort_keys=True) for item in audit_events),
        ]
    )
    credential_leaked = AUTH_VALUE in collected_text
    return {
        "ok": visible_tools == READ_ONLY_TOOLS
        and recall_ok
        and blocked
        and "tools_list_filtered" in audit_event_names
        and "request_forwarded" in audit_event_names
        and "tool_blocked" in audit_event_names
        and not credential_leaked,
        "visible_tools": visible_tools,
        "recall_ok": recall_ok,
        "blocked_control_write": blocked,
        "audit_events": audit_event_names,
        "credential_leaked": credential_leaked,
    }


if __name__ == "__main__":
    raise SystemExit(main())
