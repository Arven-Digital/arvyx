#!/usr/bin/env python3
"""Fail closed when locked dependency license metadata or project notices drift."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements" / "dev.lock"
INVENTORY = ROOT / "requirements" / "THIRD_PARTY_LICENSES.json"


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def locked_names() -> set[str]:
    return {
        normalized(name)
        for name in re.findall(r"(?m)^([A-Za-z0-9_.-]+)==", LOCK.read_text(encoding="utf-8"))
    }


def license_value(distribution: importlib.metadata.Distribution) -> str:
    declared = (
        distribution.metadata["License-Expression"]
        or distribution.metadata["License"]
        or ""
    ).strip()
    if declared and declared.upper() != "UNKNOWN":
        return declared
    classifiers = [
        value.removeprefix("License :: ")
        for value in distribution.metadata.get_all("Classifier", [])
        if value.startswith("License :: ")
    ]
    return "; ".join(classifiers)


def inventory() -> list[dict[str, str]]:
    installed = {normalized(d.metadata["Name"]): d for d in importlib.metadata.distributions() if d.metadata["Name"]}
    missing = sorted(locked_names() - installed.keys())
    if missing:
        raise SystemExit(f"locked distributions are not installed: {', '.join(missing)}")
    rows = []
    for name in sorted(locked_names()):
        distribution = installed[name]
        license_name = license_value(distribution)
        if not license_name:
            raise SystemExit(f"dependency has no declared license metadata: {name}=={distribution.version}")
        rows.append({"license": license_name, "name": distribution.metadata["Name"], "version": distribution.version})
    return rows


def verify_project_notice() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    if project.get("license") != "Apache-2.0":
        raise SystemExit("project license must remain Apache-2.0")
    if set(project.get("license-files", [])) != {"LICENSE", "NOTICE", "licenses/*.txt"}:
        raise SystemExit("pyproject must package LICENSE, NOTICE and pinned upstream licenses")
    for filename in ("LICENSE", "NOTICE", "licenses/Herdr-Apache-2.0.txt", "licenses/Paperclip-MIT.txt"):
        path = ROOT / filename
        if not path.is_file() or not path.read_text(encoding="utf-8").strip():
            raise SystemExit(f"missing or empty {filename}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="refresh the reviewed inventory")
    stacks = parser.add_mutually_exclusive_group()
    stacks.add_argument('--secret-edge', action='store_true', help='verify the separately installed optional edge runtime')
    stacks.add_argument('--mcp-client', action='store_true', help='verify the separately installed optional MCP evidence client')
    args = parser.parse_args()
    global LOCK, INVENTORY
    if args.secret_edge:
        LOCK = ROOT / 'requirements' / 'secret-edge.lock'
        INVENTORY = ROOT / 'requirements' / 'SECRET_EDGE_LICENSES.json'
    elif args.mcp_client:
        LOCK = ROOT / 'requirements' / 'mcp-client.lock'
        INVENTORY = ROOT / 'requirements' / 'MCP_CLIENT_LICENSES.json'
    verify_project_notice()
    actual = inventory()
    payload = json.dumps(actual, indent=2, sort_keys=True) + "\n"
    if args.write:
        INVENTORY.write_text(payload, encoding="utf-8")
    elif not INVENTORY.is_file() or INVENTORY.read_text(encoding="utf-8") != payload:
        raise SystemExit("third-party license inventory drift; review and run scripts/license_notice_check.py --write")
    print(f"verified LICENSE, NOTICE, and {len(actual)} locked dependency licenses")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
