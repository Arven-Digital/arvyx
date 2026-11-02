#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import time


def systemctl_show(unit: str, property_name: str) -> str:
    last_error: Exception | None = None
    for attempt in range(2):
        try:
            completed = subprocess.run(
                ["systemctl", "show", unit, f"--property={property_name}", "--value"],
                text=True, capture_output=True, check=True, timeout=3,
            )
            return completed.stdout.strip()
        except (subprocess.SubprocessError, OSError) as exc:
            last_error = exc
            if attempt < 1:
                time.sleep(0.5)
    assert last_error is not None
    raise last_error


def environment_keys(unit: str) -> set[str]:
    keys: set[str] = set()
    # Manager environment is an independent source (DefaultEnvironment and
    # set-environment); never return its values in the public diagnostic.
    manager = subprocess.run(["systemctl", "show-environment"], text=True,
                             capture_output=True, check=True, timeout=3).stdout
    for line in manager.splitlines():
        if "=" not in line:
            raise ValueError("unparseable manager environment")
        keys.add(line.split("=", 1)[0])
    keys.update(shlex.split(systemctl_show(unit, "PassEnvironment")))
    for token in shlex.split(systemctl_show(unit, "Environment")):
        if "=" in token:
            keys.add(token.split("=", 1)[0])
    for raw in systemctl_show(unit, "EnvironmentFiles").splitlines():
        match = re.match(r"^([^ ]+)(?: \(ignore_errors=(?:yes|no)\))?$", raw.strip())
        if not match:
            keys.add("__ENVIRONMENT_FILE_UNREADABLE__")
            continue
        path = Path(match.group(1).removeprefix("-"))
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", ";")):
                    continue
                # Do not silently approve unsupported multiline systemd syntax.
                if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", stripped) or stripped.endswith("\\"):
                    keys.add("__ENVIRONMENT_FILE_UNREADABLE__")
                else:
                    keys.add(stripped.split("=", 1)[0])
        except (OSError, UnicodeError):
            keys.add("__ENVIRONMENT_FILE_UNREADABLE__")
    return keys


def effective_argv(unit: str) -> list[list[str]]:
    value = systemctl_show(unit, "ExecStart")
    commands: list[list[str]] = []
    for encoded in re.findall(r"argv\[\]=([^;]+?)\s*;", value):
        commands.append(shlex.split(encoded.strip()))
    return commands


def effective_paths(unit: str) -> list[str]:
    value = systemctl_show(unit, "ExecStart")
    # Parse only the recorded systemctl shape. Unknown/escaped/partial command
    # forms fail closed rather than inferring the executable from argv[0].
    records = re.findall(r"\{\s*path=([^;]+?)\s*;\s*argv\[\]=([^;]+?)\s*;[^{}]*\}", value)
    if len(records) != value.count("{") or not records:
        return []
    return [path.strip() for path, _ in records]


def inspect(unit: str, expected_exec: str, forbidden_environment_keys: set[str], allowed_dropin_prefixes: tuple[str, ...] = ()) -> dict:
    expected_argv = shlex.split(expected_exec)
    actual_commands = effective_argv(unit)
    actual_paths = effective_paths(unit)
    dropins = systemctl_show(unit, "DropInPaths").split()
    keys = environment_keys(unit)
    findings: list[dict[str, object]] = []
    exec_matches = bool(expected_argv) and actual_commands == [expected_argv] and actual_paths == [expected_argv[0]]
    if not exec_matches:
        findings.append({"code": "effective_exec_drift", "blocking": True})
    prefixes_valid = all(prefix.startswith("/") and prefix.endswith("/") and ".." not in Path(prefix).parts and prefix != "/" for prefix in allowed_dropin_prefixes)
    if not prefixes_valid:
        findings.append({"code": "invalid_dropin_prefix", "blocking": True})
    unexpected_dropins = [path for path in dropins if not prefixes_valid or not any(
        Path(path).is_relative_to(Path(prefix)) and ".." not in Path(path).parts
        for prefix in allowed_dropin_prefixes
    )]
    if unexpected_dropins:
        findings.append({"code": "unexpected_dropins", "blocking": True, "count": len(unexpected_dropins)})
    forbidden_present = sorted(forbidden_environment_keys & keys)
    if forbidden_present:
        findings.append({"code": "forbidden_environment_override", "blocking": True, "keys": forbidden_present})
    if "__ENVIRONMENT_FILE_UNREADABLE__" in keys:
        findings.append({"code": "environment_file_unreadable", "blocking": True})
    return {
        "unit": unit,
        "ok": not findings,
        "expected_exec": expected_argv,
        "effective_exec_matches": exec_matches,
        "scope": "ExecStart executable/argv, environment key sources and drop-in paths only; not a whole-unit sandbox or privilege approval",
        "dropin_count": len(dropins),
        "dropins": dropins,
        "unexpected_dropins": unexpected_dropins,
        "forbidden_environment_keys_present": forbidden_present,
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Check ExecStart path/argv, environment keys and drop-in paths only; not a whole-unit privilege or sandbox approval")
    parser.add_argument("--unit", required=True)
    parser.add_argument("--expected-exec", required=True)
    parser.add_argument("--forbid-environment-key", action="append", default=[])
    parser.add_argument("--allow-dropin-prefix", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = inspect(args.unit, args.expected_exec, set(args.forbid_environment_key), tuple(args.allow_dropin_prefix))
    except Exception as exc:
        result = {"unit": args.unit, "ok": False, "findings": [{"code": "systemctl_read_failed", "blocking": True, "error": type(exc).__name__}]}
    print(json.dumps(result, sort_keys=True) if args.json else ("PASS" if result["ok"] else "FAIL"))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
