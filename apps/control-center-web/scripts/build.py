#!/usr/bin/env python3
"""Build the dependency-free synthetic observatory deterministically."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "public-safe-synthetic"
DIST = ROOT / "dist"


def commit_id() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short=8", "HEAD"], cwd=ROOT, text=True
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise SystemExit(f"error: cannot resolve commit id from git: {exc}") from exc


def build() -> dict[str, str]:
    if DIST.exists():
        shutil.rmtree(DIST)
    shutil.copytree(SOURCE, DIST)
    fixture = json.loads((DIST / "fixtures/replay.json").read_text(encoding="utf-8"))
    commit = commit_id()
    index = (DIST / "index.html").read_text(encoding="utf-8")
    index = index.replace("<html lang=\"en\">", f'<html lang="en" data-commit="{commit}">')
    (DIST / "index.html").write_text(index, encoding="utf-8")
    manifest = {"build_id": fixture["build_id"], "commit_id": commit, "source": "public-safe-synthetic"}
    (DIST / "build.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = build()
    print(json.dumps(result, sort_keys=True) if args.json else f"built {result['build_id']} @ {result['commit_id']}")
