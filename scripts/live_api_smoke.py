#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from arvyx_control.dogfood import dogfood_live_api


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    result = dogfood_live_api(vault=repo / "fixtures/synthetic-vault")
    print(result.to_json())
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
