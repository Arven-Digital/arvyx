from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "arvctl" / "src"))

from arvyx_control.mcp_client_evidence import (
    validate_mcp_client_evidence, validate_release_mcp_client_evidence,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate real MCP client evidence JSON.")
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=ROOT / "examples/mcp-clients/real-client-evidence.example.json",
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument(
        "--release",
        action="store_true",
        help=(
            "Check the way the release gate does: bind git_head and git_tree to this "
            "checkout, require fresh external evidence and a pinned release-grade signer. "
            "Without --release this is a structural example check, not release-grade."
        ),
    )
    args = parser.parse_args()

    if not args.release and not args.json_output:
        print(
            "note: structural check only (no tree binding, no signature); "
            "use --release for the gate's semantics",
            file=sys.stderr,
        )

    result = (validate_release_mcp_client_evidence(args.path, repo=ROOT)
              if args.release else validate_mcp_client_evidence(args.path))
    if args.json_output:
        print(json.dumps(result, sort_keys=True))
    elif result["ok"]:
        print(f"ok=true client={result.get('client')} transport={result.get('transport')}")
    else:
        for error in result["errors"]:
            print(error, file=sys.stderr)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
