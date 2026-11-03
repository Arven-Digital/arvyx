from __future__ import annotations

from pathlib import Path
import argparse
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "arvctl" / "src"))

from arvyx_control.security import (
    DENYLIST_ENV,
    iter_source_files,
    SOURCE_SKIP_DIRS,
    SECRET_RE,
    contains_literal_secret,
    canonical_shape_line_spans,
    is_expected_text,
    is_verified_image,
    is_verified_font,
    load_private_denylist,
    load_secret_scan_allowlist,
    multiline_constant_shape_spans,
    private_name_exempt_paths,
    private_name_patterns,
    python_constant_shape_spans,
    read_scannable_text,
    reviewed_line_fingerprint,
    strip_secret_refs,
)

from arvyx_control.audit import reviewed_name_example, scan_private_context

SKIP_DIRS = SOURCE_SKIP_DIRS


def _iter_scan_files(root: Path) -> list[Path]:
    """Enumerate the candidate public context.

    In a Git checkout this is the tracked files plus untracked files that are
    not ignored: exactly the content that is, or could become, public.
    Ignored local lanes (tmp/, evidence/local/, logs/) never ship, and
    scanning them makes local runs diverge from the fresh-checkout CI gate.

    A tree without .git (the extracted release archive scanned by
    public_release_export before it runs git init) falls back to every
    regular file, which is equivalent there because git archive only exports
    tracked content.
    """
    return list(iter_source_files(root))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Scan tracked and unignored candidate public context for private "
            "terms and literal secrets."
        )
    )
    parser.add_argument(
        "--shapes-only",
        action="store_true",
        help="Allow running without a private denylist; scans only generic secret shapes.",
    )
    args = parser.parse_args()

    try:
        denylist_loaded = bool(load_private_denylist(ROOT))
    except (OSError, UnicodeError, ValueError):
        print("error: configured private denylist could not be loaded", file=sys.stderr)
        return 2
    if not denylist_loaded:
        if not args.shapes_only:
            print(
                f"error: no private denylist loaded (set {DENYLIST_ENV} or add "
                ".arvyx/private-denylist.txt); pass --shapes-only only for an explicit reduced scan",
                file=sys.stderr,
            )
            return 2
        print(
            f"warning: no private denylist loaded (set {DENYLIST_ENV} or add "
            ".arvyx/private-denylist.txt); scanning for secret shapes only",
            file=sys.stderr,
        )
    try:
        hits, exempted = scan(ROOT, require_denylist=not args.shapes_only)
    except (OSError, UnicodeError, ValueError):
        print("error: private context scan could not complete", file=sys.stderr)
        return 2
    if exempted is None:
        print(
            "warning: release manifest config/public-release-paths.json is missing or "
            "malformed; private names scanned in every file (fail closed)",
            file=sys.stderr,
        )
    elif exempted:
        print(
            f"note: private-name detector skipped {exempted} manifest private-only "
            "file(s); secret shapes were scanned in every file",
            file=sys.stderr,
        )
    if hits:
        for hit in sorted(hits):
            print(hit)
        return 1
    return 0


def scan(root: Path, *, require_denylist: bool = False) -> tuple[set[str], int | None]:
    """Scan the candidate public context under root.

    Returns the findings and how many files the private-NAME detector skipped
    because the release manifest classifies them private-only (0 when no
    denylist is loaded; None when a denylist is loaded but the manifest is
    missing or malformed, so every file was name-scanned: fail closed).
    Secret shapes are scanned in every file regardless of classification.
    """
    hits, exempted, loaded, _fingerprints = scan_private_context(root)
    # Bind strict assurance to the actual scan, not a separate preflight read.
    if require_denylist and not loaded:
        raise ValueError("private denylist was not loaded by the completed scan")
    return hits, exempted


def _should_skip(path: Path, root: Path = ROOT) -> bool:
    relative = path.relative_to(root)
    if (
        relative.name == ".coverage"
        or relative.name.startswith(".coverage.")
    ):
        return True
    return any(part in SKIP_DIRS or part.endswith(".egg-info") for part in relative.parts)


if __name__ == "__main__":
    raise SystemExit(main())
