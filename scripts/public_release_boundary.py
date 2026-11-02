from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
from typing import Iterable, Mapping


CLASSIFICATIONS = {
    "private-only",
    "public-approved",
    "reimplemented-clean-room",
}

# Every private-only file must announce that it is private, in the first few
# lines, so a reader cannot copy private context out without seeing the warning.
NOTICE_MARKER = "PRIVATE: DO NOT PUBLISH"

# Private-only paths whose format has no comment syntax. Each entry states why.
# The check fails if a path is neither marked nor declared here, and also if a
# declaration here is no longer a private-only path.
NOTICE_EXEMPT: dict[str, str] = {
    "PRIVATE-BACKUP-MANIFEST.json": "Historical private backup path inventory; JSON has no comment syntax; never an export source",
    "config/public-release-paths.json": "JSON cannot carry comments, and this file is the classification authority itself",
    "config/public-candidate-rules.json": "Public candidate export rules (exclusions name private paths); JSON has no comment syntax; private-only classification forbids export",
}


class BoundaryError(RuntimeError):
    pass


def _normalize(path: str) -> str:
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        raise BoundaryError("invalid repository-relative path")
    normalized = PurePosixPath(path).as_posix()
    if ".." in PurePosixPath(path).parts or normalized in {"", "."} or normalized.startswith("../") or normalized.startswith("/"):
        raise BoundaryError(f"invalid tracked path: {path}")
    return normalized


def load_manifest(manifest_path: Path) -> dict[str, str]:
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BoundaryError("duplicate key in classification manifest")
            result[key] = value
        return result

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"),
                          object_pairs_hook=unique_fields)
    except (OSError, json.JSONDecodeError) as exc:
        raise BoundaryError(f"cannot load classification manifest: {exc}") from exc
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("paths"), dict):
        raise BoundaryError("classification manifest must have version 1 and a paths object")

    classifications: dict[str, str] = {}
    for raw_path, classification in data["paths"].items():
        path = _normalize(raw_path)
        if path != raw_path:
            raise BoundaryError("non-canonical classification path")
        if path in classifications:
            raise BoundaryError(f"ambiguous classification for {path}")
        if not isinstance(classification, str):
            raise BoundaryError(f"ambiguous classification for {path}")
        if classification not in CLASSIFICATIONS:
            raise BoundaryError(f"invalid classification for {path}: {classification}")
        classifications[path] = classification
    return classifications


def validate_tracked_paths(manifest_path: Path, tracked_paths: Iterable[str]) -> dict[str, str]:
    classifications = load_manifest(manifest_path)
    tracked = {_normalize(path) for path in tracked_paths}
    unclassified = sorted(tracked - classifications.keys())
    stale = sorted(classifications.keys() - tracked)
    if unclassified:
        raise BoundaryError(f"unclassified tracked paths: {', '.join(unclassified)}")
    if stale:
        raise BoundaryError(f"manifest paths are not tracked: {', '.join(stale)}")
    return classifications


def validate_candidate_provenance(
    manifest_path: Path, candidate_sources: Mapping[str, Mapping[str, str]]
) -> None:
    classifications = load_manifest(manifest_path)
    for candidate_path, provenance in candidate_sources.items():
        _normalize(candidate_path)
        if not isinstance(provenance, Mapping):
            raise BoundaryError(f"invalid candidate provenance for {candidate_path}")
        source = _normalize(provenance.get("source", ""))
        method = provenance.get("method")
        if method not in {"copied", "clean-room"}:
            raise BoundaryError(f"invalid candidate provenance method for {candidate_path}")
        classification = classifications.get(source)
        if classification is None:
            raise BoundaryError(f"candidate source is unclassified: {source}")
        if classification == "private-only":
            raise BoundaryError(f"private-only source cannot be copied: {source}")
        if classification == "reimplemented-clean-room" and method != "clean-room":
            raise BoundaryError(f"source must be reimplemented, not copied: {source}")


def check_private_notices(
    repo: Path,
    classifications: Mapping[str, str],
    *,
    exempt: Mapping[str, str] | None = None,
    head_lines: int = 6,
) -> list[str]:
    """Return the reasons private-only files fail to announce that they are private.

    Two failure shapes matter. A private-only file with no notice looks ordinary
    and gets copied out by someone who never read the manifest. A non-private
    file carrying the notice is the reverse contradiction and means a
    classification is wrong. Stale exemptions are reported too, so the exempt
    list cannot rot the way the allowlist cannot.
    """
    exemptions = dict(NOTICE_EXEMPT if exempt is None else exempt)
    if any(path.startswith("frontends/paperclip/") for path in classifications):
        from verified_private_bytes import verified_notice_exemptions
        try:
            exemptions.update(verified_notice_exemptions(repo, classifications))
        except (ValueError, OSError, KeyError, TypeError) as exc:
            return [f"immutable notice verification failed: {exc}"]
    private_paths = {path for path, kind in classifications.items() if kind == "private-only"}
    gaps: list[str] = []
    for path in sorted(classifications):
        full = repo / path
        if not full.is_file():
            if path in private_paths:
                gaps.append(f"private-only path is missing: {path}")
            continue
        head = "\n".join(
            full.read_text(encoding="utf-8", errors="ignore").splitlines()[:head_lines]
        )
        marked = NOTICE_MARKER in head
        if path in private_paths:
            if not marked and path not in exemptions:
                gaps.append(f"private-only file lacks the notice: {path}")
        elif marked:
            gaps.append(f"non-private file claims to be private: {path}")
    # The built-in exemption table describes the private tree. In a tree that
    # classifies nothing as private-only (the exported public candidate) it is
    # inert rather than stale; an explicitly supplied table is always checked.
    if exempt is not None or private_paths:
        for path in sorted(set(exemptions) - private_paths):
            gaps.append(f"stale notice exemption: {path}")
    return gaps


def git_tracked_paths(repo: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"], cwd=repo, capture_output=True, check=True
    )
    return [path.decode("utf-8") for path in completed.stdout.split(b"\0") if path]


def validate_working_candidate(repo: Path, manifest_path: Path, spec: Mapping) -> dict[str, str]:
    """Validate an explicit dirty rename view; NEVER a tracked-release approval.

    Every removed indexed path must have an individually acknowledged blob and
    classification. Untracked additions must be explicitly named. No glob ignores.
    The ordinary release gate remains strict and unchanged.
    """
    if not isinstance(spec, Mapping) or set(spec) != {'renames', 'additions'}:
        raise BoundaryError('candidate requires exact renames and additions')
    if not isinstance(spec['renames'], list) or not isinstance(spec['additions'], list):
        raise BoundaryError('candidate renames and additions must be lists')
    classifications = load_manifest(manifest_path)
    paths = set(git_tracked_paths(repo))
    targets = set()
    for move in spec['renames']:
        if not isinstance(move, Mapping) or set(move) != {'source', 'target', 'indexed_blob', 'classification'}:
            raise BoundaryError('invalid rename declaration')
        source, target = _normalize(move['source']), _normalize(move['target'])
        if source not in paths or target in paths or target in targets or (repo / source).exists():
            raise BoundaryError('rename must replace one absent indexed source')
        blob = subprocess.check_output(['git', 'rev-parse', ':' + source], cwd=repo, text=True).strip()
        old_head = subprocess.check_output(['git', 'show', ':' + source], cwd=repo).decode('utf-8', errors='replace').splitlines()[:6]
        if move['classification'] != 'private-only' or NOTICE_MARKER not in '\n'.join(old_head):
            raise BoundaryError('dirty rename support is restricted to notice-marked private-only source')
        if blob != move['indexed_blob'] or classifications.get(target) != move['classification']:
            raise BoundaryError('rename blob or classification mismatch')
        paths.remove(source)
        paths.add(target)
        targets.add(target)
    for raw in spec['additions']:
        path = _normalize(raw)
        if path in paths:
            raise BoundaryError('duplicate candidate addition')
        paths.add(path)
    result = validate_tracked_paths(manifest_path, paths)
    for path in paths:
        full = repo / path
        components = [repo.joinpath(*PurePosixPath(path).parts[:index])
                      for index in range(1, len(PurePosixPath(path).parts) + 1)]
        if any(component.is_symlink() for component in components) or not full.is_file():
            raise BoundaryError('candidate file absent or symlink: ' + path)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail unless every tracked path has exactly one release-boundary classification."
    )
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument(
        "--manifest", type=Path, default=Path("config/public-release-paths.json")
    )
    parser.add_argument('--working-candidate', type=Path, help='Explicit rename/addition JSON; local candidate check only, not release approval')
    args = parser.parse_args()
    manifest = args.manifest
    if not manifest.is_absolute():
        manifest = args.repo / manifest
    try:
        classifications = (validate_working_candidate(args.repo, manifest,
            json.loads(args.working_candidate.read_text())) if args.working_candidate else
            validate_tracked_paths(manifest, git_tracked_paths(args.repo)))
    except (BoundaryError, subprocess.CalledProcessError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    gaps = check_private_notices(args.repo, classifications)
    if gaps:
        for gap in gaps:
            print(f"error: {gap}", file=sys.stderr)
        return 1
    counts = {name: 0 for name in sorted(CLASSIFICATIONS)}
    for classification in classifications.values():
        counts[classification] += 1
    private_total = counts["private-only"]
    # Only exemptions that apply to a private-only path count; in a tree without
    # private-only paths (the public candidate) the built-in table is inert.
    notice_exempt_total = sum(1 for path in NOTICE_EXEMPT if classifications.get(path) == "private-only")
    if any(path.startswith("frontends/paperclip/") for path in classifications):
        from verified_private_bytes import verified_notice_exemptions
        notice_exempt_total += len(verified_notice_exemptions(args.repo, classifications))
    print(
        json.dumps(
            {
                "ok": True,
                "scope": 'explicit-working-candidate' if args.working_candidate else 'tracked-release-boundary',
                "release_approved": False,
                "counts": counts,
                "private_notices": {
                    "total": private_total,
                    "marked": private_total - notice_exempt_total,
                    "exempt": notice_exempt_total,
                },
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
