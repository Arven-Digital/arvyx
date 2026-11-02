#!/usr/bin/env python3
"""Deterministic test-file shards for the hosted coverage run.

The Python suite under branch coverage is the longest hosted job. Splitting it across
machines needs a partition that every job computes identically and that balances the
work: files are sorted, then assigned greedily (largest first) to the currently lightest
shard, with file size as the work estimate. Every file lands in exactly one shard.

    python scripts/ci_test_shard.py --count 2 --index 1   # prints shard 1's files

Only the standard library is used; the script is also importable for the test.
"""
from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_ROOTS = ("packages/arvctl/tests", "tests")


def test_files(root: Path = ROOT) -> list[Path]:
    files: list[Path] = []
    for relative in TEST_ROOTS:
        files.extend(sorted((root / relative).glob("test_*.py")))
    return files


def shards(count: int, root: Path = ROOT) -> list[list[Path]]:
    if count < 1:
        raise ValueError("shard count must be positive")
    weighted = sorted(test_files(root), key=lambda path: (-path.stat().st_size, path.as_posix()))
    buckets: list[list[Path]] = [[] for _ in range(count)]
    loads = [0] * count
    for path in weighted:
        index = min(range(count), key=lambda i: (loads[i], i))
        buckets[index].append(path)
        loads[index] += path.stat().st_size
    return [sorted(bucket) for bucket in buckets]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--count", type=int, required=True, help="number of shards")
    parser.add_argument("--index", type=int, required=True, help="1-based shard to print")
    args = parser.parse_args(argv)
    if not 1 <= args.index <= args.count:
        parser.error("--index must be between 1 and --count")
    print(" ".join(path.relative_to(ROOT).as_posix() for path in shards(args.count)[args.index - 1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
