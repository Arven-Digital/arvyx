"""The hosted coverage shards must partition the suite exactly and deterministically."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]


def _module():
    spec = importlib.util.spec_from_file_location("ci_test_shard", ROOT / "scripts/ci_test_shard.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_every_test_file_is_in_exactly_one_shard():
    module = _module()
    files = module.test_files()
    assert Path(__file__).resolve() in files
    for count in (1, 2, 3, 4):
        parts = module.shards(count)
        assert len(parts) == count
        seen = [path for part in parts for path in part]
        assert sorted(seen) == sorted(files), count
        assert len(seen) == len(set(seen)), count
        assert all(part for part in parts), count  # no empty shard for these counts


def test_shards_are_deterministic_and_balanced():
    module = _module()
    first, second = module.shards(2), module.shards(2)
    assert first == second
    loads = [sum(path.stat().st_size for path in part) for part in first]
    assert max(loads) <= 1.5 * min(loads), loads


def test_cli_prints_repository_relative_paths_for_one_shard():
    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts/ci_test_shard.py"), "--count", "2", "--index", "2"],
        check=True, capture_output=True, text=True, cwd=ROOT,
    ).stdout.split()
    module = _module()
    expected = [path.relative_to(ROOT).as_posix() for path in module.shards(2)[1]]
    assert out == expected
    assert all(not Path(item).is_absolute() for item in out)
    bad = subprocess.run([sys.executable, str(ROOT / "scripts/ci_test_shard.py"), "--count", "2", "--index", "3"],
                         capture_output=True, text=True, cwd=ROOT)
    assert bad.returncode != 0


def test_shard_union_equals_what_pytest_collects():
    """pytest's own collection is the oracle: a file the shards miss would run in no CI
    shard and silently leave the coverage floor."""
    module = _module()
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
         "packages/arvctl/tests", "tests"],
        check=True, capture_output=True, text=True, cwd=ROOT,
    ).stdout
    collected = {ROOT / line.split("::", 1)[0] for line in out.splitlines() if "::" in line}
    assert collected, "pytest collected nothing"
    assert collected == set(module.test_files())
