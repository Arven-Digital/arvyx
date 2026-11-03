from __future__ import annotations
from contextlib import closing

from importlib import resources
from pathlib import Path
import os
import stat
import tempfile
import threading

from . import private_paths, safe_open
from .vault import VAULT_MARKER
from .vault import init_vault


DEFAULT_VAULT = Path("fixtures/synthetic-vault")
DEFAULT_BENCHMARK_CASES = Path("fixtures/recall-benchmark.json")
_CACHE_ROOT: Path | None = None
_CACHE_LOCK = threading.RLock()


def resolve_default_vault(path: Path) -> Path:
    """Choose the actual vault before a caller enters authority_context.

    The packaged fallback changes identity, not just spelling. Never resolve it
    for the first time inside an already-bound dispatch.
    """
    if path != DEFAULT_VAULT or path.exists():
        return path
    with _CACHE_LOCK:
        root = _cache_root()
        _validate_cache(root)
        cache = root / "synthetic-vault"
        if not (cache / VAULT_MARKER).exists():
            # init_vault follows the ambient umask (often 0002). Create under a
            # umask that never grants group/other write, so no writable window
            # exists, then also tighten only the tree just created (pre-existing
            # entries were validated above; init_vault refuses a non-empty target).
            # Validation still decides.
            previous = os.umask(0o022)
            try:
                os.umask(previous | 0o022)
                init_vault(cache, force=False)
            finally:
                os.umask(previous)
            _drop_group_other_write(root, cache.name)
        _validate_cache(root)
        return cache


def resolve_default_benchmark_cases(path: Path) -> Path:
    if path != DEFAULT_BENCHMARK_CASES or path.exists():
        return path
    with _CACHE_LOCK:
        root = _cache_root()
        _validate_cache(root)
        cache = root / "recall-benchmark.json"
        data = resources.files("arvyx_control.data").joinpath("recall-benchmark.json").read_text(encoding="utf-8")
        if not cache.exists():
            fd, name = tempfile.mkstemp(prefix='.benchmark-', dir=root)
            temporary = Path(name)
            try:
                with os.fdopen(fd, 'w', encoding='utf-8', newline="\n") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temporary, cache, follow_symlinks=False)
                except FileExistsError:
                    pass
            finally:
                temporary.unlink(missing_ok=True)
        # A same-user stale marker is not content authority either.
        fd = safe_open.open_file(cache)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or stream.read(len(data.encode()) + 1) != data.encode():
                raise ValueError('packaged benchmark cache differs from packaged resource')
            safe_open.fsync_file(stream.fileno())
        directory_fd = safe_open.open_directory(root)
        try:
            safe_open.fsync_directory(directory_fd)
        finally:
            os.close(directory_fd)
        return cache


def ensure_repo_checkout(repo: Path) -> Path:
    repo = repo.resolve()
    required = [
        repo / "README.md",
        repo / "docs/security-audit.md",
        repo / "docs/release-gate.md",
        repo / "packages/arvctl/src/arvyx_control/cli.py",
    ]
    missing = [str(path.relative_to(repo)) for path in required if not path.exists()]
    if missing:
        raise ValueError(
            "--repo must point at an arvyx checkout for this command; "
            f"missing {', '.join(missing)}"
        )
    return repo


def _cache_root() -> Path:
    global _CACHE_ROOT
    with _CACHE_LOCK:
        if _CACHE_ROOT is None:
            # A stable per-user cache preserves default-vault identity across
            # CLI invocations. Never adopt the old shared marker-only cache.
            # Windows keeps per-user caches under LOCALAPPDATA; TEMP there is often
            # writable by other accounts, and the mode argument means nothing.
            base = Path(os.environ['LOCALAPPDATA']) if os.name == 'nt' and os.environ.get('LOCALAPPDATA') else Path(tempfile.gettempdir())
            root = base / f'amc-packaged-defaults-{private_paths.current_user()}'
            private_paths.ensure_private_directory(root, mode=0o700)
            _validate_cache(root)
            _CACHE_ROOT = root
        return _CACHE_ROOT


def _validate_cache(root: Path) -> None:
    """Reject aliases and foreign/writable cache entries before marker trust.

    The stable per-user 0700 root is the access boundary; descendant
    defaults may be readable but may not be writable by other users.
    """
    fd = safe_open.open_directory(root)
    try:
        info = os.fstat(fd)
        if not private_paths.owner_private(info, fd=fd):
            raise ValueError('packaged default cache requires owner-private root')
        _validate_cache_entries(fd)
    finally:
        os.close(fd)


def _drop_group_other_write(root: Path, name: str) -> None:
    """Remove group/other write from a freshly materialized cache subtree.

    Descriptor-relative and no-follow: a symlink or special file is left as is
    and is then refused by _validate_cache. Ownership is never changed.
    """
    parent = safe_open.open_directory(root)
    try:
        _drop_write_at(parent, name)
    finally:
        os.close(parent)


def _drop_write_at(parent: int, name: str) -> None:
    try:
        fd = safe_open.open_entry_at(parent, name)
    except OSError:
        return  # missing, symlink or special entry: left for validation to decide
    try:
        info = os.fstat(fd)
        if not private_paths.owned_by_current_user(info, fd=fd) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            return
        private_paths.drop_others_write(info, fd)
        if stat.S_ISDIR(info.st_mode):
            with closing(safe_open.scandir_names(fd)) as names_iter:
                for child in names_iter:
                    _drop_write_at(fd, child)
    finally:
        os.close(fd)


def _validate_cache_entries(fd: int) -> None:
    with closing(safe_open.scandir_names(fd)) as names_iter:
        for name in names_iter:
            info = safe_open.stat_at(fd, name)
            if (not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                    or not private_paths.owned_by_current_user(info, dirfd=fd, name=name)
                    or not private_paths.not_writable_by_others(info, dirfd=fd, name=name)):
                raise ValueError('packaged default cache contains untrusted entry')
            if stat.S_ISDIR(info.st_mode):
                child = safe_open.open_directory_at(fd, name)
                try:
                    _validate_cache_entries(child)
                finally:
                    os.close(child)
