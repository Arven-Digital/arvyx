"""Lock-free admission checks shared by mutation and snapshot boundaries.

No imports of mutation producers: callers must hold the canonical vault lock.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat as stat_module
from .filesystem import fsync_directory

def _read_regular_nofollow(path: Path, root: Path) -> bytes:
    """Open with O_NOFOLLOW, fstat-verify a regular file inside the vault root,
    then read through the verified fd (no symlink TOCTOU)."""
    try:
        # A FIFO replacement must not block before fstat can reject it.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise FileNotFoundError(str(path)) from exc
    try:
        info = os.fstat(fd)
        named = os.lstat(path)
        if (not stat_module.S_ISREG(info.st_mode)
                or not stat_module.S_ISREG(named.st_mode)
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
            raise ValueError(f"refusing non-regular file: {path}")
        resolved = Path(os.path.realpath(path))
        if resolved != root and root not in resolved.parents:
            raise ValueError(f"refusing path outside root: {path}")
        chunks: list[bytes] = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        return b"".join(chunks)
    finally:
        os.close(fd)


def assert_copyable_forget_operations(root: Path, *, recovery: tuple[str, str] | None = None) -> None:
    """Require completed intents before copying; caller owns memory_mutation.

    Never repair inode witnesses on a copy. Reconcile unfinished requests on
    the original filesystem using their exact request and idempotency key.
    Completed receipts bypass witnesses on replay, so their old inode numbers
    are harmless after copying. Repeat their namespace barrier before admitting
    another mutation or snapshot; visible receipt bytes alone are not durable
    completion. Malformed or mismatched receipts fail closed.
    """
    lane = root / ".arvyx" / "forget-operations"
    for directory in (root / ".arvyx", lane):
        if not os.path.lexists(directory):
            return
        if not stat_module.S_ISDIR(os.lstat(directory).st_mode):
            raise RuntimeError("snapshot requires a regular forget operation directory")
    for path in sorted(lane.glob("*.intent.json")):
        try:
            if re.fullmatch(r"[0-9a-f]{64}\.intent\.json", path.name) is None:
                raise ValueError("invalid intent name")
            intent = json.loads(_read_regular_nofollow(path, root))
            receipt_path = path.with_name(path.name.removesuffix(".intent.json") + ".json")
            result = intent["result"]
            request_hash = intent["request_hash"]
            if (not isinstance(result, dict)
                    or result.get("status") not in {"forgotten", "restored"}
                    or not isinstance(request_hash, str)
                    or re.fullmatch(r"[0-9a-f]{64}", request_hash) is None
                    or hashlib.sha256(result["idempotency_key"].encode()).hexdigest()
                    != path.name.removesuffix(".intent.json")):
                raise ValueError("invalid operation intent")
            if os.path.lexists(receipt_path):
                receipt = json.loads(_read_regular_nofollow(receipt_path, root))
                if receipt != {"request_hash": request_hash, "result": result}:
                    raise ValueError("completion receipt does not match intent")
                fsync_directory(receipt_path.parent)
            elif recovery != (result["idempotency_key"], request_hash):
                raise ValueError("unfinished operation fences governed mutations")
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            raise RuntimeError(
                "mutation/snapshot refused: unfinished or invalid forget/restore intent; "
                "reconcile on the original filesystem before capture"
            ) from exc

