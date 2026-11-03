"""Owner and privacy facts about files, on POSIX (uid, mode) and Windows (SID, DACL).

The package decides three things about a path it is going to trust:

- *owned by the current user*: POSIX ``st_uid == os.getuid()`` (``allow_root`` also
  accepts uid 0); Windows: the owner SID is the process token's user (``allow_root``
  also accepts SYSTEM and Administrators).
- *private*: POSIX ``st_mode & 0o077 == 0``; Windows: the DACL allows access to the
  trusted set only (``windows_acl.private_path_problem``).
- *not writable by others* (the ancestor rule): POSIX ``st_mode & 0o022 == 0``;
  Windows: no write-class right for anyone outside the trusted set.

POSIX callers keep passing the ``stat_result`` they already hold; nothing is
re-read. On Windows the mode and uid fields carry no information, so the facts are
read from the security descriptor of the open descriptor (``fd``) when the caller
holds one, else of the path. A Windows caller that supplies neither gets a refusal,
never a guess. ``current_user()`` is an ``int`` uid on POSIX and the string SID on
Windows; it is only ever compared for equality or stored as provenance.
"""
from __future__ import annotations

import os
import stat

_WINDOWS = os.name == "nt"


def current_user() -> int | str:
    """Real user identity: uid on POSIX, token SID string on Windows."""
    if _WINDOWS:
        from .windows_acl import current_user_sid
        return current_user_sid()
    return os.getuid()


def effective_user() -> int | str:
    """Effective user identity: euid on POSIX, token SID on Windows (no setuid there)."""
    if _WINDOWS:
        return current_user()
    return os.geteuid()


def is_root() -> bool:
    """POSIX euid 0. Windows never reports root: elevation is not a user identity."""
    return False if _WINDOWS else os.geteuid() == 0


def _windows_target(fd, path):
    if fd is None and path is None:
        raise OSError("Windows ownership checks need an open descriptor or a path")
    return fd, path


def _windows_entry(fd, path, dirfd, name):
    """Resolve (fd, path) for Windows checks; a (dirfd, name) pair is opened relative, never by path."""
    if fd is None and path is None and dirfd is not None and name is not None:
        from . import safe_open
        return safe_open.open_entry_at(dirfd, name), None, True
    return fd, path, False


def owned_by_current_user(st: os.stat_result, *, fd: int | None = None, path=None, dirfd: int | None = None,
                          name: str | None = None, allow_root: bool = False) -> bool:
    if not _WINDOWS:
        uid = os.getuid()
        return st.st_uid == uid or (allow_root and st.st_uid == 0)
    from . import windows_acl
    fd, path, opened = _windows_entry(fd, path, dirfd, name)
    try:
        fd, path = _windows_target(fd, path)
        owner, _rows = windows_acl.security_entries(path, fd=fd)
    finally:
        if opened:
            os.close(fd)
    if allow_root:
        return owner in windows_acl.trusted_sids()
    # An elevated administrator's objects are owned by Administrators (the token's
    # default owner), so ownership means the user SID or that default owner.
    return owner in windows_acl.current_owner_sids()


def is_private(st: os.stat_result, *, fd: int | None = None, path=None, dirfd: int | None = None,
               name: str | None = None) -> bool:
    """No access for anyone but the owner (POSIX 0o077; Windows DACL)."""
    if not _WINDOWS:
        return not stat.S_IMODE(st.st_mode) & 0o077
    from . import windows_acl
    fd, path, opened = _windows_entry(fd, path, dirfd, name)
    try:
        fd, path = _windows_target(fd, path)
        return windows_acl.private_path_problem(path, fd=fd) is None
    finally:
        if opened:
            os.close(fd)


def not_writable_by_others(st: os.stat_result, *, fd: int | None = None, path=None, dirfd: int | None = None,
                           name: str | None = None) -> bool:
    """No write access for anyone but the owner (POSIX 0o022; Windows DACL)."""
    if not _WINDOWS:
        return not stat.S_IMODE(st.st_mode) & 0o022
    from . import windows_acl
    fd, path, opened = _windows_entry(fd, path, dirfd, name)
    try:
        fd, path = _windows_target(fd, path)
        return windows_acl.others_writable_problem(path, fd=fd) is None
    finally:
        if opened:
            os.close(fd)


def owner_private(st: os.stat_result, *, fd: int | None = None, path=None, dirfd: int | None = None,
                  name: str | None = None, allow_root: bool = False) -> bool:
    """Owned by the current user and private: the usual guard for state directories and secrets."""
    return (owned_by_current_user(st, fd=fd, path=path, dirfd=dirfd, name=name, allow_root=allow_root)
            and is_private(st, fd=fd, path=path, dirfd=dirfd, name=name))


def drop_others_write(st: os.stat_result, fd: int) -> None:
    """Remove group/other write on POSIX; on Windows the equivalent is the trusted-set DACL."""
    if not _WINDOWS:
        if st.st_mode & 0o022:
            os.fchmod(fd, stat.S_IMODE(st.st_mode) & ~0o022)
        return
    if not not_writable_by_others(st, fd=fd):
        make_private(fd=fd)


def make_private(*, fd: int | None = None, path=None, mode: int = 0o700) -> None:
    """chmod to ``mode`` on POSIX; on Windows replace the DACL with the trusted set (any ``mode``)."""
    if not _WINDOWS:
        if fd is not None:
            os.fchmod(fd, mode)
        else:
            os.chmod(path, mode)
        return
    from . import windows_acl
    fd, path = _windows_target(fd, path)
    windows_acl.make_private(path, fd=fd)


def is_private_mode(mode: int, *, fd: int | None = None, path=None) -> bool:
    """``is_private`` for callers holding only a mode (an identity tuple); Windows reads the DACL."""
    if not _WINDOWS:
        return not stat.S_IMODE(mode) & 0o077
    from . import windows_acl
    fd, path = _windows_target(fd, path)
    return windows_acl.private_path_problem(path, fd=fd) is None


def is_private_mode(mode: int, *, fd: int | None = None, path=None) -> bool:
    """``is_private`` for callers holding only a mode (an identity tuple); Windows reads the DACL."""
    if not _WINDOWS:
        return not stat.S_IMODE(mode) & 0o077
    from . import windows_acl
    fd, path = _windows_target(fd, path)
    return windows_acl.private_path_problem(path, fd=fd) is None


def apply_mode(*, fd: int | None = None, path=None, mode: int) -> None:
    """chmod on POSIX. On Windows a no-op: modes are not a Windows fact.

    ``os.chmod`` there only toggles the READONLY attribute, which would make the file
    impossible to rename, replace or delete (unlike POSIX 0o444, where the directory
    governs those); privacy is the DACL inherited from the private parent instead.
    """
    if _WINDOWS:
        return
    if fd is not None:
        os.fchmod(fd, mode)
    else:
        os.chmod(path, mode)


def ensure_private_directory(path, *, mode: int = 0o700) -> bool:
    """mkdir ``path`` privately if absent; return True when it was created now.

    POSIX relies on the mode at creation (as the callers did); Windows applies the
    protected DACL to a directory created here. An existing directory is left as it
    is: the caller's privacy check decides whether to trust it.
    """
    try:
        os.mkdir(path, mode)
    except FileExistsError:
        return False
    if _WINDOWS:
        make_private(path=path)
    return True


def apply_owner(fd: int, uid, gid) -> None:
    """Restore recorded ownership. Windows has no chown: only the current user's own identity is accepted."""
    if not _WINDOWS:
        os.fchown(fd, uid, gid)
        return
    if uid not in (None, current_user()):
        raise OSError("cannot assign file ownership to another principal on Windows")
