"""POSIX calls the control plane needs on both Linux and macOS.

Linux has pipe2, waitid(WNOWAIT) and /proc/self/fd. macOS does not. The
replacements keep the same property: CLOEXEC pipes, observe-exit-without-reap,
and no-follow directory walks. They do not invent a memfd seal.
"""
import os
import select


# macOS ships these as root-owned symlinks into /private. They are the OS
# layout, not an attacker-controlled link. Every other symlink still fails.
_SYSTEM_LINKS = {
    '/var': 'private/var',
    '/tmp': 'private/tmp',
    '/etc': 'private/etc',
}


def cloexec_pipe():
    """Return a read/write pair that is not inherited across exec."""
    pipe2 = getattr(os, 'pipe2', None)
    if pipe2 is not None:
        return pipe2(os.O_CLOEXEC)
    read, write = os.pipe()
    for fd in (read, write):
        os.set_inheritable(fd, False)
    return read, write


def exited_unreaped(pid):
    """True when pid has exited and this process has not reaped it.

    Never reaps. Linux uses waitid(WNOWAIT). macOS has no waitid; a kqueue
    NOTE_EXIT leaves the zombie in place, which is the same pin.
    """
    if hasattr(os, 'waitid'):
        return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    kq = select.kqueue()
    try:
        events = kq.control([select.kevent(
            pid, select.KQ_FILTER_PROC,
            select.KQ_EV_ADD | select.KQ_EV_ONESHOT, select.KQ_NOTE_EXIT)], 1, 0)
        return bool(events)
    except ProcessLookupError:
        return False
    finally:
        kq.close()


def owned_command_supported():
    """True when we can supervise a child without reaping it early."""
    if hasattr(os, 'waitid'):
        return all(hasattr(os, name) for name in ('WNOWAIT', 'WEXITED', 'WNOHANG', 'P_PID', 'killpg'))
    return hasattr(select, 'kqueue') and hasattr(os, 'killpg')


def system_directory_symlink(path):
    """True only for the root-owned macOS firmlinks /var, /tmp and /etc."""
    path = os.path.abspath(path)
    expected = _SYSTEM_LINKS.get(path)
    if expected is None or not os.path.islink(path):
        return False
    if os.readlink(path) != expected:
        return False
    return os.lstat(path).st_uid == 0


def descend_directory(fd, part, built):
    """Open the next directory component. Consumes fd. Fails closed on links.

    A root-owned macOS system symlink is opened through its /private target.
    The caller still sees one step. Any other symlink raises.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        nxt = os.open(part, flags, dir_fd=fd)
    except OSError as exc:
        if exc.errno != 20 or not system_directory_symlink(built):
            raise
        os.close(fd)
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for private in os.readlink(built).split('/'):
            nxt = os.open(private, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    os.close(fd)
    return nxt


def fd_directory(fd, fallback):
    """Path a child can use as cwd for an already-checked directory fd.

    Linux can chdir /proc/self/fd/N, so the name cannot be swapped. macOS
    rejects /dev/fd/N as a directory, so the checked absolute path is the
    path the child receives. The caller must have already matched the inode.
    """
    pinned = f'/proc/self/fd/{fd}'
    if os.path.isdir(pinned):
        return pinned
    return os.path.abspath(fallback)
