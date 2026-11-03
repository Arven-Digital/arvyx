"""Descriptor-relative, no-follow filesystem opens on POSIX and Windows.

The authoritative writers and readers in this package walk paths one component at a
time from the filesystem root, opening each directory relative to the previous one
with ``O_NOFOLLOW`` so that no symbolic link (and no replaced ancestor) can redirect
them, and judge every object by the descriptor they hold, never by a path they
looked at earlier. On POSIX that is ``os.open(..., dir_fd=...)``; this module keeps
those exact calls. Windows has the same primitive in the native API: ``NtCreateFile``
with a ``RootDirectory`` handle opens a single name relative to an open directory,
``FILE_OPEN_REPARSE_POINT`` refuses to traverse symbolic links and junctions (the
object itself is opened and then recognised as a reparse point and rejected), and
``FILE_DIRECTORY_FILE`` / ``FILE_NON_DIRECTORY_FILE`` are ``O_DIRECTORY`` and its
negation. The handle becomes a C run-time descriptor through ``msvcrt``, so
``os.fstat``, ``os.read`` and ``os.close`` work on it unchanged, and ``os.fstat``
reports the volume serial and file index as ``st_dev`` / ``st_ino``, which is the
identity the callers compare.

Every function raises ``OSError`` on refusal, exactly like the POSIX calls it
replaces, so the callers' existing ``except OSError`` handling stays correct. The
functions never fall back to path-based opens: when the platform lacks the
primitive, ``available()`` is false and ``open_root`` raises.

Differences a caller must know (documented in docs/limitations.md):

- Windows directory listing (``scandir_names``) reads the directory by the handle's
  final path, because the C run-time cannot enumerate a directory descriptor; the
  names are only names, every child is still opened relative to the handle.
- ``st_ctime_ns`` on Windows is the creation time, not the inode change time.
- Modes are POSIX facts. ``os.fchmod`` on Windows only toggles the read-only
  attribute; privacy on Windows is the NTFS DACL (see ``windows_acl``).
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

_WINDOWS = os.name == "nt"

def _posix_ok() -> bool:
    # Evaluated per call so a caller simulating an unsupported platform (a test
    # patching os) is answered honestly, exactly as the direct checks were.
    # Truthiness, not membership: a test may patch os.open with a recorder while the
    # platform still supports dir_fd, and another may empty supports_dir_fd to simulate
    # a platform without it.
    return bool(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY") and os.supports_dir_fd and os.supports_fd)


def available() -> bool:
    """True when descriptor-relative no-follow opens exist on this platform."""
    if _WINDOWS:
        try:
            _nt()
        except OSError:
            return False
        return True
    return _posix_ok()


def stable_identity(value: int) -> int:
    """st_dev / st_ino as a signed 64-bit integer (SQLite INTEGER); unchanged on POSIX.

    Windows reports the volume serial and the 64-bit file index unsigned, so values
    at or above 2**63 are wrapped; the mapping is a bijection and the same on the
    store and the compare side.
    """
    return value - (1 << 64) if value >= (1 << 63) else value


# A fixed absolute anchor under which a vetted component is normalized; the prefix
# check below is the shape static analysis models as a path sanitizer.
_ANCHOR = os.path.join(os.sep, "arvyx-component")


def component(name: str, *, allow_self: bool = False) -> str:
    """Return ``name`` as a single plain path component, or raise ``OSError``.

    Plain means: non-empty, not ``.`` or ``..``, no ``/`` or ``\\``, no NUL and no
    ``:`` on Windows (drive and NTFS stream syntax). The name is also joined under a
    fixed anchor, normalized and required to stay directly under it, so a vetted value
    is exactly the input and the check is visible to path-injection analysis. Every
    descriptor-relative call here uses the returned value.
    """
    if allow_self and name == ".":
        return name
    if (not isinstance(name, str) or not name or name in (".", "..") or "/" in name
            or "\\" in name or "\x00" in name or (_WINDOWS and ":" in name)):
        raise OSError(f"invalid path component {name!r}")
    joined = os.path.normpath(os.path.join(_ANCHOR, name))
    if not joined.startswith(_ANCHOR + os.sep):
        raise OSError(f"invalid path component {name!r}")
    vetted = joined[len(_ANCHOR) + 1:]
    if vetted != name or os.sep in vetted or (os.altsep and os.altsep in vetted):
        raise OSError(f"invalid path component {name!r}")
    return vetted


def _refuse_component(name: str, *, allow_self: bool = False) -> str:
    return component(name, allow_self=allow_self)


def _encoded_native_name(name: str) -> bytes:
    """UTF-16 payload fitting UNICODE_STRING's USHORT lengths, including a terminator."""
    encoded = name.encode("utf-16-le", errors="surrogatepass")
    if len(encoded) + 2 > 0xFFFF:
        raise OSError(36, "native path name exceeds UNICODE_STRING capacity")
    return encoded


# --------------------------------------------------------------------------- POSIX

if not _WINDOWS:

    def open_root(root: os.PathLike | str) -> int:
        """Directory descriptor for an absolute path, walked component-wise with O_NOFOLLOW."""
        if not _posix_ok():
            raise OSError("secure descriptor-relative opens unavailable")
        path = Path(root)
        if not path.is_absolute():
            raise OSError("root must be absolute")
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:]:
                part = _refuse_component(part)
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            return fd
        except BaseException:
            os.close(fd)
            raise

    def open_directory_at(dirfd: int, name: str) -> int:
        """Open a directory name relative to a descriptor; '.' reopens the directory itself."""
        name = _refuse_component(name, allow_self=True)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            return os.open(name, flags, dir_fd=dirfd)
        except OSError as exc:
            if exc.errno != 20 or name in ('.', '..'):
                raise
            root = os.stat('/')
            info = os.fstat(dirfd)
            if (info.st_dev, info.st_ino) != (root.st_dev, root.st_ino):
                raise
            from .posix_support import system_directory_symlink
            if not system_directory_symlink('/' + name):
                raise
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                for private in os.readlink('/' + name).split('/'):
                    nxt = os.open(private, flags | os.O_CLOEXEC, dir_fd=fd)
                    os.close(fd)
                    fd = nxt
                result, fd = fd, None
                return result
            finally:
                if fd is not None:
                    os.close(fd)

    def open_file_at(dirfd: int, name: str, *, write: bool = False, create: bool = False,
                     exclusive: bool = False, mode: int = 0o600) -> int:
        name = _refuse_component(name)
        flags = (os.O_RDWR if write else os.O_RDONLY) | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        if not write:
            flags |= os.O_NONBLOCK
        if create:
            flags |= os.O_CREAT
            if exclusive:
                flags |= os.O_EXCL
        fd = os.open(name, flags, mode, dir_fd=dirfd)
        # A read-only open of a directory succeeds on POSIX; refuse it here so the
        # contract matches FILE_NON_DIRECTORY_FILE on Windows (callers still fstat).
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            os.close(fd)
            raise OSError(21, f"{name!r} is a directory")  # EISDIR
        return fd

    def stat_at(dirfd: int, name: str) -> os.stat_result:
        """lstat of one name relative to a directory descriptor ('.' is the directory itself)."""
        name = _refuse_component(name, allow_self=True)
        return os.stat(name, dir_fd=dirfd, follow_symlinks=False)

    def open_directory(path: os.PathLike | str) -> int:
        """Open a directory by path, refusing a link as the final component (the historical POSIX call)."""
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def open_file(path: os.PathLike | str, *, write: bool = False, create: bool = False,
                  exclusive: bool = False, mode: int = 0o600) -> int:
        """Open a file by path, refusing a link as the final component (the historical POSIX call)."""
        flags = (os.O_RDWR if write else os.O_RDONLY | os.O_NONBLOCK) | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        if create:
            flags |= os.O_CREAT
            if exclusive:
                flags |= os.O_EXCL
        fd = os.open(path, flags, mode)
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            os.close(fd)
            raise OSError(21, f"{os.fspath(path)!r} is a directory")  # EISDIR
        return fd

    def open_entry_at(dirfd: int, name: str) -> int:
        """Open a regular file or a directory for reading, never a link (the caller inspects fstat)."""
        name = _refuse_component(name)
        return os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=dirfd)

    def scandir_names(dirfd: int):
        """Stream names; close the iterator when stopping before exhaustion."""
        with os.scandir(dirfd) as entries:
            for entry in entries:
                yield entry.name

    def mkdir_at(dirfd: int, name: str, mode: int = 0o700) -> None:
        name = _refuse_component(name)
        os.mkdir(name, mode, dir_fd=dirfd)

    def fsync_directory(dirfd: int, *, tolerate_unwritable: bool = False) -> None:
        """fsync a directory descriptor; ``tolerate_unwritable`` is a Windows-only concession."""
        os.fsync(dirfd)

    def fsync_file(fd: int) -> None:
        """fsync a file descriptor opened for reading or writing."""
        os.fsync(fd)

    def unlink_at(dirfd: int, name: str) -> None:
        name = _refuse_component(name)
        os.unlink(name, dir_fd=dirfd)

    def rmdir_at(dirfd: int, name: str) -> None:
        name = _refuse_component(name)
        os.rmdir(name, dir_fd=dirfd)

    def link_at(dirfd: int, source: str, target: str) -> None:
        """Hard-link ``source`` as ``target`` inside one directory descriptor, never through a link."""
        source = _refuse_component(source)
        target = _refuse_component(target)
        os.link(source, target, src_dir_fd=dirfd, dst_dir_fd=dirfd, follow_symlinks=False)

    def replace_at(dirfd: int, source: str, target: str) -> None:
        """Atomically rename ``source`` over ``target`` inside one directory descriptor."""
        source = _refuse_component(source)
        target = _refuse_component(target)
        os.replace(source, target, src_dir_fd=dirfd, dst_dir_fd=dirfd)

    def descriptor_path(fd: int) -> str | None:
        """Best-effort path of a descriptor for messages only; never for decisions."""
        try:
            return os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            return None

# ------------------------------------------------------------------------- Windows

else:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _FILE_READ_DATA = 0x0001
    _FILE_LIST_DIRECTORY = 0x0001
    _FILE_WRITE_DATA = 0x0002
    _FILE_APPEND_DATA = 0x0004
    _FILE_READ_EA = 0x0008
    _FILE_WRITE_EA = 0x0010
    _FILE_READ_ATTRIBUTES = 0x0080
    _FILE_WRITE_ATTRIBUTES = 0x0100
    _SYNCHRONIZE = 0x00100000
    _READ_CONTROL = 0x00020000
    _FILE_SHARE_ALL = 0x1 | 0x2 | 0x4
    _FILE_OPEN = 0x1
    _FILE_CREATE = 0x2
    _FILE_OPEN_IF = 0x3
    _FILE_DIRECTORY_FILE = 0x1
    _FILE_NON_DIRECTORY_FILE = 0x40
    _FILE_SYNCHRONOUS_IO_NONALERT = 0x20
    _FILE_OPEN_REPARSE_POINT = 0x00200000
    _FILE_OPEN_FOR_BACKUP_INTENT = 0x4000
    _FILE_ATTRIBUTE_NORMAL = 0x80
    _OBJ_CASE_INSENSITIVE = 0x40
    _STATUS_NOT_A_DIRECTORY = 0xC0000103
    _STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA
    _STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
    _STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
    _STATUS_OBJECT_NAME_COLLISION = 0xC0000035
    _STATUS_ACCESS_DENIED = 0xC0000022
    _STATUS_SHARING_VIOLATION = 0xC0000043
    _ERRNO = {
        _STATUS_NOT_A_DIRECTORY: 20,         # ENOTDIR
        _STATUS_FILE_IS_A_DIRECTORY: 21,     # EISDIR
        _STATUS_OBJECT_NAME_NOT_FOUND: 2,    # ENOENT
        _STATUS_OBJECT_PATH_NOT_FOUND: 2,
        _STATUS_OBJECT_NAME_COLLISION: 17,   # EEXIST
        _STATUS_ACCESS_DENIED: 13,           # EACCES
        _STATUS_SHARING_VIOLATION: 13,
    }
    _INVALID_HANDLE = ctypes.c_void_p(-1).value
    _VOLUME_SERIAL_FMT = "\\\\?\\"

    class _UNICODE_STRING(ctypes.Structure):
        _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", wintypes.LPWSTR)]

    class _OBJECT_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(_UNICODE_STRING)), ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", ctypes.c_void_p), ("SecurityQualityOfService", ctypes.c_void_p),
        ]

    class _IO_STATUS_BLOCK(ctypes.Structure):
        _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_void_p)]

    _api_cache: dict = {}

    def _nt():
        if _api_cache:
            return _api_cache["ntdll"], _api_cache["kernel32"]
        try:
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        except OSError as exc:
            raise OSError("secure descriptor-relative opens unavailable") from exc
        ntdll.NtCreateFile.restype = wintypes.ULONG
        ntdll.NtCreateFile.argtypes = [
            ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, ctypes.POINTER(_OBJECT_ATTRIBUTES),
            ctypes.POINTER(_IO_STATUS_BLOCK), ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG,
            wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG,
        ]
        kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        kernel32.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        kernel32.FlushFileBuffers.restype = wintypes.BOOL
        kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        _api_cache.update(ntdll=ntdll, kernel32=kernel32)
        return ntdll, kernel32

    _FILE_CREATED = 2

    def _nt_open(root_handle, name: str, access: int, disposition: int, options: int, *, want_created: bool = False):
        """NtCreateFile of ``name`` relative to ``root_handle`` (or an absolute NT path when None).

        With ``want_created`` returns ``(handle, created)`` from the IO status block.
        """
        ntdll, _kernel32 = _nt()
        encoded = _encoded_native_name(name)
        buffer = ctypes.create_string_buffer(encoded + b"\x00\x00")
        unicode = _UNICODE_STRING(len(encoded), len(encoded) + 2, ctypes.cast(buffer, wintypes.LPWSTR))
        attributes = _OBJECT_ATTRIBUTES(ctypes.sizeof(_OBJECT_ATTRIBUTES), root_handle, ctypes.pointer(unicode),
                                        _OBJ_CASE_INSENSITIVE, None, None)
        handle = wintypes.HANDLE()
        status_block = _IO_STATUS_BLOCK()
        status = ntdll.NtCreateFile(
            ctypes.byref(handle), access | _SYNCHRONIZE, ctypes.byref(attributes), ctypes.byref(status_block),
            None, _FILE_ATTRIBUTE_NORMAL, _FILE_SHARE_ALL, disposition,
            options | _FILE_SYNCHRONOUS_IO_NONALERT | _FILE_OPEN_REPARSE_POINT, None, 0,
        )
        if status != 0:
            raise OSError(_ERRNO.get(status & 0xFFFFFFFF, 5), f"NtCreateFile {name!r} failed: NTSTATUS 0x{status & 0xFFFFFFFF:08X}")
        if want_created:
            return handle.value, (status_block.Information or 0) == _FILE_CREATED
        return handle.value

    def _handle_to_fd(handle: int, write: bool) -> int:
        try:
            return msvcrt.open_osfhandle(handle, (os.O_RDWR if write else os.O_RDONLY) | os.O_BINARY | os.O_NOINHERIT)
        except OSError:
            _nt()[1].CloseHandle(handle)
            raise

    _WRITE_DAC = 0x00040000

    def _make_private_object(fd: int) -> None:
        """Set the trusted-set DACL on the object a descriptor holds (reopened with WRITE_DAC, no path)."""
        from .windows_acl import make_private
        is_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
        handle = _nt_open(msvcrt.get_osfhandle(fd), "", _WRITE_DAC | _READ_CONTROL | _FILE_READ_ATTRIBUTES, _FILE_OPEN,
                          (_FILE_DIRECTORY_FILE | _FILE_OPEN_FOR_BACKUP_INTENT) if is_dir else _FILE_NON_DIRECTORY_FILE)
        temp = _handle_to_fd(handle, False)
        try:
            make_private(fd=temp)
        finally:
            os.close(temp)

    def _reject_reparse(fd: int) -> os.stat_result:
        info = os.fstat(fd)
        if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            os.close(fd)
            raise OSError(40, "reparse point (symbolic link or junction) refused")  # ELOOP
        return info

    def open_root(root: os.PathLike | str) -> int:
        """Directory descriptor for an absolute path, walked component-wise without following reparse points."""
        path = Path(root)
        if not path.is_absolute() or not path.drive or path.drive.startswith("\\\\"):
            raise OSError("root must be an absolute local path with a drive letter")
        drive = path.drive  # e.g. 'C:'
        handle = _nt_open(None, f"\\??\\{drive}\\", _FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES | _READ_CONTROL, _FILE_OPEN,
                          _FILE_DIRECTORY_FILE | _FILE_OPEN_FOR_BACKUP_INTENT)
        fd = _handle_to_fd(handle, False)
        try:
            _reject_reparse(fd)
            for part in path.parts[1:]:
                part = _refuse_component(part)
                next_fd = open_directory_at(fd, part)
                os.close(fd)
                fd = next_fd
            return fd
        except BaseException:
            os.close(fd)
            raise

    def open_directory_at(dirfd: int, name: str) -> int:
        """Open a directory name relative to a descriptor; '.' reopens the directory itself."""
        name = _refuse_component(name, allow_self=True)
        handle = _nt_open(msvcrt.get_osfhandle(dirfd), "" if name == "." else name,
                          _FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES | _READ_CONTROL, _FILE_OPEN,
                          _FILE_DIRECTORY_FILE | _FILE_OPEN_FOR_BACKUP_INTENT)
        fd = _handle_to_fd(handle, False)
        _reject_reparse(fd)
        return fd

    def open_file_at(dirfd: int, name: str, *, write: bool = False, create: bool = False,
                     exclusive: bool = False, mode: int = 0o600) -> int:
        name = _refuse_component(name)
        access = _FILE_READ_DATA | _FILE_READ_ATTRIBUTES | _FILE_READ_EA | _READ_CONTROL
        if write:
            access |= _FILE_WRITE_DATA | _FILE_APPEND_DATA | _FILE_WRITE_ATTRIBUTES | _FILE_WRITE_EA
        disposition = (_FILE_CREATE if exclusive else _FILE_OPEN_IF) if create else _FILE_OPEN
        handle, created = _nt_open(msvcrt.get_osfhandle(dirfd), name, access, disposition, _FILE_NON_DIRECTORY_FILE, want_created=True)
        fd = _handle_to_fd(handle, write)
        _reject_reparse(fd)
        if created and not mode & 0o077:
            # A file created owner-only on POSIX is owner-only here through its DACL.
            try:
                _make_private_object(fd)
            except BaseException:
                os.close(fd)
                raise
        return fd

    def _with_link_mode(info: os.stat_result) -> os.stat_result:
        if not info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            return info
        mode = (info.st_mode & ~stat.S_IFMT(info.st_mode)) | stat.S_IFLNK
        return os.stat_result(
            (mode, info.st_ino, info.st_dev, info.st_nlink, info.st_uid, info.st_gid, info.st_size,
             info.st_atime, info.st_mtime, info.st_ctime),
            {"st_atime_ns": info.st_atime_ns, "st_mtime_ns": info.st_mtime_ns, "st_ctime_ns": info.st_ctime_ns,
             "st_file_attributes": info.st_file_attributes},
        )

    def stat_at(dirfd: int, name: str) -> os.stat_result:
        """lstat of one name relative to a directory descriptor (reparse points report S_IFLNK; '.' is the directory)."""
        name = _refuse_component(name, allow_self=True)
        handle = _nt_open(msvcrt.get_osfhandle(dirfd), "" if name == "." else name,
                          _FILE_READ_ATTRIBUTES | _READ_CONTROL, _FILE_OPEN, _FILE_OPEN_FOR_BACKUP_INTENT)
        fd = _handle_to_fd(handle, False)
        try:
            return _with_link_mode(os.fstat(fd))
        finally:
            os.close(fd)

    def open_directory(path: os.PathLike | str) -> int:
        """Open a directory by path; on Windows the whole path is walked without following links."""
        return open_root(path)

    def open_file(path: os.PathLike | str, *, write: bool = False, create: bool = False,
                  exclusive: bool = False, mode: int = 0o600) -> int:
        """Open a file by path; the directory is walked without following links, then the name opened relative."""
        target = Path(os.path.abspath(path))
        parent = open_root(target.parent)
        try:
            return open_file_at(parent, target.name, write=write, create=create, exclusive=exclusive, mode=mode)
        finally:
            os.close(parent)

    def open_entry_at(dirfd: int, name: str) -> int:
        """Open a regular file or a directory for reading, never a reparse point."""
        name = _refuse_component(name)
        handle = _nt_open(msvcrt.get_osfhandle(dirfd), name, _FILE_READ_DATA | _FILE_READ_ATTRIBUTES | _READ_CONTROL,
                          _FILE_OPEN, _FILE_OPEN_FOR_BACKUP_INTENT)
        fd = _handle_to_fd(handle, False)
        _reject_reparse(fd)
        return fd

    def descriptor_path(fd: int) -> str | None:
        _ntdll, kernel32 = _nt()
        buffer = ctypes.create_unicode_buffer(32768)
        length = kernel32.GetFinalPathNameByHandleW(msvcrt.get_osfhandle(fd), buffer, len(buffer), 0)
        if not length or length >= len(buffer):
            return None
        value = buffer.value
        # Conventional form for messages and comparisons: drop the extended-length prefix.
        if value.startswith("\\\\?\\UNC\\"):
            return "\\\\" + value[8:]
        if value.startswith("\\\\?\\"):
            return value[4:]
        return value

    def scandir_names(dirfd: int):
        """Stream names; close early, and open children relative to the descriptor."""
        path = descriptor_path(dirfd)
        if path is None:
            raise OSError("directory path unavailable for listing")
        with os.scandir(path) as entries:
            for entry in entries:
                yield entry.name

    def mkdir_at(dirfd: int, name: str, mode: int = 0o700) -> None:
        """Create a directory relative to a descriptor; an owner-only mode becomes the trusted-set DACL."""
        name = _refuse_component(name)
        handle = _nt_open(msvcrt.get_osfhandle(dirfd), name, _FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES | _READ_CONTROL, _FILE_CREATE,
                          _FILE_DIRECTORY_FILE | _FILE_OPEN_FOR_BACKUP_INTENT)
        fd = _handle_to_fd(handle, False)
        try:
            if not mode & 0o077:
                _make_private_object(fd)
        finally:
            os.close(fd)

    _DELETE = 0x00010000
    _FILE_DELETE_ON_CLOSE = 0x00001000

    def unlink_at(dirfd: int, name: str) -> None:
        """Delete one name relative to a directory descriptor (never through a reparse point)."""
        name = _refuse_component(name)
        handle = _nt_open(msvcrt.get_osfhandle(dirfd), name, _DELETE | _FILE_READ_ATTRIBUTES, _FILE_OPEN,
                          _FILE_NON_DIRECTORY_FILE | _FILE_DELETE_ON_CLOSE)
        _nt()[1].CloseHandle(handle)

    def rmdir_at(dirfd: int, name: str) -> None:
        """Delete one empty directory relative to a directory descriptor."""
        name = _refuse_component(name)
        handle = _nt_open(msvcrt.get_osfhandle(dirfd), name, _DELETE | _FILE_READ_ATTRIBUTES, _FILE_OPEN,
                          _FILE_DIRECTORY_FILE | _FILE_DELETE_ON_CLOSE | _FILE_OPEN_FOR_BACKUP_INTENT)
        _nt()[1].CloseHandle(handle)

    def link_at(dirfd: int, source: str, target: str) -> None:
        """Hard-link ``source`` as ``target`` inside one directory descriptor.

        CreateHardLink takes paths; both are formed from the descriptor's final path and
        the source is verified first through a relative no-follow open, so a reparse
        point is never linked. The target name is created, never replaced (EEXIST).
        """
        source = _refuse_component(source)
        target = _refuse_component(target)
        probe = open_file_at(dirfd, source)
        os.close(probe)
        base = descriptor_path(dirfd)
        if base is None:
            raise OSError("directory path unavailable for linking")
        os.link(os.path.join(base, source), os.path.join(base, target))

    def replace_at(dirfd: int, source: str, target: str) -> None:
        """Rename ``source`` over ``target`` inside one directory descriptor (POSIX replace semantics).

        The source is opened relative to the descriptor with DELETE access and renamed
        with NtSetInformationFile(FileRenameInformationEx): FILE_RENAME_REPLACE_IF_EXISTS
        and FILE_RENAME_POSIX_SEMANTICS, the target name relative to the same directory
        handle (RootDirectory); no path is consulted. Older kernels without the Ex class
        get FileRenameInformation with ReplaceIfExists.
        """
        source = _refuse_component(source)
        target = _refuse_component(target)
        ntdll, kernel32 = _nt()
        ntdll.NtSetInformationFile.restype = wintypes.ULONG
        ntdll.NtSetInformationFile.argtypes = [wintypes.HANDLE, ctypes.POINTER(_IO_STATUS_BLOCK), ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG]
        directory = msvcrt.get_osfhandle(dirfd)
        handle = _nt_open(directory, source, _DELETE | _FILE_READ_ATTRIBUTES, _FILE_OPEN, _FILE_NON_DIRECTORY_FILE)
        try:
            name = _encoded_native_name(target)
            length = len(name)
            pointer = ctypes.sizeof(wintypes.HANDLE)
            # FILE_RENAME_INFORMATION(_EX): union {BOOLEAN ReplaceIfExists; ULONG Flags}
            # padded to pointer size; HANDLE RootDirectory; ULONG FileNameLength; WCHAR FileName[].
            name_offset = pointer + pointer + ctypes.sizeof(wintypes.ULONG)
            size = name_offset + length
            buffer = ctypes.create_string_buffer(size + 2)
            ctypes.memmove(ctypes.addressof(buffer) + pointer, ctypes.byref(wintypes.HANDLE(directory)), pointer)
            ctypes.memmove(ctypes.addressof(buffer) + pointer + pointer, ctypes.byref(wintypes.ULONG(length)), ctypes.sizeof(wintypes.ULONG))
            ctypes.memmove(ctypes.addressof(buffer) + name_offset, name, length)
            status_block = _IO_STATUS_BLOCK()
            ctypes.memmove(buffer, ctypes.byref(wintypes.ULONG(0x1 | 0x2)), ctypes.sizeof(wintypes.ULONG))
            status = ntdll.NtSetInformationFile(handle, ctypes.byref(status_block), buffer, size, 65)  # FileRenameInformationEx
            if status & 0xFFFFFFFF in (0xC0000003, 0xC00000BB):  # STATUS_INVALID_INFO_CLASS, STATUS_NOT_SUPPORTED
                ctypes.memset(buffer, 0, pointer)
                ctypes.memmove(buffer, ctypes.byref(ctypes.c_ubyte(1)), 1)  # ReplaceIfExists
                status = ntdll.NtSetInformationFile(handle, ctypes.byref(status_block), buffer, size, 10)  # FileRenameInformation
            if status != 0:
                raise OSError(_ERRNO.get(status & 0xFFFFFFFF, 5), f"rename {source!r} over {target!r} failed: NTSTATUS 0x{status & 0xFFFFFFFF:08X}")
        finally:
            kernel32.CloseHandle(handle)

    def fsync_file(fd: int) -> None:
        """FlushFileBuffers on the same file object; a read-only handle is reopened relative to itself.

        os.fsync on Windows needs a handle with write access; an empty relative name
        reopens exactly the object the descriptor holds (no path is consulted).
        """
        _ntdll, kernel32 = _nt()
        handle = _nt_open(msvcrt.get_osfhandle(fd), "", _FILE_WRITE_DATA | _FILE_READ_ATTRIBUTES, _FILE_OPEN,
                          _FILE_NON_DIRECTORY_FILE)
        try:
            if not kernel32.FlushFileBuffers(handle):
                raise OSError(ctypes.get_last_error(), "FlushFileBuffers failed for a file handle")
        finally:
            kernel32.CloseHandle(handle)

    def fsync_directory(dirfd: int, *, tolerate_unwritable: bool = False) -> None:
        """No directory flush on Windows, by design.

        FlushFileBuffers on a directory handle flushes the whole NTFS volume: measured
        at seconds per call under parallel load, and the ancestor chains the durable
        writers flush turned test suites into minutes of stalls. NTFS journals
        directory metadata itself; file contents are flushed through ``fsync_file``.
        This is the conditional Windows guarantee ``filesystem.fsync_directory``
        documents: file data durable, directory names journaled, not fsynced.
        """
        os.fstat(dirfd)  # the descriptor must still be a valid directory handle


# ------------------------------------------------------------ path-level helpers

_REPLACE_WAIT_SECONDS = 2.0


def replace_path(source: os.PathLike | str, target: os.PathLike | str) -> None:
    """``os.replace`` that tolerates Windows readers.

    POSIX: exactly ``os.replace``. Windows: ``MoveFileEx`` refuses to replace a file
    that another handle holds open (ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION);
    the rename is then redone relative to the directory handle with POSIX semantics
    (``replace_at``), which succeeds when the open handles share delete access (every
    ``safe_open`` reader does), and retried for a bounded window for handles that do
    not (another program holding the file). After the window the last error is raised.
    """
    if not _WINDOWS:
        os.replace(source, target)
        return
    import time
    source = os.fspath(source)
    target = os.fspath(target)
    deadline = time.monotonic() + _REPLACE_WAIT_SECONDS
    while True:
        try:
            os.replace(source, target)
            return
        except PermissionError as exc:
            if getattr(exc, "winerror", None) not in (5, 32):
                raise
            last: OSError = exc
        source_dir, source_name = os.path.split(os.path.abspath(source))
        target_dir, target_name = os.path.split(os.path.abspath(target))
        if os.path.normcase(source_dir) == os.path.normcase(target_dir):
            try:
                dirfd = open_root(source_dir)
            except OSError:
                dirfd = None
            if dirfd is not None:
                try:
                    replace_at(dirfd, source_name, target_name)
                    return
                except OSError as exc:
                    last = exc
                finally:
                    os.close(dirfd)
        if time.monotonic() >= deadline:
            raise last
        time.sleep(0.01)


def read_text_shared(path: os.PathLike | str, *, encoding: str = "utf-8") -> str:
    """Read a text file that a concurrent ``replace_path`` may replace.

    POSIX: ``Path.read_text``. Windows: a delete-sharing open (``open_file``), so the
    writer's POSIX-semantics rename succeeds while this reader still sees the old bytes.
    """
    if not _WINDOWS:
        return Path(path).read_text(encoding=encoding)
    fd = open_file(path)
    with os.fdopen(fd, "r", encoding=encoding) as handle:
        return handle.read()


_DELETED_MARKER = "\\$extend\\$deleted\\"


def resolve_path(path: os.PathLike | str) -> Path:
    """``Path.resolve()`` that survives a concurrent POSIX-semantics replacement on Windows.

    Windows ``realpath`` opens the name and asks the handle for its final name. When
    the file at that name is replaced in between (``replace_path`` while a reader
    holds the old file), the handle belongs to the old file, which NTFS now lists
    under ``\\$Extend\\$Deleted``; no live name looks like that, so resolve again
    until the live name comes back (bounded). POSIX: ``Path.resolve()``.
    """
    target = Path(path)
    if not _WINDOWS:
        return target.resolve()
    import time
    resolved = target.resolve()
    for _attempt in range(50):
        if _DELETED_MARKER not in str(resolved).lower():
            return resolved
        time.sleep(0.005)
        resolved = target.resolve()
    raise OSError(f"{target} resolved to a file deleted while open; retry the operation")
