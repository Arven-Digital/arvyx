"""Windows analogue of the POSIX private-path rules (owner plus mode 0700).

POSIX code in this package decides "private" from ``st_uid in (0, getuid())`` and
``st_mode & 0o077 == 0``, and "not writable by others" for ancestors from
``st_mode & 0o022 == 0``. Windows has neither field: ``st_uid`` is always 0 and
``st_mode`` only mirrors the read-only attribute. The equivalent facts live in the
NTFS security descriptor, read here through ``advapi32`` with ``ctypes`` only.

The trusted set is the current user's SID, ``SYSTEM`` (S-1-5-18) and
``Administrators`` (S-1-5-32-544), the Windows counterparts of the owner and root.

- ``private_path_problem(path)``: ``None`` when the path is not a reparse point, is
  owned by a trusted SID, and its DACL allows access to trusted SIDs only
  (``ACCESS_DENIED`` entries never widen access and are ignored). A missing DACL
  means "everyone", so it is a problem. Otherwise a short reason naming the SID.
- ``others_writable_problem(path)``: the ancestor rule; a problem when any
  ``ACCESS_ALLOWED`` entry for an untrusted SID carries a write-class right
  (add file, add subdirectory, delete, delete child, write DAC, write owner,
  generic write or generic all). ``C:\\`` fails it, exactly as ``/tmp`` fails
  the POSIX ancestor rule, because Authenticated Users may create folders there.
- ``make_private(path)``: replaces the DACL with a protected one (no inheritance
  from the parent) granting full control to the trusted set, the Windows
  ``chmod 700``; verified by reading it back.

Importable on every platform; every entry point refuses with ``OSError`` when the
platform is not Windows, so callers branch on ``os.name`` and never fall through
silently.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
# Entries for these well-known SIDs apply to whoever owns the object (CREATOR OWNER is
# the inheritable template, OWNER RIGHTS the explicit form); once the owner is trusted
# they grant nothing to anyone else, so they are read as the owner.
_OWNER_ALIASES = frozenset({"S-1-3-0", "S-1-3-4"})
_WELL_KNOWN = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-545": "Users",
    "S-1-5-32-544": "Administrators",
    "S-1-5-18": "SYSTEM",
    "S-1-5-7": "Anonymous",
    "S-1-5-32-546": "Guests",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-3-4": "OWNER RIGHTS",
}

# Write-class rights for the ancestor rule (FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
# FILE_DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE, GENERIC_ALL).
_WRITE_RIGHTS = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000
_FILE_ALL_ACCESS = 0x1F01FF

_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x1
_DACL_SECURITY_INFORMATION = 0x4
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_ACCESS_ALLOWED_ACE_TYPE = 0
_ACCESS_DENIED_ACE_TYPE = 1
_OBJECT_INHERIT_ACE = 0x1
_CONTAINER_INHERIT_ACE = 0x2
_TOKEN_QUERY = 0x8
_TOKEN_USER = 1
_TOKEN_OWNER = 4
_ACL_REVISION = 2
_ACL_SIZE_INFORMATION = 2


def _require_windows() -> None:
    if os.name != "nt":
        raise OSError("Windows ACL rules are only meaningful on Windows")


def _api():
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class ACE_HEADER(ctypes.Structure):
        _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", wintypes.WORD)]

    class ACCESS_ALLOWED_ACE(ctypes.Structure):
        _fields_ = [("Header", ACE_HEADER), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]

    class ACL_SIZE_INFORMATION(ctypes.Structure):
        _fields_ = [("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD), ("AclBytesFree", wintypes.DWORD)]

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class TOKEN_USER(ctypes.Structure):
        _fields_ = [("User", SID_AND_ATTRIBUTES)]

    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.SetSecurityInfo.restype = wintypes.DWORD
    advapi32.SetSecurityInfo.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.InitializeAcl.restype = wintypes.BOOL
    advapi32.InitializeAcl.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    advapi32.AddAccessAllowedAceEx.restype = wintypes.BOOL
    advapi32.AddAccessAllowedAceEx.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    return ctypes, wintypes, advapi32, kernel32, ACE_HEADER, ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, TOKEN_USER


def _sid_string(ctypes, advapi32, kernel32, sid) -> str:
    out = ctypes.c_wchar_p()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(out)):
        raise OSError(ctypes.get_last_error(), "ConvertSidToStringSid failed")
    try:
        return out.value
    finally:
        kernel32.LocalFree(out)


def current_user_sid() -> str:
    """String SID of the user the current process runs as (from the process token)."""
    _require_windows()
    ctypes, wintypes, advapi32, kernel32, *_rest, TOKEN_USER = _api()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, _TOKEN_USER, buffer, needed.value, ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        user = ctypes.cast(buffer, ctypes.POINTER(TOKEN_USER)).contents
        return _sid_string(ctypes, advapi32, kernel32, user.User.Sid)
    finally:
        kernel32.CloseHandle(token)


def current_owner_sid() -> str:
    """String SID the current token assigns as owner of the objects it creates (``TokenOwner``).

    For an elevated administrator Windows sets this to ``BUILTIN\\Administrators``, so
    files and directories the process itself creates are not owned by the user SID.
    """
    _require_windows()
    ctypes, wintypes, advapi32, kernel32, *_rest = _api()

    class TOKEN_OWNER(ctypes.Structure):
        _fields_ = [("Owner", ctypes.c_void_p)]

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, _TOKEN_OWNER, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, _TOKEN_OWNER, buffer, needed.value, ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        owner = ctypes.cast(buffer, ctypes.POINTER(TOKEN_OWNER)).contents
        return _sid_string(ctypes, advapi32, kernel32, owner.Owner)
    finally:
        kernel32.CloseHandle(token)


def current_owner_sids() -> frozenset[str]:
    """SIDs that mean "owned by the current user": the user SID and the token's default owner."""
    return frozenset({current_user_sid(), current_owner_sid()})


def trusted_sids() -> frozenset[str]:
    """The current user, SYSTEM and Administrators: owner and root, in Windows terms."""
    return frozenset({current_user_sid(), SYSTEM_SID, ADMINISTRATORS_SID})


def describe_sid(sid: str) -> str:
    name = _WELL_KNOWN.get(sid)
    return f"{sid} ({name})" if name else sid


def security_entries(path: os.PathLike | str | None = None, *, fd: int | None = None) -> tuple[str, list[tuple[str, int, int, int]] | None]:
    """Owner SID and the DACL as ``(sid, ace_type, ace_flags, mask)`` rows; ``None`` for a NULL DACL.

    With ``fd`` the descriptor's own handle is queried (no path is consulted, so a
    caller that walked descriptor-relative keeps that guarantee); otherwise the path.
    """
    _require_windows()
    ctypes, wintypes, advapi32, kernel32, ACE_HEADER, ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, _ = _api()
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    if fd is not None:
        import msvcrt
        status = advapi32.GetSecurityInfo(
            msvcrt.get_osfhandle(fd), _SE_FILE_OBJECT, _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor),
        )
        label = f"descriptor {fd}"
    elif path is not None:
        status = advapi32.GetNamedSecurityInfoW(
            os.fspath(path), _SE_FILE_OBJECT, _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor),
        )
        label = repr(os.fspath(path))
    else:
        raise OSError("security_entries needs a path or an open descriptor")
    if status != 0:
        raise OSError(status, f"GetSecurityInfo failed for {label}")
    try:
        owner_sid = _sid_string(ctypes, advapi32, kernel32, owner)
        if not dacl:
            return owner_sid, None
        info = ACL_SIZE_INFORMATION()
        if not advapi32.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), _ACL_SIZE_INFORMATION):
            raise OSError(ctypes.get_last_error(), "GetAclInformation failed")
        rows = []
        for index in range(info.AceCount):
            ace = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                raise OSError(ctypes.get_last_error(), "GetAce failed")
            header = ctypes.cast(ace, ctypes.POINTER(ACE_HEADER)).contents
            if header.AceType in (_ACCESS_ALLOWED_ACE_TYPE, _ACCESS_DENIED_ACE_TYPE):
                body = ctypes.cast(ace, ctypes.POINTER(ACCESS_ALLOWED_ACE)).contents
                sid = ace.value + ACCESS_ALLOWED_ACE.SidStart.offset
                rows.append((_sid_string(ctypes, advapi32, kernel32, sid), header.AceType, header.AceFlags, body.Mask))
            else:
                # Object or callback ACE types do not occur on file DACLs; refuse to guess.
                rows.append(("?", header.AceType, header.AceFlags, 0))
        return owner_sid, rows
    finally:
        kernel32.LocalFree(descriptor)


def _reparse_problem(path: Path) -> str | None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        return f"cannot stat: {exc.strerror or exc}"
    if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        return "reparse point (symbolic link or junction)"
    return None


def private_path_problem(path: os.PathLike | str | None = None, *, fd: int | None = None,
                         trusted: frozenset[str] | None = None) -> str | None:
    """Why the object is not private, or ``None``; the Windows ``uid`` plus ``0o077`` rule.

    A path is first checked not to be a reparse point; an ``fd`` was opened by the
    caller without following links, so only its security descriptor is read.
    """
    _require_windows()
    if fd is None:
        target = Path(path)
        problem = _reparse_problem(target)
        if problem:
            return problem
    trusted = trusted_sids() if trusted is None else trusted
    owner, rows = security_entries(path, fd=fd)
    if owner not in trusted:
        return f"owned by {describe_sid(owner)}"
    if rows is None:
        return "no DACL (everyone has access)"
    for sid, ace_type, _flags, _mask in rows:
        if ace_type == _ACCESS_DENIED_ACE_TYPE:
            continue
        if ace_type != _ACCESS_ALLOWED_ACE_TYPE:
            return f"unsupported ACE type {ace_type}"
        if sid not in trusted and sid not in _OWNER_ALIASES:
            return f"access allowed to {describe_sid(sid)}"
    return None


def others_writable_problem(path: os.PathLike | str | None = None, *, fd: int | None = None,
                            trusted: frozenset[str] | None = None) -> str | None:
    """Why untrusted principals may write into the object, or ``None``; the ancestor (``0o022``) rule."""
    _require_windows()
    if fd is None:
        target = Path(path)
        problem = _reparse_problem(target)
        if problem:
            return problem
    trusted = trusted_sids() if trusted is None else trusted
    owner, rows = security_entries(path, fd=fd)
    if rows is None:
        return "no DACL (everyone has access)"
    if owner not in trusted:
        return f"owned by {describe_sid(owner)}"
    for sid, ace_type, _flags, mask in rows:
        if ace_type == _ACCESS_ALLOWED_ACE_TYPE and sid not in trusted and sid not in _OWNER_ALIASES and mask & _WRITE_RIGHTS:
            return f"writable by {describe_sid(sid)}"
        if ace_type not in (_ACCESS_ALLOWED_ACE_TYPE, _ACCESS_DENIED_ACE_TYPE):
            return f"unsupported ACE type {ace_type}"
    return None


def make_private(path: os.PathLike | str | None = None, *, fd: int | None = None) -> None:
    """Give the object a protected DACL for the trusted set only (``chmod 700``), then verify it."""
    _require_windows()
    ctypes, wintypes, advapi32, kernel32, *_rest = _api()
    if fd is None:
        target = Path(path)
        problem = _reparse_problem(target)
        if problem:
            raise OSError(f"refusing to change the ACL of {os.fspath(target)!r}: {problem}")
        is_dir = target.is_dir()
        label = repr(os.fspath(target))
    else:
        is_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
        label = f"descriptor {fd}"
    inherit = (_OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE) if is_dir else 0
    sids = []
    try:
        for text in sorted(trusted_sids()):
            sid = ctypes.c_void_p()
            if not advapi32.ConvertStringSidToSidW(text, ctypes.byref(sid)):
                raise OSError(ctypes.get_last_error(), f"ConvertStringSidToSid failed for {text}")
            sids.append(sid)
        size = 8 + sum(12 + advapi32.GetLengthSid(sid) for sid in sids)
        acl = ctypes.create_string_buffer(size)
        if not advapi32.InitializeAcl(acl, size, _ACL_REVISION):
            raise OSError(ctypes.get_last_error(), "InitializeAcl failed")
        for sid in sids:
            if not advapi32.AddAccessAllowedAceEx(acl, _ACL_REVISION, inherit, _FILE_ALL_ACCESS, sid):
                raise OSError(ctypes.get_last_error(), "AddAccessAllowedAceEx failed")
        if fd is None:
            status = advapi32.SetNamedSecurityInfoW(
                os.fspath(target), _SE_FILE_OBJECT,
                _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
                None, None, acl, None,
            )
        else:
            # NtSetSecurityObject on the handle: advapi32's SetSecurityInfo re-derives
            # the path and walks inheritance (about 250 ms per call); the object a
            # descriptor holds here was just created, so the DACL is set directly.
            # Existing children of an older directory keep their ACLs (path-based
            # make_private propagates); the launcher's prefix uses the path form.
            import msvcrt
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
            ntdll.NtSetSecurityObject.restype = wintypes.ULONG
            ntdll.NtSetSecurityObject.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]
            advapi32.InitializeSecurityDescriptor.argtypes = [ctypes.c_void_p, wintypes.DWORD]
            advapi32.SetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, wintypes.BOOL, ctypes.c_void_p, wintypes.BOOL]
            advapi32.SetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, wintypes.WORD, wintypes.WORD]
            descriptor = ctypes.create_string_buffer(64)  # SECURITY_DESCRIPTOR (absolute) is 40 bytes on x64
            if not advapi32.InitializeSecurityDescriptor(descriptor, 1):
                raise OSError(ctypes.get_last_error(), "InitializeSecurityDescriptor failed")
            if not advapi32.SetSecurityDescriptorDacl(descriptor, True, acl, False):
                raise OSError(ctypes.get_last_error(), "SetSecurityDescriptorDacl failed")
            if not advapi32.SetSecurityDescriptorControl(descriptor, 0x1000, 0x1000):  # SE_DACL_PROTECTED
                raise OSError(ctypes.get_last_error(), "SetSecurityDescriptorControl failed")
            status = ntdll.NtSetSecurityObject(
                msvcrt.get_osfhandle(fd), _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION, descriptor,
            )
        if status != 0:
            raise OSError(status, f"SetSecurityInfo failed for {label}")
    finally:
        for sid in sids:
            kernel32.LocalFree(sid)
    problem = private_path_problem(path, fd=fd)
    if problem:
        raise OSError(f"{label} is still not private after setting its ACL: {problem}")
