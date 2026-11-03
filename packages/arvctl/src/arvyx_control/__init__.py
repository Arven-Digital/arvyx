"""Arvyx control-plane package."""

import os as _os

__all__ = ["__version__"]

__version__ = "0.1.0a0"


def _crt_binary_descriptors() -> None:
    """Windows: make raw descriptors binary by default.

    The C run-time opens descriptors from ``os.open`` in *text* mode unless
    ``O_BINARY`` is given: ``os.read`` drops every carriage return and ``os.write``
    inserts one before each line feed, which corrupts the bytes this package reads
    and writes through descriptors (event logs, memory documents, receipts).
    ``_set_fmode(_O_BINARY)`` changes the run-time's default translation mode for
    this process; Python's own ``open()`` always passes ``O_BINARY`` and is not
    affected. ``safe_open`` descriptors already carry ``O_BINARY`` explicitly.
    """
    if _os.name != "nt":
        return
    import ctypes
    try:
        ucrt = ctypes.CDLL("ucrtbase")
        ucrt._set_fmode.argtypes = [ctypes.c_int]
        ucrt._set_fmode(0x8000)  # _O_BINARY
    except (OSError, AttributeError) as exc:  # pragma: no cover - no UCRT means no Windows build of Python
        raise RuntimeError("cannot set the C run-time default file mode to binary on Windows") from exc


_crt_binary_descriptors()
