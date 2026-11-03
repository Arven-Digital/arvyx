"""Raw descriptors carry bytes unchanged on Windows once the package is imported.

Without ``_set_fmode(_O_BINARY)`` the C run-time strips carriage returns on
``os.read`` and inserts them on ``os.write`` for descriptors opened without
``O_BINARY``; the package sets the default at import (see ``arvyx_control``).
"""
import os
import subprocess
import sys
import tempfile
import unittest

import arvyx_control  # noqa: F401  (import sets the default on Windows)


class CrtBinaryModeTests(unittest.TestCase):
    def test_raw_descriptors_keep_carriage_returns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "crlf.txt")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, b"a\r\nb\n")
            finally:
                os.close(fd)
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), b"a\r\nb\n")
            fd = os.open(path, os.O_RDONLY)
            try:
                self.assertEqual(os.read(fd, 100), b"a\r\nb\n")
            finally:
                os.close(fd)

    @unittest.skipUnless(os.name == "nt", "the C run-time default is a Windows fact")
    def test_default_is_text_mode_without_the_package(self):
        # Negative control in a fresh interpreter that never imports the package.
        probe = (
            "import os, tempfile\n"
            "p = os.path.join(tempfile.mkdtemp(), 'f')\n"
            "fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.write(fd, b'x\\n'); os.close(fd)\n"
            "print(open(p, 'rb').read() == b'x\\r\\n')\n"
        )
        result = subprocess.run([sys.executable, "-I", "-c", probe], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), "True")


if __name__ == "__main__":
    unittest.main()
