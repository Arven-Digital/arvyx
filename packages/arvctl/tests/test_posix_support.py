"""Darwin equivalents for the POSIX calls the control plane requires."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from arvyx_control.posix_support import (
    cloexec_pipe, descend_directory, exited_unreaped, fd_directory,
    owned_command_supported, system_directory_symlink,
)


class PosixSupportTests(unittest.TestCase):
    def test_pipe_is_not_inherited(self):
        read, write = cloexec_pipe()
        try:
            self.assertFalse(os.get_inheritable(read))
            self.assertFalse(os.get_inheritable(write))
        finally:
            os.close(read)
            os.close(write)

    def test_owned_command_supervision_is_available(self):
        self.assertTrue(owned_command_supported())

    def test_exit_is_observed_without_reaping(self):
        import time
        process = subprocess.Popen(['/bin/sh', '-c', 'exit 0'])
        try:
            for _ in range(50):
                if exited_unreaped(process.pid):
                    break
                time.sleep(0.02)
            else:
                self.fail('exit was not observed')
            if hasattr(os, 'waitid'):
                self.assertIsNone(process.poll())
        finally:
            process.wait(timeout=2)

    def test_system_symlink_is_only_the_os_layout(self):
        if not os.path.islink('/var'):
            self.skipTest('this host has no /var symlink')
        self.assertTrue(system_directory_symlink('/var'))
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / 'alias'
            link.symlink_to(tmp)
            self.assertFalse(system_directory_symlink(link))

    def test_directory_walk_crosses_var(self):
        if not system_directory_symlink('/var'):
            self.skipTest('this host has no /var symlink')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            fd = descend_directory(fd, 'var', '/var')
            self.assertTrue(os.path.samestat(os.fstat(fd), os.stat('/private/var')))
        finally:
            os.close(fd)

    def test_fd_directory_falls_back_when_proc_is_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                pinned = fd_directory(fd, tmp)
                self.assertTrue(os.path.isdir(pinned))
            finally:
                os.close(fd)


if __name__ == '__main__':
    unittest.main()
