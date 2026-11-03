"""Directory-name budgets must apply before the directory is materialized."""
import ast
import contextlib
import os
from pathlib import Path
from types import SimpleNamespace
import unittest

from arvyx_control import safe_open


def platform_scanner(windows, scandir):
    # Execute the actual platform definition without importing Windows DLLs on POSIX.
    tree = ast.parse(Path(safe_open.__file__).read_text())
    branch = next(node for node in tree.body if isinstance(node, ast.If)
                  and ast.unparse(node.test) == 'not _WINDOWS')
    definition = next(node for node in (branch.orelse if windows else branch.body)
                      if isinstance(node, ast.FunctionDef) and node.name == 'scandir_names')
    namespace = {'os': SimpleNamespace(scandir=scandir,
                                      listdir=lambda target: [entry.name for entry in scandir(target)]),
                 'descriptor_path': lambda fd: 'held-directory'}
    exec(compile(ast.Module(body=[definition], type_ignores=[]), '<platform scanner>', 'exec'), namespace)
    return namespace['scandir_names']


class Entries:
    def __init__(self, fail=False):
        self.reads = 0
        self.closed = False
        self.fail = fail

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def __iter__(self):
        return self

    def __next__(self):
        self.reads += 1
        if self.fail:
            raise OSError('enumeration failed')
        if self.reads > 4:
            raise AssertionError('enumerated beyond caller budget')
        return SimpleNamespace(name=str(self.reads))


class ScandirStreamingTests(unittest.TestCase):
    def test_budget_stops_platform_enumeration_and_close_releases_scan(self):
        for windows in (False, True):
            with self.subTest(windows=windows):
                entries = Entries()
                scan = platform_scanner(windows, lambda target: entries)
                names = scan(123)
                self.assertEqual(entries.reads, 0)
                with contextlib.closing(names):
                    for count, name in enumerate(names):
                        if count == 2:
                            break
                self.assertEqual(entries.reads, 3)
                self.assertTrue(entries.closed)

    def test_platform_enumeration_error_closes_scan(self):
        for windows in (False, True):
            with self.subTest(windows=windows):
                entries = Entries(fail=True)
                scan = platform_scanner(windows, lambda target: entries)
                with self.assertRaisesRegex(OSError, 'enumeration failed'):
                    next(scan(123))
                self.assertTrue(entries.closed)

    @unittest.skipIf(os.name == 'nt', 'POSIX descriptor lifetime check')
    def test_native_iterator_preserves_sorted_consumers_and_directory_fd(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'b').touch()
            Path(directory, 'a').touch()
            fd = safe_open.open_root(directory)
            try:
                self.assertEqual(sorted(safe_open.scandir_names(fd)), ['a', 'b'])
                with contextlib.closing(safe_open.scandir_names(fd)) as names:
                    self.assertIn(next(names), ('a', 'b'))
                os.fstat(fd)
            finally:
                os.close(fd)


if __name__ == '__main__':
    unittest.main()
