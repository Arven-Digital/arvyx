"""Descriptor-relative no-follow opens: identical contract on POSIX and Windows.

Every test uses a fresh temporary tree. Links are symbolic links on POSIX and
junctions on Windows (symbolic links there need a privilege); both are reparse
points the backend must refuse to traverse and must report as S_IFLNK.
"""
import errno
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest

from unittest import mock

from arvyx_control import safe_open


class NativeNameTests(unittest.TestCase):
    def test_encoded_name_counts_utf16_bytes(self):
        for name in ("", "ascii", "caf\u00e9", "a\U0001f680z", "\ud800"):
            with self.subTest(name=repr(name)):
                self.assertEqual(safe_open._encoded_native_name(name),
                                 name.encode("utf-16-le", errors="surrogatepass"))

    def test_encoded_name_bounds_include_the_terminator(self):
        for name in ("a" * 32766, "\U0001f680" * 16383):
            self.assertEqual(len(safe_open._encoded_native_name(name)), 65532)
        for name in ("a" * 32767, "\U0001f680" * 16383 + "a"):
            with self.assertRaises(OSError):
                safe_open._encoded_native_name(name)

    def test_windows_components_reject_stream_and_drive_syntax(self):
        with mock.patch.object(safe_open, "_WINDOWS", True):
            for name in ("file:stream", "file::$DATA", ":stream", "C:"):
                with self.subTest(name=name), self.assertRaises(OSError):
                    safe_open._refuse_component(name)
            safe_open._refuse_component(".", allow_self=True)

    def test_posix_components_allow_colons(self):
        with mock.patch.object(safe_open, "_WINDOWS", False):
            safe_open._refuse_component("file:stream")



class ReplacePathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.target = self.base / "state.md"
        self.target.write_bytes(b"old")

    def tearDown(self):
        self.tmp.cleanup()

    def _stage(self, data=b"new"):
        staged = self.base / "state.md.tmp"
        staged.write_bytes(data)
        return staged

    def test_replaces_like_os_replace(self):
        safe_open.replace_path(self._stage(), self.target)
        self.assertEqual(self.target.read_bytes(), b"new")
        self.assertFalse((self.base / "state.md.tmp").exists())

    def test_succeeds_while_a_shared_reader_holds_the_target(self):
        # A safe_open reader shares delete access; the replacement lands at once and
        # the reader keeps the old bytes (POSIX semantics on both platforms).
        fd = safe_open.open_file(self.target)
        try:
            safe_open.replace_path(self._stage(), self.target)
            self.assertEqual(os.read(fd, 10), b"old")
        finally:
            os.close(fd)
        self.assertEqual(safe_open.read_text_shared(self.target), "new")

    @unittest.skipUnless(os.name == "nt", "plain Windows opens do not share delete access")
    def test_waits_for_a_plain_reader_and_then_fails(self):
        import time
        with mock.patch.object(safe_open, "_REPLACE_WAIT_SECONDS", 0.2):
            with open(self.target, "rb"):
                started = time.monotonic()
                with self.assertRaises(PermissionError):
                    safe_open.replace_path(self._stage(), self.target)
                self.assertGreaterEqual(time.monotonic() - started, 0.2)
        self.assertEqual(self.target.read_bytes(), b"old")

    @unittest.skipUnless(os.name == "nt", "plain Windows opens do not share delete access")
    def test_succeeds_once_a_plain_reader_closes(self):
        import threading
        handle = open(self.target, "rb")
        timer = threading.Timer(0.1, handle.close)
        timer.start()
        try:
            safe_open.replace_path(self._stage(), self.target)
        finally:
            timer.join()
            handle.close()
        self.assertEqual(self.target.read_bytes(), b"new")

    def test_read_text_shared_matches_read_text(self):
        self.target.write_text("line one\nline two\n", encoding="utf-8", newline="\n")
        self.assertEqual(safe_open.read_text_shared(self.target), self.target.read_text(encoding="utf-8"))



class ResolvePathTests(unittest.TestCase):
    def test_matches_path_resolve(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "file"
            target.write_bytes(b"x")
            self.assertEqual(safe_open.resolve_path(target), target.resolve())
            self.assertEqual(safe_open.resolve_path(str(target)), target.resolve())

    @unittest.skipUnless(os.name == "nt", "NTFS lists a replaced-but-open file under $Extend\\$Deleted")
    def test_retries_past_a_deleted_name_and_bounds_the_wait(self):
        live = pathlib.Path(r"\\?\D:\vault\agents\x\SESSION.md")
        deleted = pathlib.Path(r"\\?\D:\$Extend\$Deleted\000400000000842C4F7EE46D")
        with mock.patch.object(pathlib.Path, "resolve", side_effect=[deleted, deleted, live]):
            self.assertEqual(safe_open.resolve_path(r"D:\vault\agents\x\SESSION.md"), live)
        with mock.patch.object(pathlib.Path, "resolve", return_value=deleted):
            with self.assertRaises(OSError):
                safe_open.resolve_path(r"D:\vault\agents\x\SESSION.md")



class ComponentTests(unittest.TestCase):
    def test_plain_names_come_back_unchanged(self):
        for name in ("a", "SOUL.md", "caf\u00e9", ".hidden", "...", "a b", "x" * 200, "\U0001f680"):
            with self.subTest(name=name):
                self.assertEqual(safe_open.component(name), name)
        self.assertEqual(safe_open.component(".", allow_self=True), ".")

    def test_separators_traversal_and_control_names_are_refused(self):
        bad = ["", ".", "..", "a/b", "a\\b", "/a", "a/", "a\x00b", 42, None]
        if os.name == "nt":
            bad += ["a:b", "C:", "file::$DATA"]
        for name in bad:
            with self.subTest(name=repr(name)), self.assertRaises(OSError):
                safe_open.component(name)


class ResolveUnderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name) / "vault"
        (self.root / "projects" / "demo").mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_inside_and_root_itself(self):
        from arvyx_control.paths import resolve_under
        self.assertEqual(resolve_under(self.root, "projects", "demo"), (self.root / "projects" / "demo").resolve())
        self.assertEqual(resolve_under(self.root, "projects", "new", "file.md"), (self.root / "projects" / "new" / "file.md").resolve())
        self.assertEqual(resolve_under(self.root), self.root.resolve())

    def test_traversal_and_siblings_are_refused(self):
        from arvyx_control.paths import resolve_under
        (pathlib.Path(self.tmp.name) / "vault-sibling").mkdir()
        for parts in (("..",), ("..", "vault-sibling"), ("projects", "..", "..", "vault-sibling"), ("..", "vault-sibling", "x")):
            with self.subTest(parts=parts), self.assertRaises(ValueError):
                resolve_under(self.root, *parts)

    @unittest.skipUnless(os.name == "posix", "symlink escape fixture")
    def test_symlink_escape_is_refused(self):
        from arvyx_control.paths import resolve_under
        outside = pathlib.Path(self.tmp.name) / "outside"
        outside.mkdir()
        (self.root / "projects" / "link").symlink_to(outside)
        with self.assertRaises(ValueError):
            resolve_under(self.root, "projects", "link", "x")


def make_link(link: pathlib.Path, target: pathlib.Path) -> None:
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)
    else:
        os.symlink(target, link)


def identity(st):
    return (st.st_dev, st.st_ino)


class SafeOpenTests(unittest.TestCase):
    def setUp(self):
        base_dir = os.environ.get("LOCALAPPDATA") if os.name == "nt" else None
        self.base = pathlib.Path(tempfile.mkdtemp(prefix="arvyx-safe-open-", dir=base_dir))
        self.addCleanup(self._cleanup)
        (self.base / "sub").mkdir()
        (self.base / "sub" / "f.txt").write_bytes(b"hello")
        make_link(self.base / "link", self.base / "sub")
        self.fds = []

    def _cleanup(self):
        for fd in self.fds:
            try:
                os.close(fd)
            except OSError:
                pass
        import shutil
        shutil.rmtree(self.base, ignore_errors=True)

    def keep(self, fd):
        self.fds.append(fd)
        return fd

    @unittest.skipUnless(os.name == "nt", "native Windows UTF-16 integration")
    def test_supplementary_names_open_and_rename_without_truncation(self):
        directory = "dir-\U0001f680-end"
        source = "source-\U0001f680-end.txt"
        target = "target-\U0001f30d-end.txt"
        (self.base / directory).mkdir()
        (self.base / directory / source).write_bytes(b"supplementary")
        root = self.keep(safe_open.open_root(self.base / directory))
        fd = self.keep(safe_open.open_file_at(root, source))
        self.assertEqual(os.read(fd, 100), b"supplementary")
        safe_open.replace_at(root, source, target)
        self.assertFalse((self.base / directory / source).exists())
        self.assertEqual((self.base / directory / target).read_bytes(), b"supplementary")
        reopened = self.keep(safe_open.open_file_at(root, target))
        self.assertEqual(os.read(reopened, 100), b"supplementary")

    def test_available(self):
        self.assertTrue(safe_open.available())

    def test_open_root_holds_the_directory_identity(self):
        root = self.keep(safe_open.open_root(self.base))
        st = os.fstat(root)
        self.assertTrue(stat.S_ISDIR(st.st_mode))
        self.assertEqual(identity(st), identity(os.stat(self.base)))

    def test_open_root_refuses_relative_paths(self):
        with self.assertRaises(OSError):
            safe_open.open_root("relative/path")

    def test_open_root_refuses_a_link_on_the_path(self):
        with self.assertRaises(OSError):
            safe_open.open_root(self.base / "link")

    def test_directory_and_file_opens_relative_to_a_descriptor(self):
        root = self.keep(safe_open.open_root(self.base))
        sub = self.keep(safe_open.open_directory_at(root, "sub"))
        self.assertEqual(identity(os.fstat(sub)), identity(os.stat(self.base / "sub")))
        fd = self.keep(safe_open.open_file_at(sub, "f.txt"))
        info = os.fstat(fd)
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual(os.read(fd, 100), b"hello")

    def test_links_are_refused_and_reported_as_links(self):
        root = self.keep(safe_open.open_root(self.base))
        with self.assertRaises(OSError):
            safe_open.open_directory_at(root, "link")
        with self.assertRaises(OSError):
            safe_open.open_file_at(root, "link")
        st = safe_open.stat_at(root, "link")
        self.assertTrue(stat.S_ISLNK(st.st_mode))
        self.assertFalse(stat.S_ISDIR(st.st_mode))

    def test_stat_at_reports_kinds_and_identities(self):
        root = self.keep(safe_open.open_root(self.base))
        sub = self.keep(safe_open.open_directory_at(root, "sub"))
        self.assertTrue(stat.S_ISDIR(safe_open.stat_at(root, "sub").st_mode))
        file_stat = safe_open.stat_at(sub, "f.txt")
        self.assertTrue(stat.S_ISREG(file_stat.st_mode))
        self.assertEqual(file_stat.st_size, 5)
        self.assertEqual(identity(file_stat), identity(os.stat(self.base / "sub" / "f.txt")))

    def test_errno_mapping_matches_posix(self):
        root = self.keep(safe_open.open_root(self.base))
        sub = self.keep(safe_open.open_directory_at(root, "sub"))
        with self.assertRaises(OSError) as absent:
            safe_open.stat_at(root, "absent")
        self.assertEqual(absent.exception.errno, errno.ENOENT)
        with self.assertRaises(OSError) as notdir:
            safe_open.open_directory_at(sub, "f.txt")
        self.assertEqual(notdir.exception.errno, errno.ENOTDIR)
        with self.assertRaises(OSError) as isdir:
            safe_open.open_file_at(root, "sub")
        self.assertEqual(isdir.exception.errno, errno.EISDIR)

    def test_exclusive_create_writes_once(self):
        root = self.keep(safe_open.open_root(self.base))
        sub = self.keep(safe_open.open_directory_at(root, "sub"))
        fd = safe_open.open_file_at(sub, "new.txt", write=True, create=True, exclusive=True)
        os.write(fd, b"created")
        os.fsync(fd)
        os.close(fd)
        self.assertEqual((self.base / "sub" / "new.txt").read_bytes(), b"created")
        with self.assertRaises(OSError) as again:
            safe_open.open_file_at(sub, "new.txt", write=True, create=True, exclusive=True)
        self.assertEqual(again.exception.errno, errno.EEXIST)

    def test_mkdir_fsync_and_listing(self):
        root = self.keep(safe_open.open_root(self.base))
        sub = self.keep(safe_open.open_directory_at(root, "sub"))
        safe_open.mkdir_at(sub, "made")
        self.assertTrue((self.base / "sub" / "made").is_dir())
        safe_open.fsync_directory(sub)
        self.assertEqual(sorted(safe_open.scandir_names(root)), ["link", "sub"])
        self.assertEqual(sorted(safe_open.scandir_names(sub)), ["f.txt", "made"])

    def test_unlink_and_rmdir_relative(self):
        root = self.keep(safe_open.open_root(self.base))
        sub = self.keep(safe_open.open_directory_at(root, "sub"))
        safe_open.mkdir_at(sub, "empty")
        safe_open.unlink_at(sub, "f.txt")
        self.assertFalse((self.base / "sub" / "f.txt").exists())
        safe_open.rmdir_at(sub, "empty")
        self.assertFalse((self.base / "sub" / "empty").exists())
        # Removing the link entry never touches its target (POSIX unlink of a symlink;
        # on Windows a junction is a directory entry, so rmdir removes the junction itself).
        if os.name == "nt":
            safe_open.rmdir_at(root, "link")
        else:
            safe_open.unlink_at(root, "link")
        self.assertFalse((self.base / "link").exists() or (self.base / "link").is_symlink())
        self.assertTrue((self.base / "sub").is_dir())
        with self.assertRaises(OSError):
            safe_open.rmdir_at(root, "absent")

    def test_replace_at_renames_over_an_existing_name(self):
        root = self.keep(safe_open.open_root(self.base))
        sub = self.keep(safe_open.open_directory_at(root, "sub"))
        fd = safe_open.open_file_at(sub, "staged.txt", write=True, create=True, exclusive=True)
        os.write(fd, b"new")
        os.close(fd)
        safe_open.replace_at(sub, "staged.txt", "f.txt")
        self.assertEqual((self.base / "sub" / "f.txt").read_bytes(), b"new")
        self.assertFalse((self.base / "sub" / "staged.txt").exists())
        with self.assertRaises(OSError):
            safe_open.replace_at(sub, "absent", "f.txt")

    def test_fsync_file_on_a_read_only_descriptor(self):
        root = self.keep(safe_open.open_root(self.base))
        sub = self.keep(safe_open.open_directory_at(root, "sub"))
        fd = self.keep(safe_open.open_file_at(sub, "f.txt"))
        safe_open.fsync_file(fd)

    def test_path_components_are_single_names(self):
        root = self.keep(safe_open.open_root(self.base))
        for bad in ("..", "", "a/b", "a\\b", "a\x00b"):
            with self.subTest(component=bad), self.assertRaises(OSError):
                safe_open.open_directory_at(root, bad)
            with self.subTest(component=bad), self.assertRaises(OSError):
                safe_open.stat_at(root, bad)
            with self.subTest(component=bad), self.assertRaises(OSError):
                safe_open.open_file_at(root, bad)
        with self.assertRaises(OSError):
            safe_open.open_file_at(root, ".")

    def test_dot_reopens_the_directory_itself(self):
        root = self.keep(safe_open.open_root(self.base))
        again = self.keep(safe_open.open_directory_at(root, "."))
        self.assertEqual(identity(os.fstat(again)), identity(os.fstat(root)))
        self.assertEqual(identity(safe_open.stat_at(root, ".")), identity(os.fstat(root)))

    def test_descriptor_path_is_informational(self):
        root = self.keep(safe_open.open_root(self.base))
        path = safe_open.descriptor_path(root)
        if path is not None:
            self.assertEqual(identity(os.stat(path)), identity(os.fstat(root)))


if __name__ == "__main__":
    unittest.main()
