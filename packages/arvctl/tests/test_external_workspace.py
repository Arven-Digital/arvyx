"""Security regressions for the grant-agnostic workspace export primitive."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.external_workspace import (
    WorkspaceError, WorkspaceLimits, snapshot_workspace, read_snapshot_file,
    export_snapshot,
)


class ExternalWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "workspace"
        self.root.mkdir()
        (self.root / "src").mkdir()
        (self.root / "src/main.py").write_bytes(b"print('hello')\n")

    def snapshot(self, paths=("src/main.py",), **kwargs):
        return snapshot_workspace(self.root, paths, **kwargs)

    def test_full_nested_discovery_and_expiry_remains_callers_responsibility(self):
        (self.root / "src/nested").mkdir()
        (self.root / "src/nested/readme.md").write_text("review me")
        snap = snapshot_workspace(self.root)
        self.assertEqual(set(export_snapshot(snap)), {"src/main.py", "src/nested/readme.md"})
        self.assertEqual(snap.coverage, "workspace")
        self.assertTrue(snap.complete)
        self.assertFalse(hasattr(snap, "expires_at"))

    def test_discovery_exclusions_and_content_scan(self):
        (self.root / ".env").write_text("not disclosed")
        (self.root / "innocent.txt").write_text("password=" + "synthetic-value")
        (self.root / "binary").write_bytes(b"\xff\x00")
        snap = snapshot_workspace(self.root)
        self.assertFalse(snap.complete)
        self.assertEqual({x.path: x.reason for x in snap.excluded}, {
            ".env": "secret-or-private", "innocent.txt": "secret-content",
            "binary": "unsupported-content"})
        self.assertEqual(set(export_snapshot(snap)), {"src/main.py"})

    def test_discovery_denies_unsafe_entries_and_bounds(self):
        for kind in ("symlink", "fifo", "hardlink"):
            target = self.root / "unsafe"
            if kind == "symlink":
                target.symlink_to(self.root / "src")
            elif kind == "fifo":
                os.mkfifo(target)
            else:
                os.link(self.root / "src/main.py", target)
            with self.subTest(kind=kind), self.assertRaises(WorkspaceError):
                snapshot_workspace(self.root)
            target.unlink()
        for limits in (WorkspaceLimits(max_entries=1), WorkspaceLimits(max_depth=0)):
            with self.assertRaises(WorkspaceError):
                snapshot_workspace(self.root, limits=limits)

    def test_discovery_rejects_added_files_and_mutation_during_inventory(self):
        snap = snapshot_workspace(self.root)
        (self.root / "new.txt").write_text("new")
        with self.assertRaises(WorkspaceError):
            export_snapshot(snap)
        (self.root / "new.txt").unlink()
        real_read = os.read
        def mutate(fd, size):
            data = real_read(fd, size)
            (self.root / "late.txt").write_text("late")
            return data
        with patch("arvyx_control.external_workspace.os.read", side_effect=mutate):
            with self.assertRaises(WorkspaceError):
                snapshot_workspace(self.root)

    def test_discovery_private_directory_is_opaque_and_prefix_is_exact(self):
        (self.root / "private").mkdir()
        (self.root / "private/hidden").symlink_to("/etc/passwd")
        (self.root / "private-notes").write_text("public")
        snap = snapshot_workspace(self.root, exclude_paths=("private",))
        self.assertEqual({e.path: e.reason for e in snap.excluded}, {"private": "caller-excluded"})
        self.assertIn("private-notes", export_snapshot(snap))
        with self.assertRaises(WorkspaceError):
            read_snapshot_file(snap, "private/hidden")

    def test_selected_content_secret_is_not_exported(self):
        (self.root / "src/main.py").write_text("token='" + "synthetic-value" + "'")
        snap = self.snapshot()
        self.assertEqual(export_snapshot(snap), {})
        self.assertEqual(snap.excluded[0].reason, "secret-content")

    def test_workspace_earlier_file_mutated_while_later_exported(self):
        (self.root / "z.txt").write_text("later")
        snap = snapshot_workspace(self.root)
        from arvyx_control import external_workspace as workspace
        real_read = workspace._read
        def mutate(root, parts, *args, **kwargs):
            result = real_read(root, parts, *args, **kwargs)
            if parts == ("z.txt",):
                (self.root / "src/main.py").write_text("late mutation")
            return result
        with patch.object(workspace, "_read", side_effect=mutate):
            with self.assertRaises(WorkspaceError):
                export_snapshot(snap)

    def test_manifest_and_exact_export(self):
        snap = self.snapshot()
        entry = snap.files[0]
        self.assertEqual(entry.path, "src/main.py")
        self.assertEqual(entry.sha256, hashlib.sha256(b"print('hello')\n").hexdigest())
        self.assertTrue(snap.complete)
        self.assertEqual(export_snapshot(snap), {entry.path: b"print('hello')\n"})
        with self.assertRaises(WorkspaceError):
            read_snapshot_file(snap, "not-selected")

    def test_strict_paths(self):
        for path in ("../escape", "/etc/passwd", "src/../main.py", "./src/main.py",
                     "src//main.py", "src\\main.py", "", "src/", "x\x00y"):
            with self.subTest(path=path), self.assertRaises(WorkspaceError):
                self.snapshot((path,))

    def test_symlinks_root_parent_and_leaf(self):
        (self.root / "link").symlink_to(self.root / "src", target_is_directory=True)
        (self.root / "leaf").symlink_to(self.root / "src/main.py")
        for path in ("link/main.py", "leaf"):
            with self.assertRaises(WorkspaceError):
                self.snapshot((path,))
        alias = Path(self.tmp.name) / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(WorkspaceError):
            snapshot_workspace(alias, ("src/main.py",))

    def test_special_files_directories_and_hardlinks_rejected(self):
        os.mkfifo(self.root / "fifo")
        os.link(self.root / "src/main.py", self.root / "hard")
        for path in ("fifo", "src", "hard"):
            with self.subTest(path=path), self.assertRaises(WorkspaceError):
                self.snapshot((path,))

    def test_secret_exclusions_are_explicit_and_not_read(self):
        names = (".env", ".env.production", ".git/config", ".ssh/id_rsa", "key.pem",
                 "credentials.json", "secrets/token", "private-family/note", "local.p12")
        snap = self.snapshot(("src/main.py", *names))
        self.assertFalse(snap.complete)
        self.assertEqual({e.path for e in snap.excluded}, set(names))
        self.assertTrue(all(e.reason == "secret-or-private" for e in snap.excluded))
        self.assertEqual(len(export_snapshot(snap)), 1)
        snap = self.snapshot(exclude_paths=("src",))
        self.assertEqual(snap.files, ())
        self.assertFalse(snap.complete)

    def test_bounds_and_duplicate_paths(self):
        for limits in (WorkspaceLimits(max_files=0), WorkspaceLimits(max_file_bytes=1),
                       WorkspaceLimits(max_total_bytes=1), WorkspaceLimits(max_path_bytes=2)):
            with self.assertRaises(WorkspaceError):
                self.snapshot(limits=limits)
        with self.assertRaises(WorkspaceError):
            self.snapshot(("src/main.py", "src/main.py"))
        with self.assertRaises(WorkspaceError):
            self.snapshot((".env", ".env.local"), limits=WorkspaceLimits(max_files=1))

    def test_replacement_same_bytes_and_content_changes_fail(self):
        snap = self.snapshot()
        target = self.root / "src/main.py"
        data = target.read_bytes()
        target.unlink()
        target.write_bytes(data)
        with self.assertRaises(WorkspaceError):
            read_snapshot_file(snap, "src/main.py")
        snap = self.snapshot()
        target.write_bytes(b"changed")
        with self.assertRaises(WorkspaceError):
            export_snapshot(snap)

    def test_parent_and_root_replacement_fail(self):
        snap = self.snapshot()
        self.root.rename(self.root.with_name("old"))
        self.root.mkdir()
        (self.root / "src").symlink_to(self.root.with_name("old") / "src")
        with self.assertRaises(WorkspaceError):
            export_snapshot(snap)

    def test_aggregate_limit_and_exact_boundary(self):
        (self.root / "second").write_bytes(b"123")
        size = len((self.root / "src/main.py").read_bytes())
        with self.assertRaises(WorkspaceError):
            self.snapshot(("src/main.py", "second"),
                          limits=WorkspaceLimits(max_total_bytes=size + 2))
        snap = self.snapshot(limits=WorkspaceLimits(max_file_bytes=size, max_total_bytes=size))
        self.assertEqual(len(read_snapshot_file(snap, "src/main.py")), size)

    def test_invalid_limits_and_missing_files(self):
        for limits in (WorkspaceLimits(max_files=-1), WorkspaceLimits(max_files=True)):
            with self.assertRaises(WorkspaceError):
                self.snapshot(limits=limits)
        with self.assertRaises(WorkspaceError):
            self.snapshot(("missing",))
        with self.assertRaises(WorkspaceError):
            snapshot_workspace(Path("relative"), ())

    def test_hash_is_checked_independently_of_metadata(self):
        from dataclasses import replace
        snap = self.snapshot()
        changed = replace(snap.files[0], sha256="0" * 64)
        with self.assertRaises(WorkspaceError):
            export_snapshot(replace(snap, files=(changed,)))

    def test_parent_directory_replacement_after_snapshot(self):
        snap = self.snapshot()
        (self.root / "src").rename(self.root / "old-src")
        (self.root / "src").symlink_to(self.root / "old-src", target_is_directory=True)
        with self.assertRaises(WorkspaceError):
            export_snapshot(snap)

    def test_in_place_mutation_during_read_fails(self):
        snap = self.snapshot()
        real_read = os.read
        mutated = False
        def mutate(fd, size):
            nonlocal mutated
            data = real_read(fd, size)
            if not mutated:
                mutated = True
                (self.root / "src/main.py").write_bytes(b"changed")
            return data
        with patch("arvyx_control.external_workspace.os.read", side_effect=mutate):
            with self.assertRaises(WorkspaceError):
                export_snapshot(snap)

    def test_replacement_during_read_fails(self):
        snap = self.snapshot()
        target = self.root / "src/main.py"
        real_read = os.read
        replaced = False
        def replacing_read(fd, size):
            nonlocal replaced
            data = real_read(fd, size)
            if not replaced:
                replaced = True
                target.rename(target.with_name("old.py"))
                target.write_bytes(b"replacement")
            return data
        with patch("arvyx_control.external_workspace.os.read", side_effect=replacing_read):
            with self.assertRaises(WorkspaceError):
                read_snapshot_file(snap, "src/main.py")


if __name__ == "__main__":
    unittest.main()
