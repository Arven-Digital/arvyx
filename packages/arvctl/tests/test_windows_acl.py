"""Windows private-path rules: owner SID plus DACL, the counterpart of uid plus 0700.

Behavioural tests run on Windows only (they read and set real NTFS ACLs on fresh
temporary directories). The import and the refusal on other platforms run everywhere.
"""
import os
import pathlib
import subprocess
import tempfile
import unittest

from arvyx_control import windows_acl

USERS = "*S-1-5-32-545"


class ImportAndRefusalTests(unittest.TestCase):
    def test_module_imports_everywhere(self):
        self.assertTrue(callable(windows_acl.private_path_problem))
        self.assertEqual(windows_acl.describe_sid("S-1-1-0"), "S-1-1-0 (Everyone)")
        self.assertEqual(windows_acl.describe_sid("S-1-5-21-1-2-3-1001"), "S-1-5-21-1-2-3-1001")

    @unittest.skipIf(os.name == "nt", "refusal is for other platforms")
    def test_entry_points_refuse_off_windows(self):
        for call in (
            lambda: windows_acl.current_user_sid(),
            lambda: windows_acl.private_path_problem("."),
            lambda: windows_acl.others_writable_problem("."),
            lambda: windows_acl.make_private("."),
            lambda: windows_acl.security_entries("."),
        ):
            with self.assertRaises(OSError):
                call()


@unittest.skipUnless(os.name == "nt", "NTFS ACLs")
class WindowsAclTests(unittest.TestCase):
    def setUp(self):
        self.base = pathlib.Path(tempfile.mkdtemp(prefix="arvyx-acl-test-"))
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        subprocess.run(["icacls", str(self.base), "/reset", "/t", "/q"], capture_output=True)
        import shutil
        shutil.rmtree(self.base, ignore_errors=True)

    def _grant(self, path, spec):
        subprocess.run(["icacls", str(path), "/grant", spec], check=True, capture_output=True)

    def test_current_user_sid_is_a_user_sid_and_trusted(self):
        sid = windows_acl.current_user_sid()
        self.assertTrue(sid.startswith("S-1-5-21-") or sid.startswith("S-1-12-"), sid)
        self.assertEqual(windows_acl.trusted_sids(), frozenset({sid, windows_acl.SYSTEM_SID, windows_acl.ADMINISTRATORS_SID}))

    def test_make_private_yields_a_private_directory_that_children_inherit(self):
        windows_acl.make_private(self.base)
        self.assertIsNone(windows_acl.private_path_problem(self.base))
        self.assertIsNone(windows_acl.others_writable_problem(self.base))
        child = self.base / "child.json"
        child.write_text("{}")
        self.assertIsNone(windows_acl.private_path_problem(child))
        owner, rows = windows_acl.security_entries(self.base)
        self.assertIn(owner, windows_acl.trusted_sids())
        self.assertEqual({sid for sid, *_ in rows}, set(windows_acl.trusted_sids()))

    def test_access_for_users_is_named_as_the_problem(self):
        windows_acl.make_private(self.base)
        self._grant(self.base, USERS + ":(OI)(CI)R")
        self.assertEqual(windows_acl.private_path_problem(self.base), "access allowed to S-1-5-32-545 (Users)")
        # Read-only access is not a write problem for an ancestor.
        self.assertIsNone(windows_acl.others_writable_problem(self.base))
        windows_acl.make_private(self.base)
        self.assertIsNone(windows_acl.private_path_problem(self.base))

    def test_write_access_for_users_fails_the_ancestor_rule(self):
        windows_acl.make_private(self.base)
        self._grant(self.base, USERS + ":(OI)(CI)W")
        self.assertEqual(windows_acl.others_writable_problem(self.base), "writable by S-1-5-32-545 (Users)")

    def test_inherited_access_counts_like_explicit_access(self):
        windows_acl.make_private(self.base)
        self._grant(self.base, USERS + ":(OI)(CI)R")
        child = self.base / "sub"
        child.mkdir()
        self.assertEqual(windows_acl.private_path_problem(child), "access allowed to S-1-5-32-545 (Users)")
        windows_acl.make_private(child)
        self.assertIsNone(windows_acl.private_path_problem(child))

    def test_reparse_points_are_refused_before_any_acl_read(self):
        windows_acl.make_private(self.base)
        target = self.base / "target"
        target.mkdir()
        junction = self.base / "junction"
        subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(target)], check=True, capture_output=True)
        self.assertEqual(windows_acl.private_path_problem(junction), "reparse point (symbolic link or junction)")
        self.assertEqual(windows_acl.others_writable_problem(junction), "reparse point (symbolic link or junction)")
        with self.assertRaises(OSError):
            windows_acl.make_private(junction)

    def test_missing_path_is_reported_not_raised(self):
        problem = windows_acl.private_path_problem(self.base / "absent")
        self.assertTrue(problem.startswith("cannot stat"), problem)


if __name__ == "__main__":
    unittest.main()
