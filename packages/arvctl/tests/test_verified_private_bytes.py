import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import unittest.mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts'))
import verified_private_bytes
from verified_private_bytes import verified_notice_exemptions, PROVENANCE, LOCAL_PATCHES
from public_release_boundary import check_private_notices, validate_candidate_provenance, BoundaryError


class VerifiedPrivateBytesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        shutil.copytree(ROOT / 'frontends/paperclip/vendor', self.repo / 'frontends/paperclip/vendor')
        shutil.copytree(ROOT / 'frontends/paperclip/public', self.repo / 'frontends/paperclip/public')
        for name in ['package.json', 'package-lock.json']:
            shutil.copyfile(ROOT / 'frontends/paperclip' / name, self.repo / 'frontends/paperclip' / name)
        self.classes = json.loads((ROOT / 'config/public-release-paths.json').read_text())['paths']

    def test_exact_bytes(self):
        # Notice exemptions are issued only for pinned paths classified private-only;
        # every pinned digest is verified regardless of classification.
        pinned = {p: 'private-only' for p in self.classes if p.startswith('frontends/paperclip/')}
        all_pinned = verified_notice_exemptions(self.repo, {**self.classes, **pinned})
        self.assertEqual(len(all_pinned), 403)
        # Unpinned private-only paperclip files (local test fixtures) earn no exemption:
        # they carry the notice header like every other private-only file.
        expected = sum(1 for p in all_pinned if self.classes.get(p) == 'private-only')
        self.assertEqual(len(verified_notice_exemptions(self.repo, self.classes)), expected)
        self.assertTrue(set(verified_notice_exemptions(self.repo, self.classes)) <= set(all_pinned))

    def test_tampering_source_and_provenance(self):
        for rel in ['frontends/paperclip/vendor/components/KanbanBoard.tsx', PROVENANCE]:
            with self.subTest(rel=rel):
                p = self.repo / rel
                raw = p.read_bytes()
                p.write_bytes(raw + b'\n')
                self.assertTrue(check_private_notices(self.repo, self.classes)[0].startswith('immutable notice verification failed:'))
                p.write_bytes(raw)

    def test_public_reclassification_drops_the_exemption_but_keeps_the_digest_check(self):
        classes = {p: 'private-only' for p in self.classes if p.startswith('frontends/paperclip/')}
        classes['frontends/paperclip/vendor/index.css'] = 'public-approved'
        exemptions = verified_notice_exemptions(self.repo, classes)
        self.assertNotIn('frontends/paperclip/vendor/index.css', exemptions)
        self.assertEqual(len(exemptions), 402)
        p = self.repo / 'frontends/paperclip/vendor/index.css'
        p.write_bytes(p.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'immutable private bytes changed'):
            verified_notice_exemptions(self.repo, classes)

    def test_symlink_refused(self):
        p = self.repo / 'frontends/paperclip/vendor/index.css'
        p.unlink()
        p.symlink_to(ROOT / 'frontends/paperclip/vendor/index.css')
        with self.assertRaises(ValueError):
            verified_notice_exemptions(self.repo, self.classes)

    def test_unlisted_source_has_no_exception(self):
        rel = 'frontends/paperclip/vendor/unreviewed.ts'
        (self.repo / rel).write_text('export const value = 1;')
        classes = {**self.classes, rel: 'private-only'}
        self.assertIn('private-only file lacks the notice: ' + rel, check_private_notices(self.repo, classes))

    def test_private_export_still_refused(self):
        with self.assertRaises(BoundaryError):
            validate_candidate_provenance(ROOT / 'config/public-release-paths.json', {'out.json': {'source': 'PRIVATE-BACKUP-MANIFEST.json', 'method': 'copied'}})


class ReviewedLocalPatchTests(unittest.TestCase):
    """Negative controls for the explicit local-patch pins (review 2026-10-30)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        shutil.copytree(ROOT / 'frontends/paperclip/vendor', self.repo / 'frontends/paperclip/vendor')
        shutil.copytree(ROOT / 'frontends/paperclip/public', self.repo / 'frontends/paperclip/public')
        for name in ['package.json', 'package-lock.json']:
            shutil.copyfile(ROOT / 'frontends/paperclip' / name, self.repo / 'frontends/paperclip' / name)
        self.classes = json.loads((ROOT / 'config/public-release-paths.json').read_text())['paths']
        self.provenance = {e['path']: e['sha256'] for e in json.loads((ROOT / PROVENANCE).read_text())['files']}

    def test_every_local_patch_is_bound_to_recorded_upstream_bytes(self):
        self.assertEqual(len(LOCAL_PATCHES), 24)
        for rel, (upstream, local, reason) in LOCAL_PATCHES.items():
            with self.subTest(rel=rel):
                self.assertEqual(self.provenance[rel], upstream)
                self.assertNotEqual(upstream, local)
                self.assertTrue(reason.strip())

    def test_tampered_local_patch_is_refused(self):
        rel = 'frontends/paperclip/vendor/shared/portability-zip.ts'
        p = self.repo / rel
        p.write_bytes(p.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'immutable private bytes changed: ' + rel):
            verified_notice_exemptions(self.repo, self.classes)

    def test_removing_a_local_patch_pin_refuses_the_patched_bytes(self):
        # Patched bytes are accepted only through their explicit pin; without it the
        # file is checked against the recorded upstream digest and refused. (Needs no
        # git history: CI checks out with fetch-depth 1.)
        rel = 'api/client.ts'
        forged = {k: v for k, v in LOCAL_PATCHES.items() if k != rel}
        with unittest.mock.patch.object(verified_private_bytes, 'LOCAL_PATCHES', forged):
            with self.assertRaisesRegex(ValueError, 'immutable private bytes changed: frontends/paperclip/vendor/' + rel):
                verified_notice_exemptions(self.repo, self.classes)

    def test_patch_bound_to_wrong_upstream_digest_is_refused(self):
        rel = 'api/client.ts'
        upstream, local, reason = LOCAL_PATCHES[rel]
        forged = {**LOCAL_PATCHES, rel: ('0' * 64, local, reason)}
        with unittest.mock.patch.object(verified_private_bytes, 'LOCAL_PATCHES', forged):
            with self.assertRaisesRegex(ValueError, 'not bound to the recorded upstream bytes'):
                verified_notice_exemptions(self.repo, self.classes)

    def test_patch_cannot_add_a_file_outside_the_inventory(self):
        forged = {**LOCAL_PATCHES, 'shared/new-file.ts': ('1' * 64, '2' * 64, 'forged')}
        with unittest.mock.patch.object(verified_private_bytes, 'LOCAL_PATCHES', forged):
            with self.assertRaisesRegex(ValueError, 'outside the upstream inventory'):
                verified_notice_exemptions(self.repo, self.classes)
