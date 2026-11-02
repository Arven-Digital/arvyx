"""Regression source for 06-01; not executed during the restricted fix lane."""
import base64
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.replica import build_manifest, read_state_file, read_vault_file


@unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires POSIX no-follow descriptors")
class ReplicaAliasTests(unittest.TestCase):
    def test_failover_marker_remains_an_independent_authority_fence(self):
        from arvyx_control.replica_authority import ReplicaAuthorityUnavailable
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'.arvyx').mkdir();(root/'.arvyx/failover.json').write_text('{}')
            with self.assertRaises(ReplicaAuthorityUnavailable):build_manifest(root)
    def test_storage_destination_alias_refused_before_equal_write_or_delete(self):
        from arvyx_control import replica
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.arvyx').mkdir()
            lock = root / '.arvyx/vault.lock'
            lock.write_bytes(b'held synthetic authority')
            before = lock.stat().st_ino
            (root / 'notes').symlink_to('.arvyx', target_is_directory=True)
            for operation in (
                lambda: replica._destination_inventory(root),
                lambda: replica._destination_matches(root / 'notes/vault.lock', hashlib.sha256(lock.read_bytes()).hexdigest()),
                lambda: replica._durable_write(root / 'notes/vault.lock', b'incoming'),
            ):
                with self.assertRaises((ValueError, OSError)):
                    operation()
                self.assertEqual(lock.read_bytes(), b'held synthetic authority')
                self.assertEqual(lock.stat().st_ino, before)

    def test_manifest_and_endpoint_share_no_alias_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "vault"
            root.mkdir()
            (root / ".arvyx").mkdir()
            (root / ".arvyx/host-local.private").write_bytes(b"private")
            (root / "ordinary").write_bytes(b"public")
            (root / "direct").symlink_to(".arvyx/host-local.private")
            (root / "local-state").symlink_to(".arvyx", target_is_directory=True)
            (root / "public-alias").symlink_to("ordinary")
            (root / "outside").symlink_to(Path(tmp) / "external")
            (root / "nested").mkdir()
            (root / "nested/.arvyx").mkdir()
            (root / "nested/.arvyx/hidden").write_bytes(b"private")
            os.mkfifo(root / "fifo")
            manifest = build_manifest(root)
            self.assertEqual(set(manifest["files"]), {"ordinary"})
            self.assertEqual(base64.b64decode(read_vault_file(root, "ordinary")["content_b64"]), b"public")
            for relative in ("direct", "local-state/host-local.private", "public-alias", "outside", "fifo",
                             ".arvyx/host-local.private", "nested/.arvyx/hidden", "../external", "/ordinary",
                             "nested/../ordinary", "nested//ordinary", "nested\\ordinary"):
                with self.subTest(relative=relative), self.assertRaises((ValueError, OSError)):
                    read_vault_file(root, relative)

    def test_root_and_root_ancestor_aliases_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "real/vault"
            root.mkdir(parents=True)
            (root / "ordinary").write_bytes(b"public")
            (parent / "root-alias").symlink_to(root, target_is_directory=True)
            (parent / "ancestor-alias").symlink_to(root.parent, target_is_directory=True)
            for alias in (parent / "root-alias", parent / "ancestor-alias/vault"):
                with self.subTest(alias=alias):
                    with self.assertRaises((ValueError, OSError)):
                        read_vault_file(alias, "ordinary")
                    with self.assertRaises((ValueError, OSError)):
                        build_manifest(alias)

    def test_directory_swap_cannot_follow_alias(self):
        from arvyx_control import replica
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "safe").mkdir()
            (root / "safe/file").write_bytes(b"public")
            (root / ".arvyx").mkdir()
            (root / ".arvyx/file").write_bytes(b"private")
            original = os.open
            def swapping_open(path, flags, *args, **kwargs):
                if path == "safe" and "dir_fd" in kwargs:
                    (root / "safe").rename(root / "old-safe")
                    (root / "safe").symlink_to(".arvyx", target_is_directory=True)
                return original(path, flags, *args, **kwargs)
            # Patch the walk only after the root capability has been opened.
            with replica._source_root(root) as fd:
                with patch.object(replica.os, "open", side_effect=swapping_open):
                    with self.assertRaises(OSError):
                        replica._source_bytes(fd, "safe/file")

    def test_state_prefix_contract_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "control-events.jsonl"
            prefix = b'{"type":"unrelated"}\n'
            state.write_bytes(prefix)
            manifest = build_manifest(Path(tmp), state=state)
            meta = manifest["state_files"]["control-events.jsonl"]
            self.assertEqual(meta, {"size": len(prefix), "sha256": hashlib.sha256(prefix).hexdigest()})
            state.write_bytes(prefix + b'{"type":"later"}\n')
            payload = read_state_file("control-events.jsonl", state, None, **meta)
            self.assertEqual(base64.b64decode(payload["content_b64"]), prefix)
            state.write_bytes(b"x" * len(prefix))
            with self.assertRaises(ValueError):
                read_state_file("control-events.jsonl", state, None, **meta)
