"""Focus75 regression specifications. NOT EXECUTED in the source-only fix lane."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('focus75_builder', ROOT / 'scripts/build_arvyx_native.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class NativeProvenanceTests(unittest.TestCase):
    def test_command_selects_sessions_and_rpc_without_exact_filter(self):
        command = builder.native_test_command('/explicit/cargo')
        selected = command[command.index('herdr') + 1]
        for name in ('client::shell::amc_sessions::tests::selection',
                     'client::shell::amc_sessions::rpc::tests::selection',
                     'client::shell::amc_session_rpc::tests::selection'):
            self.assertIn(selected, name)
        self.assertNotIn('--exact', command)
        self.assertEqual(command[0], '/explicit/cargo')
        self.assertIn('--offline', command)
        self.assertIn('--locked', command)

    def test_source_digest_binds_non_overlay_source_bytes_and_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'upstream.rs'
            source.write_text('before')
            before = builder.source_digest(root)
            source.write_text('after')
            after = builder.source_digest(root)
            self.assertNotEqual(before, after)
            source.rename(root / 'renamed.rs')
            self.assertNotEqual(after, builder.source_digest(root))

    def test_source_digest_refuses_external_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / 'source'
            root.mkdir()
            external = parent / 'external'
            external.write_text('not bound')
            (root / 'escape').symlink_to(external)
            with self.assertRaisesRegex(ValueError, 'external symlink'):
                builder.source_digest(root)
