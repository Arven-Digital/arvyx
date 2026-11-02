"""Synthetic filesystem tests; optional real python-dotenv compatibility probe."""
import importlib.util
import io
import json
import subprocess
import sys
import multiprocessing as mp
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.secret_delivery_writer import Destination, DeliveryError


def worker(directory, key, queue, version=None):
    try:
        Destination(directory, '.env', os.getuid(), allowed_keys={key}).write(key, 'synthetic', overwrite_version=version)
        queue.put('ok')
    except DeliveryError as exc:
        queue.put(str(exc))


class WriterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / '.env'
        self.dest = Destination(str(self.root), '.env', os.getuid(), allowed_keys={'KEY', 'OTHER', 'A', 'B', 'anthtropic_auth'} | {'K' + str(i) for i in range(20)})

    def tearDown(self):
        self.tmp.cleanup()

    def seed(self, data):
        self.path.write_bytes(data)
        self.path.chmod(0o600)

    def test_create_and_metadata_receipt(self):
        receipt = self.dest.write('anthtropic_auth', 'synthetic')
        self.assertEqual(receipt.key, 'anthtropic_auth')
        self.assertNotIn('synthetic', repr(receipt))
        self.assertEqual(self.path.read_bytes(), b'anthtropic_auth="synthetic"\n')
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_preserve_and_compare_and_set(self):
        self.seed(b'# comment\r\nOTHER=unchanged\r\nexport KEY = "old" # note\r\n')
        version = self.dest.inspect('KEY').version
        with self.assertRaisesRegex(DeliveryError, '^overwrite-required$'):
            self.dest.write('KEY', 'new')
        self.dest.write('KEY', 'new', overwrite_version=version)
        self.assertEqual(self.path.read_bytes(), b'# comment\r\nOTHER=unchanged\r\nKEY="new"\n')
        with self.assertRaisesRegex(DeliveryError, '^version-conflict$'):
            self.dest.write('KEY', 'later', overwrite_version=version)

    def test_invalid_names_values_and_encoding(self):
        for key in [' bad', 'x-y', 'x\nINJECT', 'é', '1A', '']:
            with self.assertRaisesRegex(DeliveryError, '^invalid-name$'):
                self.dest.write(key, 'synthetic')
        for value in ['${HOME}', 'x\x00y', '\ud800', 'x' * 65537]:
            with self.assertRaisesRegex(DeliveryError, '^unsupported-value$'):
                self.dest.write('KEY', value)
        self.seed(b'KEY=\xff\n')
        with self.assertRaisesRegex(DeliveryError, '^unsupported-file$'):
            self.dest.write('OTHER', 'synthetic')

    def test_encoding_errors_do_not_carry_secret_context(self):
        with self.assertRaises(DeliveryError) as caught:
            self.dest.write('KEY', 'synthetic' + '\ud800')
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(caught.exception.args, ('unsupported-value',))
        self.seed(b'A=synthetic\xff\n')
        with self.assertRaises(DeliveryError) as caught:
            self.dest.prepare('A')
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(caught.exception.args, ('unsupported-file',))
        credential = Destination(str(self.root), '.env', os.getuid(), allowed_keys={'SYNTHETIC_KEY'})
        with self.assertRaisesRegex(DeliveryError, '^unsupported-value$'):
            credential.write('SYNTHETIC_KEY', '雪')

    def test_duplicate_or_unsupported_file(self):
        for raw in [b'KEY=a\nexport KEY=b\n', b"'KEY'=a\n", b'KEY="unterminated\n', b'A=x\nA=y\n']:
            self.seed(raw)
            with self.assertRaises(DeliveryError):
                self.dest.write('OTHER', 'synthetic')
            self.assertEqual(self.path.read_bytes(), raw)

    def test_permissions_owner_links_paths(self):
        self.seed(b'A=a\n')
        self.path.chmod(0o644)
        with self.assertRaises(DeliveryError):
            self.dest.write('B', 'b')
        self.path.chmod(0o600)
        os.link(self.path, self.root / 'alias')
        with self.assertRaises(DeliveryError):
            self.dest.write('B', 'b')
        self.path.unlink()
        self.path.symlink_to(self.root / 'alias')
        with self.assertRaises(DeliveryError):
            self.dest.write('B', 'b')
        with self.assertRaises(DeliveryError):
            Destination(str(self.root), '../escape', os.getuid())
        with self.assertRaises(DeliveryError):
            Destination(str(self.root), '.env', os.getuid() + 1, allowed_keys={'A'}).inspect('A')
        self.root.chmod(0o755)
        with self.assertRaises(DeliveryError):
            self.dest.inspect('A')

    def test_external_change_before_replace(self):
        self.seed(b'A=a\n')
        original = os.fsync
        changed = False
        def change(fd):
            nonlocal changed
            original(fd)
            if not changed:
                changed = True
                self.seed(b'A=external\n')
        with patch('arvyx_control.secret_delivery_writer.os.fsync', side_effect=change):
            with self.assertRaisesRegex(DeliveryError, '^version-conflict$'):
                self.dest.write('B', 'synthetic')
        self.assertEqual(self.path.read_bytes(), b'A=external\n')
        self.assertFalse(list(self.root.glob('*.tmp')))

    def test_concurrent_processes_preserve_all_keys(self):
        ctx = mp.get_context('spawn')
        queue = ctx.Queue()
        processes = [ctx.Process(target=worker, args=(str(self.root), 'K' + str(i), queue)) for i in range(6)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(15)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual([queue.get(timeout=2) for _ in processes], ['ok'] * 6)
        for i in range(6):
            self.assertTrue(self.dest.inspect('K' + str(i)).exists)

    def test_competing_overwrites_have_one_winner(self):
        self.seed(b'KEY=old\n')
        version = self.dest.prepare('KEY').version
        ctx = mp.get_context('spawn')
        queue = ctx.Queue()
        processes = [ctx.Process(target=worker, args=(str(self.root), 'KEY', queue, version)) for _ in range(2)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(15)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(sorted(queue.get(timeout=2) for _ in processes), ['ok', 'version-conflict'])

    def test_version_bound_to_key_and_target(self):
        self.seed(b'A=a\nB=b\n')
        version = self.dest.prepare('A').version
        with self.assertRaisesRegex(DeliveryError, '^version-conflict$'):
            self.dest.write('B', 'new', overwrite_version=version)
        other = Destination(str(self.root), 'other.env', os.getuid(), allowed_keys={'A'})
        with self.assertRaisesRegex(DeliveryError, '^version-conflict$'):
            other.write('A', 'new', overwrite_version=version)

    def test_precommit_failure_keeps_original_and_cleans_temp(self):
        self.seed(b'A=a\n')
        with patch('arvyx_control.secret_delivery_writer.os.fsync', side_effect=OSError('synthetic')):
            with self.assertRaisesRegex(DeliveryError, '^io-failure$'):
                self.dest.write('B', 'synthetic')
        self.assertEqual(self.path.read_bytes(), b'A=a\n')
        self.assertFalse(list(self.root.glob('*.tmp')))

    def test_bounds_and_ownership(self):
        self.seed(b'A=a\n')
        before = self.path.stat()
        self.dest.write('B', 'b')
        after = self.path.stat()
        self.assertEqual((before.st_uid, before.st_gid), (after.st_uid, after.st_gid))
        self.seed(b'#' + b'x' * 1048576)
        with self.assertRaisesRegex(DeliveryError, '^unsupported-file$'):
            self.dest.write('B', 'synthetic')

    def test_policy_defaults_deny_behavior_keys(self):
        closed = Destination(str(self.root), '.env', os.getuid())
        for key in ['PATH', 'PYTHONPATH', 'LD_PRELOAD', 'BASH_ENV', 'anthtropic_auth']:
            with self.assertRaisesRegex(DeliveryError, '^key-not-enrolled$'):
                closed.prepare(key)
            with self.assertRaisesRegex(DeliveryError, '^key-not-enrolled$'):
                closed.write(key, 'synthetic')

    def test_lock_links_and_directory_symlink(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'unchanged')
        outside.chmod(0o600)
        lock = self.root / self.dest.lockname
        lock.symlink_to(outside)
        with self.assertRaises(DeliveryError):
            self.dest.write('KEY', 'synthetic')
        lock.unlink()
        os.link(outside, lock)
        with self.assertRaises(DeliveryError):
            self.dest.write('KEY', 'synthetic')
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(DeliveryError):
            Destination(str(link), '.env', os.getuid(), allowed_keys={'KEY'}).prepare('KEY')
        self.assertEqual(outside.read_bytes(), b'unchanged')

    def test_fifo_rejected_without_blocking(self):
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(DeliveryError):
            self.dest.write('KEY', 'synthetic')

    def test_durability_failure_is_ambiguous(self):
        original = os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('synthetic failure')
            original(fd)
        with patch('arvyx_control.secret_delivery_writer.os.fsync', side_effect=fail_directory):
            with self.assertRaisesRegex(DeliveryError, '^io-ambiguous$'):
                self.dest.write('KEY', 'synthetic')
        self.assertEqual(self.path.read_bytes(), b'KEY="synthetic"\n')

    def test_actual_hermes_loader_synthetic_home(self):
        if importlib.util.find_spec('hermes_cli') is None:
            self.skipTest('separate Hermes source + installed dependencies required')
        values = {'anthtropic_auth': '  Türkçe 雪 # $HOME \\"quote"\nline\r\n ',
                  'SYNTHETIC_KEY': ' ASCII \\"quotes"\nline\t ',
                  'SYNTHETIC_TEXT': ' Unicode 雪 '}
        dest = Destination(str(self.root), '.env', os.getuid(), allowed_keys=values)
        for key, value in values.items():
            dest.write(key, value)
        with self.assertRaisesRegex(DeliveryError, '^unsupported-value$'):
            dest.write('SYNTHETIC_KEY', '雪')
        managed = self.root / 'managed'
        managed.mkdir(mode=0o700)
        script = '''
import contextlib, io, json, os, sys
from pathlib import Path
from hermes_cli.env_loader import load_hermes_dotenv, _sanitize_loaded_credentials
from hermes_cli.config import _sanitize_env_lines
expected = json.load(sys.stdin)
path = Path(os.environ['HERMES_HOME']) / '.env'
before = path.read_bytes()
assert _sanitize_env_lines(before.decode().splitlines(keepends=True)) == before.decode().splitlines(keepends=True)
loaded = load_hermes_dotenv(hermes_home=path.parent, load_external_secrets=False)
assert loaded == [path]
assert path.read_bytes() == before
assert all(os.environ.get(key) == value for key, value in expected.items())
# Prove the real runtime's credential sanitizer boundary, capturing warnings.
os.environ['SYNTHETIC_KEY'] = 'a' + chr(38634)
with contextlib.redirect_stderr(io.StringIO()):
    _sanitize_loaded_credentials()
assert os.environ['SYNTHETIC_KEY'] == 'a'
print('Hermes loader and sanitizer verified')
'''
        env = {'HOME': str(self.root), 'HERMES_HOME': str(self.root),
               'HERMES_MANAGED_DIR': str(managed), 'PYTHONDONTWRITEBYTECODE': '1',
               'PYTHONPATH': os.pathsep.join(sys.path)}
        result = subprocess.run([sys.executable, '-c', script], input=json.dumps(values),
                                text=True, capture_output=True, env=env, cwd=self.root, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'Hermes loader and sanitizer verified')

    def test_actual_dotenv_roundtrip(self):
        try:
            from dotenv import dotenv_values
        except ImportError:
            self.skipTest('python-dotenv not an AMC runtime dependency; run separate Hermes parser probe')
        values = ['a\'b"c', '\\literal\\n', 'line1\nline2\r\nend', '$HOME # text', 'Türkçe 雪', '  padded\t ', '', '\\\"\n\t']
        for value in ['ends' + chr(92), 'two' + chr(92) * 2]:
            with self.assertRaisesRegex(DeliveryError, '^unsupported-value$'):
                self.dest.write('KEY', value)
        for i, value in enumerate(values):
            self.dest.write('K' + str(i), value)
        parsed = dotenv_values(stream=io.StringIO(self.path.read_text()), interpolate=True)
        self.assertEqual([parsed['K' + str(i)] for i in range(len(values))], values)
        self.assertNotEqual(dotenv_values(stream=io.StringIO('K="${MISSING_SYNTHETIC_VAR}"\n'))['K'], '${MISSING_SYNTHETIC_VAR}')
        # Exercise quote/backslash combinations beside a following binding, not
        # just as the final line (python-dotenv's greedy quote scanner matters).
        import itertools
        dest = Destination(str(self.root), 'probe.env', os.getuid(), allowed_keys={'VALUE', 'NEXT'})
        dest.write('VALUE', '')
        dest.write('NEXT', 'sentinel')
        for pair in itertools.product(['a', "'", '"', chr(92), '\n', '\r', '\t', '$', '#', '雪', ' '], repeat=2):
            value = ''.join(pair)
            if value.endswith(chr(92)):
                continue
            dest.write('VALUE', value, overwrite_version=dest.prepare('VALUE').version)
            parsed = dotenv_values(self.root / 'probe.env')
            self.assertEqual(parsed, {'VALUE': value, 'NEXT': 'sentinel'})


if __name__ == '__main__':
    unittest.main()
