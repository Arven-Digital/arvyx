"""Offline, owned fixtures only; command children are synthetic Python scripts."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from arvyx_control import brokers


class BrokerBoundsTests(unittest.TestCase):
    def resolve(self, spec, name='value'):
        with patch.object(brokers, 'load_broker_config', return_value={'fixture': spec}):
            return brokers.resolve_ref(brokers.SecretRef(broker='fixture', path=name).uri).value

    def test_file_raw_bytes_rejected_before_decode_or_strip(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(brokers, 'MAX_SECRET_BYTES', 64):
            path = Path(tmp) / 'value'
            for content in (b' ' * 1000 + b'x', b'x' * 65 + b'\xff'):
                path.write_bytes(content)
                with self.subTest(case=content[-1]), self.assertRaises(brokers.BrokerError):
                    self.resolve({'provider': 'file', 'base': tmp})
            path.write_bytes(b'x' * 64)
            self.assertEqual(self.resolve({'provider': 'file', 'base': tmp}), 'x' * 64)

    def test_envfile_aggregate_source_budget(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(brokers, 'MAX_ENVFILE_BYTES', 128, create=True):
            path = Path(tmp) / 'owned.env'
            for content in (b'value=ok\n' + b'#\n' * 100, b'#\n' * 100 + b'value=ok\n', b'x' * 129 + b'\xff'):
                path.write_bytes(content)
                with self.subTest(size=len(content)), self.assertRaises(brokers.BrokerError):
                    self.resolve({'provider': 'envfile', 'path': str(path)})
            path.write_bytes(b'# owned\nvalue="ok"\n')
            self.assertEqual(self.resolve({'provider': 'envfile', 'path': str(path)}), 'ok')

    def command(self, code, timeout=2):
        return self.resolve({'provider': 'command', 'command': [sys.executable, '-c', code, '{path}'], 'timeout_seconds': timeout})

    @unittest.skipUnless(os.name == 'posix', 'the owned-command broker supervises with POSIX process groups and is POSIX-only')
    def test_command_each_stream_is_bounded_before_decode(self):
        with patch.object(brokers, 'MAX_SECRET_BYTES', 1024):
            for fd in (1, 2):
                for suffix in (b'', b'\xff'):
                    with self.subTest(fd=fd, invalid=bool(suffix)), self.assertRaises(brokers.BrokerError):
                        self.command(f'import os; os.write({fd}, b"x" * 8192 + {suffix!r}); os.write(1, b"ok")')
            self.assertEqual(self.command('import os; os.write(2, b"x" * 1024); os.write(1, b"ok")'), 'ok')

    @unittest.skipUnless(os.name == 'posix', 'the owned-command broker supervises with POSIX process groups and is POSIX-only')
    def test_concurrent_stream_collection_and_nonzero_exit(self):
        self.assertEqual(self.command('import os; [(os.write(2,b"e"*4096),os.write(1,b"o"*4096)) for _ in range(8)]'), 'o' * 32768)
        with self.assertRaises(brokers.BrokerError):
            self.command('import sys; print("owned"); sys.exit(7)')

    def test_timeout_is_finite_positive_before_start(self):
        for timeout in ('nan', 'inf', 0, -1, 'bad', 10**400):
            with self.subTest(timeout=str(timeout)[:10]), patch.object(brokers.subprocess, 'Popen', side_effect=AssertionError('must not start')), self.assertRaises(brokers.BrokerError):
                self.command('pass', timeout)

    def test_leader_exit_with_descendant_holding_both_pipes(self):
        started = time.monotonic()
        with self.assertRaises(brokers.BrokerError):
            self.command('import os,time; p=os.fork(); os._exit(0) if p else time.sleep(4)', 0.15)
        self.assertLess(time.monotonic() - started, 1.5)

    def test_closed_pipes_do_not_remove_process_deadline(self):
        started = time.monotonic()
        with self.assertRaises(brokers.BrokerError):
            self.command('import os,time; os.close(1); os.close(2); time.sleep(4)', 0.15)
        self.assertLess(time.monotonic() - started, 1.5)

    @unittest.skipUnless(os.name == 'posix', 'the owned-command broker supervises with POSIX process groups and is POSIX-only')
    def test_cleanup_never_signals_after_other_reaper_lost_child_identity(self):
        from unittest.mock import Mock
        process = Mock(pid=410, returncode=None, stdin=None, stdout=None, stderr=None)
        with patch.object(brokers.os, 'waitid', side_effect=ChildProcessError('private-detail')), \
             patch.object(brokers.os, 'killpg') as kill:
            with self.assertRaisesRegex(brokers.BrokerError, 'cleanup incomplete') as failure:
                brokers._cleanup_owned_command(process)
        kill.assert_not_called()
        process.wait.assert_called_once_with(timeout=1.0)
        self.assertNotIn('private-detail', str(failure.exception))

    @unittest.skipUnless(os.name == 'posix', 'the owned-command broker supervises with POSIX process groups and is POSIX-only')
    def test_cleanup_keeps_unreaped_leader_until_after_group_signal(self):
        from unittest.mock import Mock
        process = Mock(pid=410, returncode=None, stdin=None, stdout=None, stderr=None)
        order = []
        process.wait.side_effect = lambda **_: order.append('reap')
        with patch.object(brokers.os, 'waitid', side_effect=lambda *args: order.append('observe')), \
             patch.object(brokers.os, 'killpg', side_effect=lambda *args: order.append('signal')):
            brokers._cleanup_owned_command(process)
        self.assertEqual(order, ['observe', 'signal', 'reap'])

    def test_child_and_inherited_pipe_deadline_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp) / 'child.pid'
            code = f'import os,time; p=os.fork(); open({str(pidfile)!r},"w").write(str(p or os.getpid())); time.sleep(4)'
            started = time.monotonic()
            with self.assertRaises(brokers.BrokerError):
                self.command(code, 0.15)
            self.assertLess(time.monotonic() - started, 1.5)
            # The group is killed with SIGKILL, which the orphan cannot catch, but
            # its exit is asynchronous: right after killpg it may still be scheduled
            # to die, then briefly remain a zombie. Once that settles it cannot be
            # running, so poll briefly before judging.
            if pidfile.exists():
                pid = int(pidfile.read_text())
                deadline = time.monotonic() + 2.0
                while self.process_state(pid) not in (None, 'Z') and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertIn(self.process_state(pid), (None, 'Z'))

    @staticmethod
    def process_state(pid):
        """/proc state letter of pid, or None once the process is gone."""
        try:
            return Path(f'/proc/{pid}/stat').read_text().rpartition(')')[2].split()[0]
        except OSError:
            return None


if __name__ == '__main__':
    unittest.main()
