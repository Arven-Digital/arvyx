from arvyx_control.local_executor import ExecutionPolicy
import signal
from arvyx_control.replica_authority import authority_context
import subprocess
import threading
import os
import unittest
from unittest.mock import patch, call
from arvyx_control.cockpit import LocalCockpit


@unittest.skipUnless(os.name == 'posix', 'PTY owner, curses surface, fork or pidfd semantics are POSIX-only')
class PortableEndTests(unittest.TestCase):
    def setUp(self):
        wait = patch('os.waitpid',return_value=(410,0))
        wait.start()
        self.addCleanup(wait.stop)
        handles=patch('os.pidfd_open',side_effect=lambda pid:pid)
        handles.start();self.addCleanup(handles.stop)
        close=patch('os.close')
        close.start();self.addCleanup(close.stop)

    def live(self):
        return {'pid':410,'fd':7,'stop':threading.Event()}

    def test_missing_proc_uses_pid_only_ps_and_checks_session_membership(self):
        live=self.live()
        order=[]
        with patch('pathlib.Path.iterdir',side_effect=FileNotFoundError('/proc')), \
             patch('subprocess.check_output',side_effect=['410 Z\n411 S\n412 S\n413 S\n','412 S\n']) as ps, \
             patch('os.getsid',side_effect=lambda pid: {411:410,412:999,413:410}[pid]), \
             patch('signal.pidfd_send_signal') as kill, patch('os.killpg',side_effect=lambda *a:order.append('leader')) as killpg:
            kill.side_effect=lambda *a:order.append('member')
            LocalCockpit._terminate(live)
        self.assertTrue(live['stop'].is_set())
        self.assertEqual(ps.call_args_list,[call(['/bin/ps','-axo','pid=,stat='],text=True,timeout=5)]*2)
        self.assertEqual(kill.call_args_list,[call(411,signal.SIGKILL),call(413,signal.SIGKILL)])
        self.assertEqual(order[0],'leader')
        killpg.assert_called_once_with(410,signal.SIGKILL)

    def test_disappearing_process_does_not_prevent_group_stop(self):
        with patch('pathlib.Path.iterdir',side_effect=FileNotFoundError('/proc')), \
             patch('subprocess.check_output',return_value='411 S\n'), \
             patch('os.getsid',side_effect=ProcessLookupError), \
             patch('os.killpg') as killpg:
            LocalCockpit._terminate(self.live())
        killpg.assert_called_once_with(410,signal.SIGKILL)

    def test_ps_failure_still_stops_group_but_never_claims_complete(self):
        for error in [BlockingIOError(), subprocess.TimeoutExpired('ps',5),subprocess.CalledProcessError(1,'ps')]:
            with self.subTest(error=type(error).__name__), \
                 patch('pathlib.Path.iterdir',side_effect=FileNotFoundError('/proc')), \
                 patch('subprocess.check_output',side_effect=error),patch('os.killpg') as killpg:
                with self.assertRaisesRegex(ValueError,'termination incomplete'):
                    LocalCockpit._terminate(self.live())
                killpg.assert_called_once_with(410,signal.SIGKILL)

    def test_permission_denial_does_not_skip_other_members_and_is_not_acknowledged(self):
        with patch('pathlib.Path.iterdir',side_effect=FileNotFoundError('/proc')), \
             patch('subprocess.check_output',return_value='411 S\n412 S\n'), \
             patch('os.getsid',return_value=410), \
             patch('signal.pidfd_send_signal',side_effect=[PermissionError(),None]) as kill,patch('os.killpg') as killpg:
            with self.assertRaisesRegex(ValueError,'termination incomplete'):
                LocalCockpit._terminate(self.live())
        self.assertEqual(kill.call_count,2)
        killpg.assert_called_once_with(410,signal.SIGKILL)

    def test_rechecks_new_members_and_bounds_unending_spawners(self):
        with patch('pathlib.Path.iterdir',side_effect=FileNotFoundError('/proc')), \
             patch('subprocess.check_output',side_effect=['411 S\n','412 S\n','']) as ps, \
             patch('os.getsid',return_value=410),patch('signal.pidfd_send_signal') as kill,patch('os.killpg'):
            LocalCockpit._terminate(self.live())
        self.assertEqual(kill.call_count,2)
        self.assertEqual(ps.call_count,3)
        with patch('pathlib.Path.iterdir',side_effect=FileNotFoundError('/proc')), \
             patch('subprocess.check_output',return_value='411 S\n') as ps, \
             patch('os.getsid',return_value=410),patch('signal.pidfd_send_signal'),patch('os.killpg'):
            with self.assertRaisesRegex(ValueError,'termination incomplete'):
                LocalCockpit._terminate(self.live())
        self.assertEqual(ps.call_count,3)

    def test_closed_pty_does_not_skip_unverified_members(self):
        live=self.live()
        live['fd']=None
        with patch('pathlib.Path.iterdir',side_effect=FileNotFoundError('/proc')), \
             patch('subprocess.check_output',side_effect=['411 S\n','']), \
             patch('os.getsid',return_value=410),patch('signal.pidfd_send_signal') as kill,patch('os.killpg'):
            LocalCockpit._terminate(live)
        kill.assert_called_once_with(411,signal.SIGKILL)

    def test_group_signal_allows_bounded_leader_exit_before_reaping(self):
        with patch('pathlib.Path.iterdir',side_effect=FileNotFoundError('/proc')), \
             patch('subprocess.check_output',return_value=''),patch('os.killpg'), \
             patch('os.waitpid',side_effect=[(0,0),(410,0)]) as wait:
            LocalCockpit._terminate(self.live())
        self.assertEqual(wait.call_count,2)

    def test_darwin_zombie_group_eperm_is_not_live_member_denial(self):
        with patch('pathlib.Path.iterdir',side_effect=FileNotFoundError('/proc')), \
             patch('subprocess.check_output',return_value='410 Z\n'), \
             patch('os.killpg',side_effect=PermissionError()):
            LocalCockpit._terminate(self.live())

    def test_proc_binary_state_handles_nonutf8_comm(self):
        from pathlib import Path
        passes=iter([[Path('/proc/410'),Path('/proc/411')],[Path('/proc/410')]])
        def stat(path):
            return b'410 (leader) Z 1' if path.parent.name=='410' else b'411 (nonutf8-\xc3) S 1'
        with patch('pathlib.Path.iterdir',side_effect=lambda:next(passes)), \
             patch('pathlib.Path.read_bytes',stat),patch('os.killpg'), \
             patch('os.getsid',return_value=410),patch('signal.pidfd_send_signal') as kill:
            LocalCockpit._terminate(self.live())
        kill.assert_called_once_with(411,signal.SIGKILL)

    def test_close_continues_and_releases_resources_after_one_fault(self):
        from unittest.mock import Mock
        owner=object.__new__(LocalCockpit)
        owner.closed=False
        owner.lock=threading.RLock()
        owner.archive_stop=threading.Event()
        owner.operator_stop=threading.Event()
        owner.archive_thread=owner.operator_thread=owner.web_server=None
        owner.delegation_remote_recovery=owner.delegation_remote_fence=None
        owner.db=Mock()
        owner.owner=Mock()
        owner.live={'a':dict(self.live(),thread=Mock()),'b':dict(self.live(),pid=420,thread=Mock())}
        with patch.object(LocalCockpit,'_terminate',side_effect=[ValueError('termination incomplete'),None]) as terminate:
            with self.assertRaisesRegex(ValueError,'termination incomplete'):
                owner.close()
        self.assertEqual(terminate.call_count,2)
        owner.db.close.assert_called_once()
        owner.owner.close.assert_called_once()
        self.assertTrue(owner.closed)

    def test_close_handles_database_fault_and_still_closes_every_session(self):
        import sqlite3
        from unittest.mock import Mock
        owner=object.__new__(LocalCockpit)
        owner.closed=False
        owner.lock=threading.RLock()
        owner.archive_stop=threading.Event()
        owner.operator_stop=threading.Event()
        owner.archive_thread=owner.operator_thread=owner.web_server=None
        owner.delegation_remote_recovery=owner.delegation_remote_fence=None
        owner.db=Mock()
        owner.owner=Mock()
        owner.live={'a':dict(self.live(),thread=Mock()),'b':dict(self.live(),pid=420,thread=Mock())}
        def terminated(live):
            live['terminated'] = True
        # Inject at the actual post-termination retirement boundary, not an
        # unrelated mocked execute that this shutdown path may never reach.
        with patch.object(LocalCockpit,'_terminate',side_effect=terminated) as terminate, \
             patch.object(LocalCockpit,'_retire_live',side_effect=[sqlite3.OperationalError('injected disk fault'),None]) as retire:
            with self.assertRaisesRegex(ValueError,'termination incomplete'):
                owner.close()
        self.assertEqual(terminate.call_count,2)
        self.assertEqual(retire.call_count,2)
        owner.db.close.assert_called_once()
        owner.owner.close.assert_called_once()
        self.assertTrue(owner.closed)


@unittest.skipUnless(os.name == 'posix', 'PTY owner, curses surface, fork or pidfd semantics are POSIX-only')
class PortableLifecycleTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        from arvyx_control.cockpit_client import initialize
        from arvyx_control.control import create_task
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name)/'home'
        initialize(self.home)
        self.owner=self.open_owner()
        self.enterContext(authority_context(self.owner.vault, self.owner.state))
        self.addCleanup(lambda:self.owner.close())
        task=create_task(self.owner.state,'Lifecycle acceptance',owner='demobot').task
        self.session=self.owner.open(project='demo-agent',task=task.id,name='cleanup-test',actor='operator')

    def open_owner(self):
        return LocalCockpit(self.home/'runtime',self.home/'vault',self.home/'events.jsonl','fixture', execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))

    def test_restart_preserves_uncertainty_without_signaling_reused_pid(self):
        sid=self.session['id']
        self.owner.db.execute('INSERT INTO cleanup_ownership VALUES(?,?)',(sid,99999999))
        self.owner.db.commit()
        self.owner.close()
        self.owner=self.open_owner()
        with patch('os.killpg') as kill:
            with self.assertRaisesRegex(ValueError,'cleanup unverified'):
                self.owner.end(sid,actor='operator')
            with self.assertRaisesRegex(ValueError,'cleanup unverified'):
                self.owner.start(sid,actor='operator', environment='host')
        kill.assert_not_called()
        self.assertNotEqual(self.owner.list()[0]['status'],'ended')

    def test_natural_shell_exit_keeps_identity_and_end_cleans_background_member(self):
        import os,time
        from pathlib import Path
        sid=self.session['id']
        leader=self.owner.start(sid,actor='operator', environment='host')['pid']
        token=self.owner.attach(sid,actor='operator')['attachment']
        self.owner.write(sid,'nohup sleep 60 </dev/null >/dev/null 2>&1 & echo $! > child.pid\nexit\n',actor='operator',attachment=token)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and self.owner.list()[0]['status']!='stopped':
            time.sleep(.02)
        self.assertEqual(self.owner.list()[0]['status'],'stopped')
        child=int((Path(self.session['workspace'])/'child.pid').read_text())
        self.assertEqual(os.getsid(child),leader)
        self.assertEqual(self.owner.end(sid,actor='operator')['status'],'ended')
        self.assertTrue(self.owner.live[sid]['terminated'])

    def test_post_fork_sql_fault_keeps_reservation_and_stops_child(self):
        import sqlite3
        sid=self.session['id']
        self.owner.db.execute("CREATE TRIGGER inject BEFORE INSERT ON cleanup_ownership WHEN NEW.pid>0 BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.owner.start(sid,actor='operator', environment='host')
        self.assertIsNone(self.owner.db.execute('SELECT pid FROM cleanup_ownership WHERE session=?',(sid,)).fetchone())
        self.assertTrue(self.owner.live[sid]['retired'])
        self.assertFalse(self.owner.live[sid]['thread'].is_alive())
        self.assertTrue(self.owner.live[sid]['terminated'])
        self.assertIn('thread',self.owner.live[sid])
        # The pump owns the same connection: serialize DDL and commit together.
        with self.owner.lock:
            self.owner.db.execute('DROP TRIGGER inject')
            self.owner.db.commit()

    def test_pump_start_failure_stops_child_and_never_joins_unstarted_thread(self):
        sid=self.session['id']
        real=threading.Thread.start
        def start(thread):
            if getattr(getattr(thread,'_target',None),'__name__','')=='_pump':
                raise RuntimeError('injected thread exhaustion')
            return real(thread)
        with patch.object(threading.Thread,'start',start):
            with self.assertRaisesRegex(RuntimeError,'thread exhaustion'):
                self.owner.start(sid,actor='operator', environment='host')
        self.assertTrue(self.owner.live[sid]['terminated'])
        self.assertIsNone(self.owner.live[sid]['fd'])
        self.assertEqual(self.owner.end(sid,actor='operator')['status'],'ended')
        self.owner.close()
