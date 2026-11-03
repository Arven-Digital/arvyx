from arvyx_control.local_executor import ExecutionPolicy
import os
import shutil
from arvyx_control.replica_authority import authority_context
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from arvyx_control import control
if sys.platform == "linux":
    from arvyx_control import cockpit


@unittest.skipUnless(sys.platform == "linux", "local PTY slice requires Linux")
@unittest.skipUnless(hasattr(socket, 'AF_UNIX'), 'PTY owner integration over the Unix socket is POSIX-only; Windows covers its loopback endpoint in test_owner_endpoint')
class CockpitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.state = self.root / "events.jsonl"
        self.vault = self.root / "vault"
        shutil.copytree(Path(__file__).resolve().parents[3] / "fixtures/synthetic-vault", self.vault)
        self.enterContext(authority_context(self.vault, self.state))
        self.task = control.create_task(self.state, "Synthetic cockpit check", owner="demobot").task
        self.service = cockpit.LocalCockpit(self.root / "private", self.vault, self.state, "laptop-a", execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))
        self.addCleanup(lambda: self.service.close())

    def open(self, **overrides):
        args = dict(project="demo-agent", task=self.task.id, name="demo", actor="operator")
        args.update(overrides)
        return self.service.open(**args)

    def test_bound_empty_workspace_and_duplicate_refusal(self):
        session = self.open()
        self.assertEqual(list(Path(session["workspace"]).iterdir()), [])
        self.assertEqual(Path(session["workspace"]).name, session["name"])
        self.assertEqual(session["task"], self.task.id)
        with self.assertRaisesRegex(ValueError, "active session"):
            self.open(name="second")
        self.assertEqual(control.list_tasks(self.state).tasks[0].status, "open")

    def test_boundaries_fail_before_workspace_creation(self):
        for args in [dict(project="missing"), dict(task="missing"), dict(name=" Demo"),
                     dict(actor="demobot"), dict(name="../escape")]:
            with self.subTest(args=args), self.assertRaises((ValueError, PermissionError)):
                self.open(**args)
        self.assertEqual(self.service.list(), [])

    def test_real_controlling_terminal_detach_replay_end_preserves_files(self):
        session = self.open()
        sid = session["id"]
        self.service.start(sid, actor="operator", environment='host')
        token = self.service.attach(sid, actor="operator")["attachment"]
        self.service.write(sid, "test -t 0 && test -t 1 && printf 'PTY_OK\\n'; printf keep > receipt.txt\n", actor="operator", attachment=token)
        output = ""
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            output = self.service.read(sid, actor="operator")["output"]
            if "PTY_OK\r\n" in output and (Path(session["workspace"]) / "receipt.txt").exists():
                break
            time.sleep(.02)
        self.assertIn("PTY_OK\r\n", output)
        pid = self.service.list()[0]["pid"]
        self.service.detach(sid, actor="operator", attachment=token)
        os.kill(pid, 0)
        self.assertIn("PTY_OK", self.service.read(sid, actor="operator")["output"])
        self.service.attach(sid, actor="operator")
        self.service.end(sid, actor="operator")
        self.assertEqual((Path(session["workspace"]) / "receipt.txt").read_text(), "keep")
        self.assertEqual(self.service.list()[0]["status"], "ended")
        with self.assertRaises(ValueError):
            self.service.write(sid, "echo forbidden\n", actor="operator")

    def test_restart_stays_stopped_and_binding_is_fixed(self):
        session = self.open()
        self.service.start(session["id"], actor="operator", environment='host')
        self.service.close()
        self.service = cockpit.LocalCockpit(self.root / "private", self.vault, self.state, "laptop-a", execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))
        self.assertEqual(self.service.list()[0]["status"], "stopped")
        self.assertIsNone(self.service.list()[0]["pid"])
        self.assertEqual(self.service.list()[0]["workspace"], session["workspace"])
        with self.assertRaisesRegex(ValueError, "active session"):
            self.open()

    def test_second_owner_refused(self):
        with self.assertRaisesRegex(ValueError, "already owned"):
            cockpit.LocalCockpit(self.root / "private", self.vault, self.state, "laptop-a", execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))

    def test_second_root_same_authority_refused(self):
        with self.assertRaisesRegex(ValueError, "already owned"):
            cockpit.LocalCockpit(self.root / "other", self.vault, self.state, "laptop-a", execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))

    def test_foreground_process_terminated_on_end(self):
        session = self.open()
        sid = session["id"]
        self.service.start(sid, actor="operator", environment='host')
        token = self.service.attach(sid, actor="operator")["attachment"]
        self.service.write(sid, "sleep 30 & echo $! > child.pid; wait\n", actor="operator", attachment=token)
        child_file = Path(session["workspace"]) / "child.pid"
        deadline = time.monotonic() + 3
        # The shell creates child.pid before writing the PID; wait for a
        # complete newline-terminated value, not mere existence.
        while time.monotonic() < deadline:
            if child_file.exists() and child_file.read_text().endswith("\n"):
                break
            time.sleep(.02)
        child = int(child_file.read_text())
        self.service.end(sid, actor="operator")
        try:
            os.kill(child, 0)
            status = Path(f"/proc/{child}/stat").read_text().rsplit(") ", 1)[1].split()[0]
            if status == "Z":
                return
        except (ProcessLookupError, FileNotFoundError):
            return
        finally:
            try:
                os.kill(child, 9)
            except ProcessLookupError:
                pass
        self.fail("session child survived end")

    def test_resize_and_delta_cursor(self):
        session = self.open()
        sid = session["id"]
        self.service.start(sid, actor="operator", environment='host')
        self.service.attach(sid, actor="operator")
        self.service.resize(sid, rows=33, columns=101, actor="operator", attachment=self.service.live[sid]["attached"])
        self.service.write(sid, "stty size\n", actor="operator", attachment=self.service.live[sid]["attached"])
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = self.service.read(sid, actor="operator")
            if "33 101\r\n" in result["output"]:
                break
            time.sleep(.02)
        self.assertIn("33 101\r\n", result["output"])
        # The shell may still be printing its prompt after the stty output; drain until
        # the cursor is quiet so the delta read below observes exactly nothing new.
        cursor = result["cursor"]
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            delta = self.service.read(sid, actor="operator", cursor=cursor)
            if delta["output"] == "":
                break
            cursor = delta["cursor"]
            time.sleep(.02)
        self.assertEqual(self.service.read(sid, actor="operator", cursor=cursor)["output"], "")
        with self.assertRaises(ValueError):
            self.service.resize(sid, rows=0, columns=80, actor="operator")

    def test_cli_socket_attach_resize_detach(self):
        import json
        import signal
        self.service.close()
        policy_file=self.root/'execution-policy.json'
        policy_file.write_text(json.dumps(dict(host_uid=os.geteuid(),allow_host=True,allow_root=False,sandbox_launcher=None)))
        policy_file.chmod(0o600)
        process = subprocess.Popen([
            sys.executable, "-m", "arvyx_control.cockpit", "--root", str(self.root / "private"),
            "--vault", str(self.vault), "--state", str(self.state), "--host", "laptop-a", "--execution-policy",str(policy_file),"serve",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def cleanup():
            process.send_signal(signal.SIGINT)
            process.wait(timeout=10)
        self.addCleanup(cleanup)
        endpoint = self.root / "private/cockpit.sock"
        deadline = time.monotonic() + 4
        while not endpoint.exists() and time.monotonic() < deadline:
            self.assertIsNone(process.poll())
            time.sleep(.02)
        self.assertEqual(endpoint.stat().st_mode & 0o777, 0o600)
        def request(operation, **args):
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(4)
                client.connect(str(endpoint))
                client.sendall(json.dumps(dict(operation=operation, **args)).encode() + b"\n")
                with client.makefile("rb") as stream:
                    return json.loads(stream.readline())
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(4)
            client.connect(str(endpoint))
            client.sendall(b"null\n")
            with client.makefile("rb") as stream:
                reply = stream.readline()
            self.assertTrue(reply, "malformed request must not crash the PTY owner")
            self.assertFalse(json.loads(reply)["ok"])
        opened = request("open", project="demo-agent", task=self.task.id, name="socket", actor="operator")
        self.assertTrue(opened["ok"], opened)
        sid = opened["result"]["id"]
        # REV-0551: refusals remain on the served owner; nothing is launched for them.
        missing = request("start", sid=sid, actor="operator")
        self.assertFalse(missing["ok"]); self.assertIn("explicit execution mode required", missing["error"])
        denied_root = request("start", sid=sid, actor="operator", environment="root", root_acknowledged=True)
        self.assertFalse(denied_root["ok"]); self.assertIn("independent root policy", denied_root["error"])
        self.assertTrue(all(row["status"] == "stopped" for row in request("list")["result"]))
        self.assertTrue(request("start", sid=sid, actor="operator",environment="host")["ok"])
        attached = request("attach", sid=sid, actor="operator")
        self.assertTrue(attached["ok"])
        attachment_id = attached["result"]["attachment"]
        self.assertTrue(request("resize", sid=sid, rows=25, columns=90, actor="operator", attachment=attachment_id)["ok"])
        self.assertFalse(request("write", sid=sid, text="echo denied\n", actor="demobot")["ok"])
        self.assertTrue(request("detach", sid=sid, actor="operator", attachment=attachment_id)["ok"])
        self.assertFalse(request("write", sid=sid, text="echo denied\n", actor="operator")["ok"])
        self.assertTrue(request("end", sid=sid, actor="operator")["ok"])

    def test_start_without_policy_or_mode_never_reaches_process_boundary(self):
        from unittest.mock import patch
        sid = self.open()["id"]
        # The same owner directory served without any configured policy.
        self.service.close()
        unconfigured = cockpit.LocalCockpit(self.root / "private", self.vault, self.state, "laptop-a")
        try:
            with patch.object(unconfigured, "_start") as unconfigured_start:
                with self.assertRaisesRegex(PermissionError, "configured execution policy and explicit execution mode required"):
                    unconfigured.start(sid, actor="operator", environment="host")
                unconfigured_start.assert_not_called()
        finally:
            unconfigured.close()
        self.service = cockpit.LocalCockpit(self.root / "private", self.vault, self.state, "laptop-a", execution_policy=ExecutionPolicy(host_uid=os.geteuid(), allow_host=True))
        with patch.object(self.service, "_start") as start:
            with self.assertRaisesRegex(PermissionError, "configured execution policy and explicit execution mode required"):
                self.service.start(sid, actor="operator")
            with self.assertRaisesRegex(PermissionError, "independent root policy"):
                self.service.start(sid, actor="operator", environment="root", root_acknowledged=False)
            with self.assertRaisesRegex(PermissionError, "explicit installed sandbox launcher required"):
                self.service.start(sid, actor="operator", environment="sandbox")
            start.assert_not_called()
        self.assertEqual({row["status"] for row in self.service.list()}, {"stopped"})

    def test_existing_path_spaces_and_unauthorized_input(self):
        workspace = self.root / "existing folder"
        workspace.mkdir()
        session = self.open(workspace=str(workspace))
        self.assertEqual(session["workspace"], str(workspace))
        with self.assertRaises(PermissionError):
            self.service.start(session["id"], actor="demobot", environment='host')
        self.assertEqual(self.service.list()[0]["status"], "stopped")

    def test_backpressure_keeps_control_responsive(self):
        import threading
        sid = self.open()["id"]
        self.service.start(sid, actor="operator", environment='host')
        token = self.service.attach(sid, actor="operator")["attachment"]
        self.service.write(sid, "stty -echo -icanon; echo READY; sleep 30\n", actor="operator", attachment=token)
        deadline = time.monotonic() + 3
        while "READY\r\n" not in self.service.read(sid, actor="operator")["output"] and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertIn("READY\r\n", self.service.read(sid, actor="operator")["output"])
        results = []
        writer = threading.Thread(target=lambda: [results.append(self.service.write(sid, "x" * 4096, actor="operator", attachment=token)) for _ in range(100)], daemon=True)
        writer.start()
        writer.join(1)
        done = threading.Event()
        control = threading.Thread(target=lambda: (self.service.list(), done.set()), daemon=True)
        control.start()
        try:
            self.assertTrue(done.wait(.5), "list stalled behind PTY input")
            self.assertFalse(writer.is_alive(), "input admission blocked")
            self.assertTrue(any(not r["accepted"] for r in results))
            started = time.monotonic()
            self.assertEqual(self.service.end(sid, actor="operator")["status"], "ended")
            self.assertLess(time.monotonic() - started, 2)
        finally:
            self.service._terminate(self.service.live[sid])
            writer.join(3)
            control.join(3)

    def test_input_ack_is_queue_acceptance_not_delivery(self):
        from unittest.mock import patch
        sid = self.open()["id"]
        self.service.start(sid, actor="operator", environment='host')
        self.service.attach(sid, actor="operator")
        with patch.object(cockpit.os, "write", return_value=1):
            result = self.service.write(sid, "a command with a suffix\n", actor="operator", attachment=self.service.live[sid]["attached"])
        self.assertNotEqual(result, {"sent": True}, "short syscall write must not ACK full delivery")
        self.assertTrue(result["accepted"])
        self.assertEqual(result["accepted_bytes"], len("a command with a suffix\n".encode()))

    def test_short_interrupted_blocked_and_failed_input_preserves_accounting(self):
        import threading
        from unittest.mock import patch
        live = dict(fd=123, input=bytearray(b"abcdef"), input_lock=threading.Lock(),
                    written_bytes=0, discarded_bytes=0, input_error=None)
        with patch.object(cockpit.os, "write", side_effect=[2, InterruptedError(), BlockingIOError(), 4]) as write:
            for expected in (b"cdef", b"cdef", b"cdef", b""):
                self.service._flush_input(live)
                self.assertEqual(live["input"], expected)
            self.assertEqual(write.call_args_list[-1].args[1], b"cdef")
        self.assertEqual(live["written_bytes"], 6)
        live["input"].extend(b"failed")
        with patch.object(cockpit.os, "write", side_effect=OSError("synthetic failure")):
            self.service._flush_input(live)
        self.assertEqual(live["discarded_bytes"], 6)
        self.assertTrue(live["input_error"])
        self.assertEqual(live["input"], b"")
