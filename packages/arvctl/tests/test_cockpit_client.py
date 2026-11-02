import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

if sys.platform == "linux":
    from arvyx_control import cockpit_client


@unittest.skipUnless(sys.platform == "linux", "Linux pilot")
class PilotClientTests(unittest.TestCase):
    def test_fleet_draft_send_preserves_explicit_session_binding(self):
        from unittest.mock import patch
        # Use an isolated, test-owned pilot home; never the operator's default home.
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "pilot"
            cockpit_client.initialize(home)
            with patch.object(cockpit_client, 'request', return_value={'accepted': True}) as request, patch.object(sys, 'argv', ['arvyx-cockpit', '--home', str(home), 'draft', 'send', 'draft-one', '--session', 'keeper:session-one', '--consent', 'digest', '--attachment', 'lease']):
                cockpit_client.main()
        self.assertEqual(request.call_args.kwargs['sid'], 'keeper:session-one')
        self.assertEqual(request.call_args.kwargs['identifier'], 'draft-one')

    def test_initialize_isolated_existing_amc_vault_and_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "pilot"
            result = cockpit_client.initialize(root)
            self.assertTrue((root / "vault/.arvyx-vault").exists())
            self.assertTrue((root / "vault/registry/projects/demo-agent.json").exists())
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(result["project"], "demo-agent")
            self.assertEqual(cockpit_client.initialize(root), result)

    def test_offline_new_does_not_create_task(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "pilot"
            cockpit_client.initialize(root)
            run = subprocess.run([sys.executable, "-m", "arvyx_control.cockpit_client", "--home", str(root), "new", "demo", "--title", "Offline draft"], capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse((root / "events.jsonl").exists())

    def test_installed_style_cli_init_and_help(self):
        with tempfile.TemporaryDirectory() as temp:
            run = subprocess.run([sys.executable, "-m", "arvyx_control.cockpit_client", "--home", str(Path(temp) / "pilot"), "init"], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)["project"], "demo-agent")
            help_run = subprocess.run([sys.executable, "-m", "arvyx_control.cockpit_client", "--help"], capture_output=True, text=True)
            self.assertIn("attach", help_run.stdout)
            self.assertIn("new", help_run.stdout)

    def test_attach_surfaces_gap_and_discards_discontinuous_tail(self):
        from unittest.mock import patch, MagicMock
        from arvyx_control import cockpit_client as client
        import os
        writes = []
        def response(root, operation, **fields):
            if operation == "capabilities":
                return {"protocol": 2}
            if operation == "read":
                return {"output": "UNSAFE_TAIL", "cursor": 70000, "truncated": True}
            return {"attachment": "test-lease"}
        with patch.object(client.sys, "stdin", MagicMock()), patch.object(client.sys, "stdout", MagicMock()), \
             patch("termios.tcgetattr"), patch("termios.tcsetattr"), patch("tty.setraw"), \
             patch.object(client, "request", side_effect=response), \
             patch.object(client.os, "get_terminal_size", return_value=os.terminal_size((80, 24))), \
             patch.object(client.os, "write", side_effect=lambda fd, data: writes.append(data) or len(data)), \
             patch.object(client.select, "select", return_value=([1], [], [])), \
             patch.object(client.os, "read", return_value=b"\x1d"):
            client.attach(Path("unused"), "session")
        output = b"".join(writes)
        self.assertIn(b"REPLAY GAP", output)
        self.assertNotIn(b"UNSAFE_TAIL", output)

    def test_incompatible_protocol_does_not_acquire_attachment(self):
        from unittest.mock import patch, MagicMock
        with patch.object(cockpit_client.sys, "stdin", MagicMock()), \
             patch.object(cockpit_client.sys, "stdout", MagicMock()), \
             patch.object(cockpit_client, "request", return_value={"protocol": 1}) as rpc:
            with self.assertRaisesRegex(ValueError, "incompatible"):
                cockpit_client.attach(Path("unused"), "session")
            rpc.assert_called_once_with(Path("unused"), "capabilities")
