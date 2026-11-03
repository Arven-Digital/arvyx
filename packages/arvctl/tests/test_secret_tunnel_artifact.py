from __future__ import annotations

from pathlib import Path, PurePosixPath
import plistlib
import unittest


ROOT = Path(__file__).resolve().parents[3]
if not (ROOT / 'deploy').is_dir():
    raise unittest.SkipTest('deployment tree is not part of this checkout (public candidate)')
TEMPLATE = ROOT / "deploy" / "launchd" / "digital.arven.v2-secret-tunnel.plist.example"


class SecretTunnelArtifactTests(unittest.TestCase):
    def test_launchd_template_is_fail_closed_and_loopback_only(self) -> None:
        payload = plistlib.loads(TEMPLATE.read_bytes())
        # Render caller-owned synthetic SSH inputs in memory; never read a key.
        args = payload["ProgramArguments"]
        identity = PurePosixPath("/synthetic/operator/.ssh/tunnel_ed25519")  # launchd template: POSIX paths on any host
        configured_identity = PurePosixPath(args[args.index("-i") + 1])
        self.assertTrue(configured_identity.is_absolute())
        self.assertEqual(configured_identity.parent.name, ".ssh")
        args[args.index("-i") + 1] = str(identity)
        known_hosts = [index for index, value in enumerate(args)
                       if value.startswith("UserKnownHostsFile=")]
        self.assertEqual(len(known_hosts), 1)
        configured_hosts = PurePosixPath(args[known_hosts[0]].split("=", 1)[1])
        self.assertEqual(configured_hosts.parent, configured_identity.parent)
        self.assertEqual(configured_hosts.name, "known_hosts")
        args[known_hosts[0]] = "UserKnownHostsFile=/synthetic/operator/.ssh/known_hosts"
        self.assertEqual(payload["Label"], "digital.arven.v2-secret-tunnel")
        args = payload["ProgramArguments"]
        self.assertEqual(args[0], "/usr/bin/ssh")
        self.assertEqual(args[1:3], ["-F", "/dev/null"])
        self.assertNotIn("ClearAllForwardings=yes", args)
        self.assertIn("-N", args)
        self.assertIn("-T", args)
        self.assertIn("IdentitiesOnly=yes", args)
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("BatchMode=yes", args)
        self.assertIn("ExitOnForwardFailure=yes", args)
        self.assertIn("ServerAliveInterval=30", args)
        self.assertIn("ServerAliveCountMax=3", args)
        self.assertEqual(args.count("-R"), 1)
        self.assertEqual(args[args.index("-R") + 1], "127.0.0.1:18084:127.0.0.1:8084")
        self.assertIn("GlobalKnownHostsFile=/dev/null", args)
        for forbidden in ("-L", "-D", "-w", "-A", "-X", "-Y"):
            self.assertNotIn(forbidden, args)
        option_values = {args[index + 1] for index, arg in enumerate(args[:-1]) if arg == "-o"}
        for prefix in (
            "LocalForward=",
            "RemoteForward=",
            "DynamicForward=",
            "ForwardAgent=",
            "ForwardX11=",
            "PermitLocalCommand=",
            "ProxyCommand=",
        ):
            self.assertFalse(any(value.startswith(prefix) for value in option_values), prefix)
        self.assertNotIn("0.0.0.0", " ".join(args))
        self.assertNotIn("*:", " ".join(args))
        self.assertEqual(
            args[args.index("-i") + 1],
            str(identity),
        )
        self.assertTrue(payload["RunAtLoad"])
        self.assertEqual(payload["KeepAlive"], {"SuccessfulExit": False})
        self.assertEqual(payload["ThrottleInterval"], 10)

    def test_template_requires_explicit_core_host_render(self) -> None:
        text = TEMPLATE.read_text(encoding="utf-8")
        self.assertEqual(text.count("__CORE_HOST__"), 1)
        self.assertNotIn("IdentityAgent", text)
        self.assertNotIn("ForwardAgent", text)


if __name__ == "__main__":
    unittest.main()
