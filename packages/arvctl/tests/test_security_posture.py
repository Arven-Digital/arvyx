"""Security posture gate derived from the Supermemory teardown (2026-09-09).

Background: supermemory-server v0.0.8 binds 0.0.0.0 and derives "localhost"
trust from the client-supplied Host header (``new URL(req.url).hostname``),
which grants unauthenticated owner access from any network client. See
docs/plans/2026-09-09-supermemory-teardown-backlog.md (B8).

This test enforces the opposite posture in AMC source:

1. No wildcard bind defaults: any server bind/listen must default to loopback
   (127.0.0.1 / ::1 / localhost). "0.0.0.0" may only appear with an explicit
   opt-in flag and an adjacent warning comment.
2. No Host-header-derived trust: authorization decisions must never be based
   on the Host header, X-Forwarded-* headers, or URL hostname comparisons
   against loopback literals.
3. The scanner itself is validated with a positive control: the vulnerable
   pattern replicas below MUST be detected, so a clean scan result is
   trustworthy rather than a silent no-op.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCAN_DIRS = ("apps", "packages", "scripts", "deploy")
SCAN_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".go"}
SKIP_PARTS = {"node_modules", ".git", "__pycache__", "dist", "build", ".venv"}

# Authorization/trust decision derived from client-controlled host information.
HOST_TRUST_PATTERNS = (
    re.compile(
        r"""headers?\s*(?:\[|\.get\()\s*['"](host|x-forwarded-(?:for|host|proto))['"]""",
        re.IGNORECASE,
    ),
    re.compile(r"""\.hostname\s*==="""),
    re.compile(
        r"""request\.host\s*==\s*['"](localhost|127\.0\.0\.1|::1)['"]""",
        re.IGNORECASE,
    ),
)

# This gate file intentionally embeds replicas of vulnerable patterns as
# controls; it must not scan itself.
SELF_EXEMPT = "test_security_posture.py"

# Outbound header ASSIGNMENT (e.g. an edge proxy setting the Host header on
# a forwarded request) is not a trust decision and must not be flagged.
HOST_HEADER_ASSIGNMENT = re.compile(
    r"""headers?\s*\[\s*['"](?:host|x-forwarded-[^'"]*)['"]\s*\]\s*=(?!=)""",
    re.IGNORECASE,
)

# Wildcard binds. Allowed only when the same line (or the line above) carries
# this exact, reviewable marker; generic prose such as "documented" or
# "explicit" must never suppress a finding accidentally.
WILDCARD_BIND_PATTERN = re.compile(r"""['"]0\.0\.0\.0['"]""")
OPT_IN_MARKER = re.compile(
    r"SECURITY:\s*WILDCARD-BIND-OPT-IN", re.IGNORECASE
)

# Bind/listen context: the wildcard literal is only a finding near a server.
BIND_CONTEXT = re.compile(
    r"(bind|listen|serve|host\s*=|HTTPServer|run\(|add_argument)", re.IGNORECASE
)

POSITIVE_CONTROL_VULNERABLE = [
    """hostname = new URL(req.url).hostname === "localhost";""",
    """if request.headers.get("host") == "localhost": grant_owner()""",
    """if headers["x-forwarded-for"] == "127.0.0.1": trust()""",
    """request.host == "localhost" and allow()""",
]
POSITIVE_CONTROL_WILDCARD = [
    """app.run(host="0.0.0.0", port=8080)""",
    """serve_parser.add_argument("--listen", default="0.0.0.0")""",
    """serve_api(\n    host="0.0.0.0",\n    port=9999,\n)""",
]
NEGATIVE_CONTROL_SAFE = [
    """serve_parser.add_argument("--host", default="127.0.0.1")""",
    """base_url = f"http://127.0.0.1:{server.server_port}\"""",
    """# SECURITY: WILDCARD-BIND-OPT-IN\napp.run(host="0.0.0.0")""",
    """serve_api(\n    host="0.0.0.0",\n    port=0,\n)""",
    """headers["Host"] = f"{server.upstream_host}:{server.upstream_port}\"""",
]


def _scan_text(
    text: str, *, wildcard_exempt_window: re.Pattern[str] | None = None
) -> tuple[list[str], list[str]]:
    """Return (host_trust_hits, wildcard_hits) for one file's text."""
    host_hits: list[str] = []
    wildcard_hits: list[str] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if stripped.startswith("#") and not any(
            p.search(line) for p in HOST_TRUST_PATTERNS
        ):
            # Comment lines are scanned for host-trust too (docs can encode
            # the wrong pattern) but wildcard literals in comments need the
            # opt-in marker check like code.
            pass
        for pattern in HOST_TRUST_PATTERNS:
            if pattern.search(line):
                # An outbound assignment of the header is not a trust read.
                if not HOST_HEADER_ASSIGNMENT.search(line):
                    host_hits.append(f"line {lineno}: {stripped[:120]}")
        if WILDCARD_BIND_PATTERN.search(line) and BIND_CONTEXT.search(line):
            context = lines[max(0, lineno - 2) : lineno]
            if not any(OPT_IN_MARKER.search(ctx) for ctx in context):
                if wildcard_exempt_window is not None:
                    window = "\n".join(
                        lines[max(0, lineno - 4) : lineno + 3]
                    )
                    if wildcard_exempt_window.search(window):
                        continue
                wildcard_hits.append(f"line {lineno}: {stripped[:120]}")
    return host_hits, wildcard_hits


def _iter_source_files():
    for scan_dir in SCAN_DIRS:
        root = REPO_ROOT / scan_dir
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.suffix not in SCAN_SUFFIXES or not path.is_file():
                continue
            if any(part in SKIP_PARTS for part in path.parts):
                continue
            if path.name == SELF_EXEMPT:
                continue
            yield path


class TestScannerDetectsVulnerablePatterns(unittest.TestCase):
    """Positive control: the scanner must fire on known-bad replicas."""

    def test_host_trust_patterns_detected(self):
        for snippet in POSITIVE_CONTROL_VULNERABLE:
            with self.subTest(snippet=snippet):
                host_hits, _ = _scan_text(snippet)
                self.assertTrue(
                    host_hits, "scanner failed to detect vulnerable host-trust pattern"
                )

    def test_wildcard_binds_detected(self):
        for snippet in POSITIVE_CONTROL_WILDCARD:
            with self.subTest(snippet=snippet):
                _, wildcard_hits = _scan_text(snippet)
                self.assertTrue(
                    wildcard_hits, "scanner failed to detect wildcard bind"
                )

    def test_safe_patterns_not_flagged(self):
        """Negative control: correct loopback defaults stay clean."""
        exempt_window = re.compile(r"\bport\s*=\s*0\b")
        for snippet in NEGATIVE_CONTROL_SAFE:
            with self.subTest(snippet=snippet):
                host_hits, wildcard_hits = _scan_text(
                    snippet, wildcard_exempt_window=exempt_window
                )
                self.assertEqual(host_hits, [])
                self.assertEqual(wildcard_hits, [])


class TestRepoSecurityPosture(unittest.TestCase):
    def test_no_host_header_trust_or_wildcard_bind_defaults(self):
        import subprocess
        tracked = subprocess.run(["git", "ls-files", "-z", *SCAN_DIRS], cwd=REPO_ROOT,
                                 capture_output=True, check=False).stdout.decode()
        for scan_dir in SCAN_DIRS:
            if not (REPO_ROOT / scan_dir).is_dir():
                # A root that this checkout never tracks (the public candidate carries no
                # deployment tree) is absent by design; a tracked root must exist.
                self.assertFalse(
                    any(path.startswith(scan_dir + "/") for path in tracked.split("\0")),
                    f"configured security scan root disappeared: {scan_dir}",
                )
        findings: list[str] = []
        scanned = 0
        for path in _iter_source_files():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned += 1
            rel = path.relative_to(REPO_ROOT)
            is_test = "tests" in rel.parts or rel.name.startswith("test_")
            # Only ephemeral port=0 test harnesses are exempt, detected in a
            # window around the hit (call args may span lines). A fixed-port
            # wildcard bind in tests is still caught. Host-trust checks apply
            # everywhere without exemption.
            exempt_window = re.compile(r"\bport\s*=\s*0\b") if is_test else None
            host_hits, wildcard_hits = _scan_text(
                text, wildcard_exempt_window=exempt_window
            )
            for hit in host_hits:
                findings.append(f"{rel}: HOST-TRUST {hit}")
            for hit in wildcard_hits:
                findings.append(f"{rel}: WILDCARD-BIND {hit}")
        self.assertGreater(scanned, 0, "scanner visited no source files")
        self.assertEqual(
            findings,
            [],
            "security posture violations (Supermemory teardown B8):\n"
            + "\n".join(findings),
        )


if __name__ == "__main__":
    unittest.main()
