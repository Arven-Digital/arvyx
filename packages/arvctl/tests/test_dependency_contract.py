from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
LOCK = ROOT / "requirements" / "dev.lock"
HASHED_REQUIREMENT = re.compile(r"^[A-Za-z0-9_.-]+==[^\s\\]+ \\\\$")


class DependencyContractTests(unittest.TestCase):
    def test_known_build_dependency_advisories_are_remediated(self) -> None:
        # The advisory floor is bound to the real pip-audit receipt for this round.
        text = LOCK.read_text(encoding="utf-8")
        for name, floor in (("filelock", (4, 2, 1)), ("setuptools", (84, 1, 0))):
            with self.subTest(package=name):
                version = re.search(rf"(?m)^{name}==([0-9.]+)", text)
                self.assertIsNotNone(version)
                assert version is not None
                self.assertGreaterEqual(tuple(map(int, version[1].split('.'))), floor)
        config = tomllib.loads((ROOT / 'pyproject.toml').read_text())
        self.assertIn('setuptools==84.2.1', config['build-system']['requires'])
        self.assertIn('setuptools==84.2.1', (ROOT / 'requirements/dev.in').read_text())

    def test_dev_lock_is_fully_pinned_and_hashed(self) -> None:
        text = LOCK.read_text(encoding="utf-8")
        logical = []
        current = ""
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            current = f"{current} {line}".strip()
            if not line.endswith("\\"):
                logical.append(current)
                current = ""
        self.assertFalse(current, "unterminated requirement continuation")
        self.assertTrue(logical)
        for requirement in logical:
            self.assertRegex(requirement, r"^[A-Za-z0-9_.-]+==[^\s]+ ")
            self.assertIn("--hash=sha256:", requirement)

        for tool in ("build", "coverage", "cyclonedx-bom", "pip-audit", "pip-licenses", "setuptools"):
            self.assertRegex(text, rf"(?m)^{re.escape(tool)}==")

    def test_every_requirements_lock_is_fully_pinned_and_hashed(self) -> None:
        """Every lock a workflow installs gets the same pin/hash discipline.

        The evidence-client lock is separate from dev.lock on purpose (the project
        runtime stays standard-library-only), but separation is not an exemption:
        anything the release pipeline installs must be pinned and hashed.
        """
        locks = sorted((ROOT / "requirements").glob("*.lock"))
        self.assertTrue(locks, "no requirement locks found")
        for lock in locks:
            with self.subTest(lock=lock.name):
                text = lock.read_text(encoding="utf-8")
                logical = []
                current = ""
                for raw in text.splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    current = f"{current} {line}".strip()
                    if not line.endswith("\\"):
                        logical.append(current)
                        current = ""
                self.assertFalse(current, f"{lock.name} has an unterminated requirement")
                self.assertTrue(logical, f"{lock.name} is empty")
                for requirement in logical:
                    self.assertRegex(requirement, r"^[A-Za-z0-9_.-]+==[^\s]+ ")
                    self.assertIn("--hash=sha256:", requirement)

    def test_project_has_no_declared_runtime_dependencies(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(project["dependencies"], [])

    def test_workflows_use_only_the_committed_hashed_lock(self) -> None:
        for relative in (".github/workflows/ci.yml", ".github/workflows/release-provenance.yml"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("requirements/dev.lock", text)
            self.assertIn("--require-hashes", text)
            self.assertNotRegex(text, r"pip install (?:\\\n\s*)?(?:build|coverage|cyclonedx-bom|pip-audit)==")

    def test_make_exposes_fail_closed_dependency_gates(self) -> None:
        text = (ROOT / "Makefile").read_text(encoding="utf-8")
        for target in ("dev-install:", "build:", "dependency-audit:", "sbom:", "license-check:"):
            self.assertIn(target, text)
        self.assertRegex(text, r"pip_audit[^\n]*--strict")
        self.assertIn("cyclonedx_py environment", text)
        self.assertIn("--output-reproducible", text)
        self.assertIn("--disable-pip", text)
        self.assertIn("license-check", text)


if __name__ == "__main__":
    unittest.main()
