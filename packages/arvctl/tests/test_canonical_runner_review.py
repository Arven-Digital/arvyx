"""Canonical gates must collect function tests and unittest classes alike."""
import json,re,tomllib
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[3]

class CanonicalRunnerTests(unittest.TestCase):
    def test_hashed_pytest_and_reviewed_runner_licenses_are_committed(self):
        inputs=(ROOT/'requirements/dev.in').read_text();lock=(ROOT/'requirements/dev.lock').read_text()
        records={r['name'].lower():r for r in json.loads((ROOT/'requirements/THIRD_PARTY_LICENSES.json').read_text())}
        self.assertRegex(inputs,r'(?m)^pytest==9\.1\.1$')
        for name in ('pytest','iniconfig','pluggy','colorama'):
            with self.subTest(name=name):
                self.assertRegex(lock,rf'(?m)^{name}==[^\n]+ \\\n    --hash=sha256:[a-f0-9]{{64}}')
                self.assertIn(name,records)
        versions=dict(re.findall(r'(?m)^([\w.-]+)==([^\s\\]+)',lock))
        for name,version in re.findall(r'(?m)^([\w.-]+)==([^\s\\]+)',inputs):
            self.assertEqual(version,versions[name],name+' input and reviewed lock must agree')
        self.assertEqual(tomllib.loads((ROOT/'pyproject.toml').read_text())['project']['dependencies'],[])

    def test_make_runs_both_python_test_styles_and_frontend_npm(self):
        text=(ROOT/'Makefile').read_text()
        # Both test roots stay the default targets; hosted CI narrows them per shard.
        self.assertIn('-m pytest $(PYTEST_TARGETS) -q',text)
        self.assertIn('test: test-python test-frontend test-npm',text)
        self.assertIn('npm --prefix frontends/paperclip test',text)
        self.assertIn('npm --prefix packaging/npm test',text)
        # One parallel pytest pass with xdist-aware coverage (pytest-cov) replaces the
        # serial `coverage run -m pytest`; the floor is still enforced by `coverage report`.
        self.assertIn('-m pytest $(PYTEST_TARGETS) -q -n $(PYTEST_WORKERS) --dist loadfile --cov --cov-branch --cov-fail-under=0',text)
        # The floor is enforced over the combined shards by `coverage report`, not per run.
        self.assertIn('PYTEST_TARGETS ?= packages/arvctl/tests tests',text)
        self.assertNotIn('-m coverage run --branch -m pytest',text)

    def test_workflows_use_full_pytest_coverage_and_keep_floor(self):
        ci=(ROOT/'.github/workflows/ci.yml').read_text();release=(ROOT/'.github/workflows/release-provenance.yml').read_text()
        self.assertNotIn('-m unittest discover',ci+release)
        self.assertIn('--fail-under=75',ci+release)
        for text in (ci,release):
            self.assertIn('make frontend-deps',text)
            self.assertIn('requirements/dev.lock',text)
            self.assertIn('--fail-under=75',text)
        # Hosted CI composes the same full aggregate without rerunning suites.
        for command in ('make ci-preflight PYTHON=python', 'make test-python PYTHON=python',
                        'make test-frontend', 'make test-npm', 'make ci-integration PYTHON=python'):
            self.assertIn(command, ci)
        self.assertNotIn('run: make ci PYTHON=python', ci)
        self.assertIn('make ci PYTHON=python', release)
