"""Security-pinned backend/license regression; never depends on host versions."""
import contextlib
import io
import json
from pathlib import Path
import re
import runpy
import tempfile
import unittest
from unittest.mock import patch
from subprocess import CompletedProcess

ROOT=Path(__file__).resolve().parents[3]
VERIFIED={
    'filelock':('4.2.4',{'301241438c57936ef93f4243a94f2559022268bfcf9b375a9a72eb0f8db8358e','c6d8663535e1650ee430507b4ffbac7b464dd64b7647ea0112a9f406499d163d'}),
    'setuptools':('84.2.1',{'3ff8b3b5492a0aa66960f4419365a86b84e013070d4313e4d4a6894f5d64d6bc','ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2'}),
}

class DependencySecurityMetadataTests(unittest.TestCase):
    def test_msgpack_advisory_repair_is_pinned_and_documented(self):
        self.assertRegex((ROOT/'requirements/dev.in').read_text(), r'(?m)^msgpack==1\.2\.4$')
        self.assertRegex((ROOT/'requirements/dev.lock').read_text(), r'(?m)^msgpack==1\.2\.4 ')
        rows={r['name']:r for r in json.loads((ROOT/'requirements/THIRD_PARTY_LICENSES.json').read_text())}
        self.assertEqual(rows['msgpack']['version'], '1.2.4')

    def test_reviewed_licenses_match_fixed_wheel_metadata(self):
        rows={r['name'].lower():r for r in json.loads((ROOT/'requirements/THIRD_PARTY_LICENSES.json').read_text())}
        for name,(version,_) in VERIFIED.items():
            with self.subTest(package=name):
                self.assertEqual(rows[name],dict(name=name,version=version,license='MIT'))

    def test_security_pins_survive_lock_regeneration_inputs(self):
        # filelock arrives through cachecontrol; keep the reviewed security pin
        # in the input as well so regenerating the lock cannot drop the fix.
        inputs=(ROOT/'requirements/dev.in').read_text()
        for name,(version,_) in VERIFIED.items():
            with self.subTest(package=name):
                self.assertRegex(inputs,r'(?m)^'+name+'=='+re.escape(version)+r'$')

    def test_secure_pins_retain_both_verified_distribution_hashes(self):
        lock=(ROOT/'requirements/dev.lock').read_text()
        for name,(version,hashes) in VERIFIED.items():
            with self.subTest(package=name):
                match=re.search(r'(?m)^'+name+r'=='+re.escape(version)+r' \\\n((?:    --hash=sha256:[a-f0-9]+(?: \\)?\n)+)',lock)
                self.assertIsNotNone(match)
                self.assertEqual(set(re.findall(r'sha256:([a-f0-9]+)',match[1])),hashes)

    def test_builder_accepts_fixed_backend_and_retains_no_isolation_build(self):
        module=runpy.run_path(str(ROOT/'scripts/build_arvyx_npm.py'))
        def directories(source,destination,**kwargs): Path(destination).mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory() as temp:
            destination=Path(temp)/'new-package'
            with patch('sys.argv',['builder','--output',str(destination)]),patch('shutil.copytree',side_effect=directories),patch('shutil.copy2'),patch('subprocess.run',return_value=CompletedProcess([],0,'84.2.1\n','')) as calls,contextlib.redirect_stdout(io.StringIO()):
                module['main']()
            probe=calls.call_args_list[0]
            self.assertEqual(probe.args[0][1:3],['-I','-c'])
            wheel=next(c.args[0] for c in calls.call_args_list if 'wheel' in c.args[0])
            self.assertIn('--no-build-isolation',wheel)
            self.assertIn('--no-deps',wheel)
            build_call=next(c for c in calls.call_args_list if c.args[0][:3]==['npm','run','build'])
            self.assertEqual(build_call.kwargs['env']['VITE_AMC_FIXTURE_ONLY'],'false')
            ci=next(c for c in calls.call_args_list if c.args[0][:2]==['npm','ci'])
            self.assertIn('--include=dev',ci.args[0])

    def test_builder_rejects_vulnerable_backend_before_writing_output(self):
        module=runpy.run_path(str(ROOT/'scripts/build_arvyx_npm.py'))
        with tempfile.TemporaryDirectory() as temp:
            destination=Path(temp)/'never-created'
            with patch('subprocess.run',return_value=CompletedProcess([],0,'83.0.0\n','')),patch('sys.argv',['builder','--output',str(destination)]),contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error: module['main']()
            self.assertEqual(error.exception.code,2)
            self.assertFalse(destination.exists())
