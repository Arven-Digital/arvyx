"""Synthetic PEM boundary regression tests; no real key material."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / 'src'), str(Path(__file__).resolve().parents[2] / 'safe-mcp-bridge/src')]
from arvyx_control import security, mcp, control
from safe_mcp_bridge import cli as bridge

BODY = 'U1lOVEhFVElDX09OTFlfTk9UX0FfUkVBTF9LRVk='

def pem(label, closed=True):
    return '-----' + 'BEGIN ' + label + '-----\n' + BODY + ('\n-----END ' + label + '-----' if closed else '')

class PemTests(unittest.TestCase):
    def test_dispatch_body_and_clipped(self):
        with tempfile.TemporaryDirectory() as d:
            vault = Path(d)
            p = vault / 'projects/sample/KEY.md'
            p.parent.mkdir(parents=True)
            for closed in (True, False):
                p.write_text('ordinary\n' + pem('RSA PRIVATE KEY', closed))
                for lines in ('3', '1-4'):
                    with self.subTest(closed=closed, lines=lines):
                        result = mcp._call_tool({'name': 'memory.excerpt', 'arguments': {'source_path': 'projects/sample/KEY.md', 'lines': lines, 'max_tokens': 40}}, vault, vault / 'state', {'memory.excerpt'})
                        self.assertNotIn(BODY, json.dumps(result))

    def test_bridge_split_and_whole(self):
        for label in ('RSA PRIVATE KEY', 'DSA PRIVATE KEY', 'ENCRYPTED PRIVATE KEY'):
            for closed in (True, False):
                text = pem(label, closed)
                for value in (text, text.splitlines(), [{'text': part} for part in text.splitlines()], [text[:12], text[12:]]):
                    with self.subTest(label=label, closed=closed, value_type=type(value).__name__):
                        out = io.StringIO()
                        with contextlib.redirect_stdout(out):
                            bridge._emit_response({'redaction': {'fail_on_secret_output': True}}, {'result': value})
                        self.assertNotIn(BODY, out.getvalue())

    def test_admission_scanner_and_standalone(self):
        for label in ('DSA PRIVATE KEY', 'ENCRYPTED PRIVATE KEY'):
            text = pem(label)
            with self.subTest(label=label):
                self.assertTrue(security.contains_literal_secret(text))
                self.assertTrue(security.canonical_secret_line_spans(text))
                with self.assertRaises(ValueError):
                    control._reject_secret_shaped_text(transcript=text)
                self.assertNotIn(BODY, security.redact_secrets(text))
                self.assertNotIn(BODY, bridge.bounded_secret_subn(text, bridge._FALLBACK_SECRET_RE)[0])

    def test_malformed_boundaries_and_parity(self):
        self.assertEqual(security.SECRET_RE.pattern, bridge._FALLBACK_SECRET_RE.pattern)
        for tail in ('', '\n-----END EC PRIVATE KEY-----\nstill sensitive'):
            text = pem('RSA PRIVATE KEY', False) + tail
            for redact in (security.redact_secrets, lambda s: bridge.bounded_secret_subn(s, bridge._FALLBACK_SECRET_RE)[0]):
                result = redact(text)
                self.assertNotIn(BODY, result)
                self.assertNotIn('still sensitive', result)
        # Real archive admission must reject before reaching its SQLite writer.
        from types import SimpleNamespace
        from arvyx_control.cockpit_archive import append_record
        owner = SimpleNamespace(_human=lambda actor: None)
        for label in ('DSA PRIVATE KEY', 'ENCRYPTED PRIVATE KEY'):
            with self.assertRaisesRegex(ValueError, 'secret-shaped'):
                append_record(owner, 'session', event_id='synthetic', source='operator-note', text=pem(label), actor='human')
        text = pem('RSA PRIVATE KEY', False) + '\n' + ('ordinary ' * 100000)
        self.assertNotIn('ordinary', security.redact_secrets(text))

    def test_line_preservation_and_public_material(self):
        text = 'before\n' + pem('RSA PRIVATE KEY') + '\nafter'
        result = security.redact_secrets(text)
        self.assertEqual(result.count('\n'), text.count('\n'))
        self.assertTrue(result.endswith('after'))
        public = '-----BEGIN PUBLIC KEY-----\nordinary\n-----END PUBLIC KEY-----'
        self.assertEqual(public, security.redact_secrets(public))

if __name__ == '__main__':
    unittest.main()
