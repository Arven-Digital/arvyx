"""Synthetic decoded dictionary-key boundary regressions; no real secrets."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / 'src'), str(Path(__file__).resolve().parents[2] / 'safe-mcp-bridge/src')]
from safe_mcp_bridge import cli as bridge

PEM_LABEL = 'RSA PRIVATE KEY'
OPEN = f'-----BEGIN {PEM_LABEL}-----\n'
END = '\n-----END RSA PRIVATE KEY-----'
BODY = 'SYNTHETIC_SOL27_BODY_ONLY'


class BridgeKeyTests(unittest.TestCase):
    def emit_envelope(self, value, config=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bridge._emit_response(config or {'redaction': {'fail_on_secret_output': True}}, {'result': value})
        return json.loads(out.getvalue())

    def emit(self, value, config=None):
        return self.emit_envelope(value, config)['result']

    def assert_withheld_then_valid(self, value, config=None):
        config = config or {'redaction': {'fail_on_secret_output': True}}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bridge._emit_response(config, {'id': 'untrusted-correlation', 'result': value})
            bridge._emit_response(config, {'id': 2, 'result': {'safe': 'next frame'}})
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        withheld, valid = map(json.loads, lines)
        self.assertEqual(withheld, {'jsonrpc': '2.0', 'id': None, 'error': {
            'code': -32003, 'message': 'response withheld; outcome uncertain; nothing retried'}})
        self.assertEqual(valid, {'id': 2, 'result': {'safe': 'next frame'}})
        self.assertNotIn(BODY, out.getvalue())
        self.assertNotIn('synthetic-configured-value', out.getvalue())
        self.assertNotIn('untrusted-correlation', out.getvalue())

    def test_key_value_context(self):
        cases = [
            {OPEN: BODY + END},
            {'prefix': OPEN, BODY + END: 'safe-tail'},
            {'nested': [{OPEN: [BODY, END]}]},
            {'safe-prefix-----BE': 'GIN RSA PRIVATE KEY-----\n', BODY: END},
            [{'-----BEGIN RSA PRI': ['VATE KEY-----\n', {BODY: END}]}],
            {OPEN.lower(): BODY + END.lower()},
            {OPEN: BODY},
            {OPEN: BODY + '\n-----END EC PRIVATE KEY-----\nSYNTHETIC_TAIL'},
        ]
        for value in cases:
            with self.subTest(value=value):
                result = json.dumps(self.emit(value))
                self.assertNotIn(BODY, result)
                self.assertNotIn('SYNTHETIC_TAIL', result)

    def test_safe_structure_and_tail_preserved(self):
        self.assertEqual(self.emit({'safe': [1, None, {'x': 'y'}]}), {'safe': [1, None, {'x': 'y'}]})
        result = self.emit({OPEN: BODY + END, 'tail': {'kept': 'ordinary'}})
        self.assertEqual(result['tail'], {'kept': 'ordinary'})

    def test_collisions_withhold_unsafe_response_and_continue(self):
        for value in (
            {OPEN: BODY + END, '[REDACTED-SECRET]': 'must-not-overwrite'},
            {'sk-' + 'a' * 24: 1, 'sk-' + 'b' * 24: 2},
            {OPEN: {BODY: 1, BODY + '2': 2}},
        ):
            with self.subTest(value=value):
                with self.assertRaises(bridge.BridgeError):
                    bridge._redact_shapes({'result': value})
                self.assert_withheld_then_valid(value)

    def test_configured_secret_still_fails_closed(self):
        config = {'auth': {'env': 'SOL27_SYNTHETIC_SECRET'}, 'redaction': {'fail_on_secret_output': True}}
        with patch.dict(os.environ, {'SOL27_SYNTHETIC_SECRET': 'synthetic-configured-value'}):
            for value in ({'synthetic-configured-value': 'safe'}, {'safe': 'synthetic-configured-value'}):
                self.assert_withheld_then_valid(value, config)


if __name__ == '__main__':
    unittest.main()
