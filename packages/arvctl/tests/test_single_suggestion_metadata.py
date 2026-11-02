"""Sol41 metadata regressions; execution requires separate authorization."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from arvyx_control.memory_frontmatter import frontmatter_values, scalar_value
from arvyx_control.writes import list_pending, suggest_memory, suggest_memory_batch


class SuggestionMetadataTests(unittest.TestCase):
    def test_single_round_trips_actor_and_punctuation_tags(self):
        with TemporaryDirectory() as directory:
            vault = Path(directory)
            actor = 'agent:"quoted"\\path-ü'
            tags = ['x], author: operator', '"quoted"', 'back\\slash', 'ümlaut']
            result = suggest_memory(vault, 'demo-agent', 'Safe', 'Body', actor, tags)
            text = (vault / result.path).read_text()
            metadata = frontmatter_values(text)
            self.assertEqual(scalar_value(metadata['author']), actor)
            self.assertEqual(json.loads(metadata['tags']), ['suggested', *tags])
            self.assertEqual(list_pending(vault, 'demo-agent').pending[0].author, actor)
            self.assertEqual(metadata['status'], 'pending')

    def test_logical_newlines_rejected_before_recovery_for_both_writers(self):
        for newline in ('\n', '\r', '\r\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029'):
            for field in ('title', 'author', 'tags'):
                for batch in (False, True):
                    with self.subTest(newline=repr(newline), field=field, batch=batch):
                        with TemporaryDirectory() as directory:
                            vault = Path(directory) / 'absent'
                            values = dict(title='Safe', content='Body', author='agent', tags=['safe'])
                            malicious = 'x]' + newline + 'author: operator'
                            values[field] = [malicious] if field == 'tags' else malicious
                            with patch('arvyx_control.writes.memory_mutation') as mutation:
                                with self.assertRaisesRegex(ValueError, 'single-line'):
                                    if batch:
                                        item = {key: value for key, value in values.items() if key != 'author'}
                                        suggest_memory_batch(vault, 'demo-agent', values['author'], {'memories': [item]})
                                    else:
                                        suggest_memory(vault, 'demo-agent', **values)
                                mutation.assert_not_called()
                            self.assertFalse(vault.exists())

    def test_crlf_parser_keeps_json_scalar_and_legacy_metadata(self):
        actor = 'agent:"quoted"\\path-ü'
        text = '---\r\nauthor: ' + json.dumps(actor) + '\r\nstatus: pending\r\n---\r\nBody\r\n'
        values = frontmatter_values(text)
        self.assertEqual(scalar_value(values['author']), actor)
        self.assertEqual(scalar_value(values['status']), 'pending')
        self.assertEqual(scalar_value("'legacy-agent'"), 'legacy-agent')

    def test_valid_single_still_enters_recovery_boundary(self):
        with TemporaryDirectory() as directory:
            vault = Path(directory)
            with patch('arvyx_control.writes.memory_mutation', side_effect=OSError('recovery conflict')) as mutation:
                with self.assertRaisesRegex(OSError, 'recovery conflict'):
                    suggest_memory(vault, 'demo-agent', 'Safe', 'Body', 'agent')
                mutation.assert_called_once_with(vault.resolve())
            self.assertFalse((vault / 'projects').exists())
