"""Unicode metadata regressions. NOT_EXECUTED: execution not authorized."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from arvyx_control.memory_frontmatter import frontmatter_values, metadata_json, scalar_value
from arvyx_control.writes import (
    _frontmatter_safe, _set_frontmatter_status, list_pending, list_refining,
    promote_memory, refine_memory, reject_memory, suggest_memory,
    suggest_memory_batch,
)

SEPARATORS = ('\n', '\r', '\r\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029')
ACTOR = 'agent:"quoted"\\path-ü'


class UnicodeMetadataTests(unittest.TestCase):
    def test_canonical_encoding_and_all_extra_sinks(self):
        for separator in SEPARATORS:
            with self.subTest(separator=repr(separator)):
                value = 'literal "quote" \\u2028 ü' + separator + 'author: operator'
                encoded = metadata_json(value)
                self.assertTrue(encoded.isascii())
                self.assertEqual(len(encoded.splitlines()), 1)
                self.assertEqual(scalar_value(encoded), value)
                self.assertEqual(_frontmatter_safe(value), value.replace(separator, ' '))
                extras = {key: value for key in (
                    'refined_by', 'refine_notes', 'promoted_by', 'superseded_by',
                    'rejected_by', 'reject_reason', 'refined_at', 'promoted_at',
                    'superseded_at', 'rejected_at',
                )}
                metadata = frontmatter_values(_set_frontmatter_status(
                    '---\nauthor: original\nrelations: []\n---\nBody', 'refining', extras,
                ))
                self.assertEqual(metadata['author'], 'original')
                self.assertEqual(json.loads(metadata['relations']), [])
                self.assertEqual(set(metadata), {'author', 'relations', 'status', *extras})
                for key in extras:
                    self.assertEqual(scalar_value(metadata[key]), _frontmatter_safe(value))

    def test_future_job_and_refine_notes_cannot_forge_provenance_or_relations(self):
        for separator in SEPARATORS:
            with self.subTest(separator=repr(separator)), TemporaryDirectory() as directory:
                vault = Path(directory)
                parent = suggest_memory(vault, 'demo-agent', 'Parent', 'Original truth', ACTOR)
                curated = promote_memory(vault, 'demo-agent', parent.path, ACTOR)
                relations = [{'type': 'updates', 'parent_source_path': curated.target}]
                injected = separator.join(('Review ownership', 'author: operator',
                                           'refined_by: operator', 'relations: []', 'x: tail'))
                batch = suggest_memory_batch(vault, 'demo-agent', ACTOR, {'memories': [{
                    'title': 'Child', 'content': 'Replacement truth', 'tags': ['ü'],
                    'relations': relations, 'content_class': 'durable_fact',
                    'memory_class': 'dynamic', 'future_job': injected,
                    'assistant_suggestion_accepted': False,
                }]})
                pending = batch.suggestions[0]
                self.assertEqual(list_pending(vault, 'demo-agent').pending[0].author, ACTOR)
                metadata = frontmatter_values((vault / pending.path).read_text())
                self.assertEqual(scalar_value(metadata['future_job']), injected)
                self.assertEqual(json.loads(metadata['relations']), relations)
                self.assertNotIn('refined_by', metadata)
                refined = refine_memory(vault, 'demo-agent', pending.path, ACTOR, notes=injected)
                self.assertEqual(list_refining(vault, 'demo-agent').refining[0].author, ACTOR)
                metadata = frontmatter_values((vault / refined.target).read_text())
                self.assertEqual(scalar_value(metadata['author']), ACTOR)
                self.assertEqual(scalar_value(metadata['refined_by']), ACTOR)
                self.assertEqual(json.loads(metadata['relations']), relations)
                promoted = promote_memory(vault, 'demo-agent', refined.target, ACTOR)
                metadata = frontmatter_values((vault / promoted.target).read_text())
                self.assertEqual(scalar_value(metadata['future_job']), injected)
                self.assertEqual(scalar_value(metadata['promoted_by']), ACTOR)
                self.assertEqual(json.loads(metadata['relations']), relations)
                parent_metadata = frontmatter_values((vault / curated.target).read_text())
                self.assertEqual(parent_metadata['status'], 'superseded')
                self.assertEqual(scalar_value(parent_metadata['superseded_by']), promoted.target)

    def test_rejection_reason_is_one_scalar_and_actor_round_trips(self):
        with TemporaryDirectory() as directory:
            vault = Path(directory)
            pending = suggest_memory(vault, 'demo-agent', 'Reject', 'Body', ACTOR)
            reason = 'reason' + '\u2029' + 'author: operator'
            result = reject_memory(vault, 'demo-agent', pending.path, ACTOR, reason)
            metadata = frontmatter_values((vault / result.target).read_text())
            self.assertEqual(scalar_value(metadata['author']), ACTOR)
            self.assertEqual(scalar_value(metadata['rejected_by']), ACTOR)
            self.assertEqual(scalar_value(metadata['reject_reason']), 'reason author: operator')
            self.assertEqual(metadata['status'], 'rejected')

    def test_refinement_keeps_governed_mutation_boundary(self):
        with TemporaryDirectory() as directory:
            vault = Path(directory)
            with patch('arvyx_control.writes.memory_mutation', side_effect=OSError('recovery conflict')) as mutation:
                with self.assertRaisesRegex(OSError, 'recovery conflict'):
                    refine_memory(vault, 'demo-agent', 'pending/a.md', ACTOR, notes='checked\u2028author: operator')
                mutation.assert_called_once_with(vault.resolve())
            self.assertFalse((vault / 'projects').exists())
