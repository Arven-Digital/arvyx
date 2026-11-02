"""Static-authored integration regressions; execution requires authorization."""
import json

from arvyx_control import index


def test_snapshot_is_request_local_and_cache_metadata_roundtrips(tmp_path):
    source = tmp_path / "projects" / "demo" / "note.md"
    source.parent.mkdir(parents=True)
    source.write_text("# Durable\nNeedle is preserved.\n", encoding="utf-8")
    cold = index.load_index(tmp_path)
    assert cold and all(chunk.snapshot_text is not None for chunk in cold)
    artifact = json.loads((tmp_path / index.INDEX_RELATIVE).read_text())
    entry = artifact["files"]["projects/demo/note.md"]
    assert {"mtime_ns", "size", "content_hash", "chunks"} <= entry.keys()
    for chunk in cold:
        row = chunk.to_dict()
        assert "snapshot_text" not in row
        restored = index._decode_cached_chunk(chunk.relative_path, row)
        assert restored.snapshot_text is None
        assert restored.to_dict() == row
        assert {"timestamp", "heading", "terms", "length", "start_line", "end_line", "relative_path"} <= row.keys()
    warm = index.load_index(tmp_path)
    assert [chunk.to_dict() for chunk in warm] == [chunk.to_dict() for chunk in cold]
    assert [chunk.snapshot_text for chunk in warm] == [chunk.snapshot_text for chunk in cold]
    source.write_text("# Replacement\nDifferent source generation.\n", encoding="utf-8")
    assert all("Replacement" not in index.chunk_text(tmp_path, chunk) for chunk in cold)


def test_vector_and_timestamp_survive_serialization_without_snapshot():
    chunk = index.IndexedChunk("projects/demo/note.md", 2, 3, "Heading",
                               {"needle": 2}, 2, 123.5, (1.0, 0.0), "Needle snapshot")
    row = chunk.to_dict()
    assert "snapshot_text" not in row
    restored = index._decode_cached_chunk(chunk.relative_path, row)
    assert restored.timestamp == 123.5
    assert restored.vector == (1.0, 0.0)
    assert restored.terms == {"needle": 2}
    assert restored.to_dict() == row
