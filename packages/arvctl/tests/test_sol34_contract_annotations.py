"""Security contract annotations must describe implemented checkpoint access."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_checkpoint_comment_matches_recall_exclusion():
    text = (ROOT / 'packages/arvctl/src/arvyx_control/session.py').read_text()
    assert 'recall-visible' not in text
    assert 'excluded from recall' in text


def test_digest_identity_exemption_documents_session_scope():
    text = (ROOT / 'packages/arvctl/src/arvyx_control/mcp.py').read_text()
    block = text.split('UNBOUND_IDENTITY_ARGUMENT_TOOLS = {', 1)[1].split('"memory.session_get"', 1)[0]
    assert 'session.read' in block
    assert 'memory.read' not in block
