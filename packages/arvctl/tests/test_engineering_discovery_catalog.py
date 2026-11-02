"""Product research families must be represented without invented detection."""
from pathlib import Path
import re

from arvyx_control.harness_discovery import discovery_catalog


def test_catalog_covers_exact_product_table_without_relabeling_editor_presence():
    product = Path(__file__).resolve().parents[3] / 'docs/product.md'
    labels = re.findall(r'^\|\s*\d+\s*\|\s*(.*?)\s*\|', product.read_text(), re.MULTILINE)
    assert len(labels) == 25
    for platform in ('linux', 'darwin', 'windows'):
        catalog = discovery_catalog(platform)
        targets = [d for d in catalog if d.get('product_target')]
        assert {d['label'] for d in targets} == set(labels)
        assert len(targets) == 25
        editor = next(d for d in catalog if d['family'] == 'vscode')
        copilot = next(d for d in targets if d['family'] == 'vscode-copilot')
        assert editor['kind'] == 'editor' and not editor['product_target']
        assert not copilot['supported'] and not copilot['paths']
        assert all(d['requires_explicit_connect'] and not d['auto_import'] for d in catalog)
