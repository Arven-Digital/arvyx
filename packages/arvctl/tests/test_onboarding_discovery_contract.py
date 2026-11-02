"""Disposable API regressions for truthful bounded discovery."""
from arvyx_control.public_onboarding_api import fixture_composition


def test_connector_capability_and_safe_location(tmp_path):
    api, token, _ = fixture_composition(tmp_path)
    try:
        code, data = api.dispatch('POST', '/api/public-onboarding/discover', 'Bearer ' + token, {})
        assert code == 200
        candidate = data['candidates'][0]
        assert candidate['available'] is True
        assert candidate['location'] == '~/.hermes/config.yaml'
        assert str(tmp_path) not in str(data)
        api.owner.connectors.clear()
        code, data = api.dispatch('POST', '/api/public-onboarding/discover', 'Bearer ' + token, {})
        assert data['candidates'][0]['available'] is False
        assert data['candidates'][0]['reason']
    finally:
        api.close()


def test_unknown_location_and_truncation_remain_explicit(tmp_path):
    api, token, _ = fixture_composition(tmp_path)
    try:
        api.owner.discovery = lambda: {'candidates': [{'id': 'x', 'family': 'x', 'label': 'X', 'kind': 'agent', 'path': '/private/root'}], 'truncated': True}
        code, data = api.dispatch('POST', '/api/public-onboarding/discover', 'Bearer ' + token, {})
        assert code == 200 and data['truncated'] is True
        assert data['candidates'][0]['location'] == 'Known local location (label unavailable)'
        assert '/private/root' not in str(data)
    finally:
        api.close()
