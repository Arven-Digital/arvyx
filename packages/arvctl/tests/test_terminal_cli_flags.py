from pathlib import Path
import pytest
from arvyx_control.onboarding_cli import main


@pytest.mark.parametrize('extra', [
    [], ['--new-hermes-profile', 'Fresh'], ['--authorize-default-resume'],
    ['--new-hermes-profile', 'Fresh', '--authorize-default-resume'],
])
def test_terminal_rejects_history_only_number_gate(monkeypatch, extra):
    calls = []
    monkeypatch.setattr('arvyx_control.terminal_sessions.terminal_menu', lambda *a, **kw: calls.append((a, kw)) or 0)
    assert main(['terminal', '--hermes-home', '/explicit/profile', '--workspace', '/explicit/work',
                 '--authorize-native-launch', *extra]) == 2
    assert calls == []


def test_terminal_forwards_exact_existing_frontend(monkeypatch):
    calls = []
    monkeypatch.setattr('arvyx_control.terminal_sessions.terminal_menu', lambda *a, **kw: calls.append((a, kw)) or 0)
    assert main(['terminal', '--native-owner', '/owner', '--frontend-home', '/frontend', '--arvyx-binary', '/binary']) == 0
    args, kwargs = calls.pop()
    assert args == (Path('/owner'), Path('/frontend'), Path('/binary'))
    assert kwargs['authorize_launch'] is False
    assert kwargs['new_profile'] is None
