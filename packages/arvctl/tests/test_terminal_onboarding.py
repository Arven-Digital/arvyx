"""Fresh package onboarding must not mistake metadata for native attachment."""
from arvyx_control.onboarding_cli import main


def test_fresh_terminal_explains_safe_read_only_path(capsys, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('fresh onboarding must not launch or attach')
    monkeypatch.setattr('arvyx_control.terminal_sessions.terminal_menu', forbidden)
    monkeypatch.setattr('arvyx_control.terminal_sessions.history_menu', forbidden)
    assert main(['terminal']) == 2
    error = capsys.readouterr().err
    assert 'No existing native frontend was supplied' in error
    assert 'arvyx amc --prefix DIRECTORY history --hermes-home PROFILE' in error
    assert 'read-only' in error
    assert 'Telegram' in error
    assert 'does not create a native binding' in error
    assert 'docs/native-first-session.md' in error


def test_partial_native_route_is_not_replaced_by_history(capsys, monkeypatch):
    monkeypatch.setattr('arvyx_control.terminal_sessions.terminal_menu',
                        lambda *a, **kw: (_ for _ in ()).throw(AssertionError('no attach')))
    assert main(['terminal', '--native-owner', '/explicit/owner']) == 2
    assert 'All three exact attach inputs are required' in capsys.readouterr().err
