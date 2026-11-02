from unittest.mock import Mock, patch
from arvyx_control.terminal_sessions import terminal_menu
from arvyx_control.agent_sessions import RoutingError
import pytest


@pytest.mark.parametrize('kwargs', [dict(hermes_home='/profile'), dict(authorize_launch=True)])
def test_no_history_or_launch_gate_is_reintroduced(kwargs):
    with patch('builtins.input', side_effect=AssertionError('text gate forbidden')):
        with pytest.raises(RoutingError):
            terminal_menu(None, None, None, **kwargs)


def test_normal_terminal_enters_arvyx_without_prompt():
    adapter = Mock()
    adapter.open_ui.return_value = 0
    with patch('arvyx_control.terminal_sessions.ExistingArvyxAdapter', return_value=adapter), patch('builtins.input', side_effect=AssertionError('number gate forbidden')):
        assert terminal_menu('/owner', '/frontend', '/binary') == 0
    # Explicitly absent onboarding preserves the attach-only/no-text-gate contract.
    adapter.open_ui.assert_called_once_with(onboarding=None)
