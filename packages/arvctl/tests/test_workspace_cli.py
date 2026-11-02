"""The terminal New preparation uses the same real HTTP-handler consent lane."""
from unittest.mock import patch
from test_session_workspace_journey import journey
from test_local_onboarding_services import services
from arvyx_control.shared_onboarding_cli import menu

def test_cli_prepares_selected_workspace_without_launch(journey):
    _,http,target,root,_=journey
    def call(path,body=None):
        status,result=http(path,body);assert status<300,result;return result
    choices=iter(['sessions','new','create','yes','quit'])
    answers=iter(['1','1','cli-work'])
    def choose(prompt,options):
        value=next(choices);assert value in options, 'shared terminal must offer '+value
        return value
    with patch('arvyx_control.onboarding_cli.choose',side_effect=choose),patch('builtins.input',side_effect=lambda *args:next(answers)),patch('builtins.print'):
        assert menu(call)==0
    assert (root/'cli-work').is_dir()
