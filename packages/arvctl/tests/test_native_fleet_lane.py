"""Source-fix regressions; execution requires separate approval."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from arvyx_control.cockpit_fleet import FleetCockpit

SID = 'a' * 32


def fleet():
    value = object.__new__(FleetCockpit)
    value.owner = SimpleNamespace(host='home', open=Mock(return_value={'id': SID}),
                                  native=Mock(return_value={'session': SID, 'conversation': SID}))
    value.endpoints = {}
    return value


def test_open_identity_roundtrips_to_native_without_rewriting_conversation():
    value = fleet()
    row = value.open(project='p', task='t', name='n', actor='operator')
    assert row == {'id': 'home:' + SID, 'host': 'home'}
    native = value.native(row['id'], actor='operator')
    assert native == {'session': row['id'], 'conversation': SID}
    value.owner.native.assert_called_once_with(sid=SID, actor='operator')


def test_embedded_archive_draft_and_delegation_sessions_are_qualified_not_record_ids():
    value = fleet()
    raw = {'records': [{'session': SID, 'id': SID, 'text': SID}],
           'delegation': {'session': SID}, 'native': {'session': SID, 'conversation': SID}}
    result = value._embedded_sessions('home', raw)
    assert result['records'][0] == {'session': 'home:' + SID, 'id': SID, 'text': SID}
    assert result['delegation']['session'] == 'home:' + SID
    assert result['native']['conversation'] == SID
    assert raw['records'][0]['session'] == SID


def test_malformed_embedded_session_is_refused_not_normalized():
    with pytest.raises(ValueError, match='invalid exact fleet session identity'):
        fleet()._embedded_sessions('home', {'session': 'HOME:' + SID})
