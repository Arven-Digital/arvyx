import json
import pytest
from arvyx_control.machine_enrollment import enroll,verify

def test_enrollment_is_empty_explicit_and_not_pilot_adoption(tmp_path):
    root=tmp_path/'clean'
    with pytest.raises(ValueError):enroll(root,'physical-a')
    assert not root.exists()
    result=enroll(root,'physical-a',confirmed=True)
    assert result['organizer'] is None and not result['owner_started']
    assert verify(root,'physical-a')['kind']=='explicit-local-human'
    assert list((root/'vault'/'registry').iterdir())==[root/'vault'/'registry'/'machines']
    (root/'pilot.json').write_text('{}')
    with pytest.raises(PermissionError):verify(root,'physical-a')


def test_production_owner_inspection_requires_enrollment_and_refuses_pilot(tmp_path):
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control.cockpit_local import inspect_existing_owner
    from unittest.mock import patch
    root=tmp_path/'clean';enroll(root,'machine-a',confirmed=True)
    owner=LocalCockpit(root/'runtime',root/'vault',root/'events.jsonl','machine-a')
    connection=tmp_path/'connection.json';connection.write_text(json.dumps(dict(home=str(root))))
    with patch('arvyx_control.cockpit_local.request',return_value=owner.snapshot(actor='operator')):
        result=inspect_existing_owner(connection);assert result['home']==root and result['eligible_agents']==[]
        (root/'pilot.json').write_text('{}')
        with pytest.raises(PermissionError):inspect_existing_owner(connection)
    owner.close()
