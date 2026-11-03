"""offline intake regressions; real parser, synthetic clock and target."""
import io
import json
from email.message import Message
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from arvyx_control.secret_delivery import COOKIE, SecretDelivery, Session
from arvyx_control.secret_delivery_protocol import Principal, Receipts
from arvyx_control.vault import init_vault
import os

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='secret delivery destinations are defined by POSIX uid and mode semantics')


class Intake(io.BytesIO):
    def __init__(self, raw, after_read):
        super().__init__(raw)
        self.after_read = after_read
        self.reads = 0

    def read(self, size=-1):
        result = super().read(size)
        self.reads += 1
        self.after_read()
        return result


@pytest.fixture
def lane():
    with TemporaryDirectory() as root:
        target = SimpleNamespace(id='synthetic', agent='agent', runtime='runtime',
                                 allowed_keys=('KEY',), exchange=Mock(return_value={'status': 'saved'}))
        # The runner's scratch ancestors are group-writable; isolate only this
        # unrelated filesystem guard. SQLite, reservations and parser stay real.
        with patch('arvyx_control.secret_delivery_protocol.safe_parents'):
            store = Receipts(Path(root) / 'receipts.sqlite')
        vault = Path(root) / 'vault'
        init_vault(vault)
        service = SecretDelivery('https://synthetic.invalid', [target], store, vault=vault)
        session = Session('human-a', 'synthetic-csrf', 10)
        session.preparations['confirmation'] = ('synthetic', 'KEY', 'version', False, 100)
        service.sessions['sid'] = session
        clock = [0]
        with patch('arvyx_control.secret_delivery.time.time', side_effect=lambda: clock[0]):
            yield service, session, target, clock


def request(lane, action='send', after_read=lambda: None, csrf='synthetic-csrf', principal=None,
            delivery_id='synthetic-delivery'):
    service, _, _, _ = lane
    payload = {'target': 'synthetic', 'key': 'KEY', 'value': 'synthetic-value',
               'delivery_id': delivery_id, 'confirmation': 'confirmation', 'overwrite': False}
    if action == 'prepare':
        payload = {'target': 'synthetic', 'key': 'KEY'}
    elif action == 'status':
        payload = {'delivery_id': 'synthetic-delivery'}
    raw = json.dumps(payload).encode()
    headers = Message()
    for key, value in {'Origin': service.origin, 'X-Secret-Delivery': '1', 'Cookie': COOKIE+'=sid',
                       'X-Secret-CSRF': csrf, 'Content-Type': 'application/json',
                       'Content-Length': str(len(raw))}.items():
        headers[key] = value
    handler = SimpleNamespace(path='/secret-delivery/'+action, command='POST', headers=headers,
                              connection=SimpleNamespace(settimeout=Mock()),
                              rfile=Intake(raw, after_read), wfile=io.BytesIO(),
                              send_response=Mock(), send_header=Mock(), end_headers=Mock())
    service.handle(handler, principal or Principal('human-a', 100))
    return handler.send_response.call_args.args[0], json.loads(handler.wfile.getvalue()), handler


@pytest.mark.parametrize('action', ['send', 'prepare', 'status'])
@pytest.mark.parametrize('end', [10, 11])
def test_expiry_during_actual_body_intake_rejects_before_operation(lane, action, end):
    service, session, target, clock = lane
    with patch.object(service, 'operate', wraps=service.operate) as operate, \
            patch.object(service.receipts, 'reserve', wraps=service.receipts.reserve) as reserve:
        status, result, handler = request(lane, action, after_read=lambda: clock.__setitem__(0, end))
        assert handler.rfile.reads == 1
        assert status == 400
        assert result == {'error': 'secret-delivery-rejected'}
        operate.assert_not_called()
        reserve.assert_not_called()
    target.exchange.assert_not_called()
    assert 'confirmation' in session.preparations
    assert service.receipts.get('synthetic-delivery', 'human-a') is None


@pytest.mark.parametrize('mutation', ['actor', 'csrf', 'remove', 'replace'])
def test_session_binding_rechecked_after_intake(lane, mutation):
    service, session, target, _ = lane
    def change():
        if mutation == 'actor':
            session.actor = 'human-b'
        elif mutation == 'csrf':
            session.csrf = 'changed-csrf'
        elif mutation == 'remove':
            service.sessions.pop('sid')
        else:
            service.sessions['sid'] = Session('human-a', 'synthetic-csrf', 10)
    with patch.object(service, 'operate', wraps=service.operate) as operate:
        assert request(lane, after_read=change)[0] == 400
        operate.assert_not_called()
    target.exchange.assert_not_called()


def test_unexpired_send_keeps_idempotency_and_one_time_confirmation(lane):
    service, session, target, clock = lane
    status, result, handler = request(lane, after_read=lambda: clock.__setitem__(0, 9))
    assert handler.rfile.reads == 1
    assert status == 200
    assert result['receipt']['status'] == 'saved'
    assert 'confirmation' not in session.preparations
    assert request(lane)[1] == result
    assert request(lane, delivery_id='new-delivery')[0] == 400
    assert service.receipts.get('new-delivery', 'human-a') is None
    target.exchange.assert_called_once()
    target.exchange.assert_called_once_with({'action': 'send', 'target': 'synthetic', 'agent': 'agent',
                                            'runtime': 'runtime', 'key': 'KEY', 'value': 'synthetic-value',
                                            'delivery_id': 'synthetic-delivery', 'version': 'version',
                                            'overwrite': False, 'actor': 'human-a'})


def test_unexpired_prepare_and_status_controls(lane):
    _, _, target, clock = lane
    target.exchange.return_value = {'exists': False, 'version': 'version'}
    assert request(lane, 'prepare', after_read=lambda: clock.__setitem__(0, 9))[0] == 200
    assert request(lane, 'status')[:2] == (200, {'receipt': None})
    target.exchange.assert_called_once()


def test_principal_expiry_after_body_still_rejects(lane):
    _, _, target, clock = lane
    status, _, handler = request(lane, principal=Principal('human-a', 5),
                                 after_read=lambda: clock.__setitem__(0, 5))
    assert status == 400
    assert handler.rfile.reads == 1
    target.exchange.assert_not_called()


@pytest.mark.parametrize('case', ['csrf', 'actor', 'expired'])
def test_initial_auth_checks_still_precede_body(lane, case):
    _, _, target, clock = lane
    kwargs = {}
    if case == 'csrf':
        kwargs['csrf'] = 'wrong'
    elif case == 'actor':
        kwargs['principal'] = Principal('human-b', 100)
    else:
        clock[0] = 10
    status, _, handler = request(lane, **kwargs)
    assert status == 400
    assert handler.rfile.reads == 0
    target.exchange.assert_not_called()
