"""Pinned machine endpoint transport over existing Unix/OpenSSH trust.

Endpoint validation adapted from Herdr's saved-endpoint constraints at
5bd900d88c80d95f5b145397e45bbeea398b8165 (Apache-2.0). No remote
installer, credential copy, host-key bypass or transparent write retry.
"""
from dataclasses import dataclass
from pathlib import Path
import re
from .cockpit_client import request, exchange_deadline, REQUEST_TIMEOUT


@dataclass(frozen=True)
class Endpoint:
    root: Path
    host: str
    state: str

    def call(self, operation, **fields):
        with exchange_deadline(REQUEST_TIMEOUT):
            return self._call(operation, **fields)

    def _call(self, operation, **fields):
        # Identity preflight and any subsequent operation share the inherited
        # absolute deadline. request/exchange puts only the shrinking duration
        # on each wire hop; the peer strips it before strict method dispatch.
        identity = request(self.root, 'snapshot', actor='operator',
                           _endpoint_identity={'host': self.host, 'state': self.state})
        if identity.get('host') != self.host or identity.get('state') != self.state:
            raise ValueError('endpoint identity mismatch; no operation delivered')
        if operation == 'snapshot':
            return identity
        return request(self.root, operation, _endpoint_identity={'host': self.host, 'state': self.state}, **fields)


def ssh_forward_plan(target, local_socket, remote_socket):
    """Return argv only. Starting a remote connection is an explicit operator act.

    local_socket should be <private endpoint root>/runtime/cockpit.sock so the
    normal Endpoint client works unchanged. The existing remote owner must be
    separately installed/approved; -N executes no remote command.
    """
    if not isinstance(target, str) or not re.fullmatch(r'(?:[A-Za-z0-9_][A-Za-z0-9_-]*@)?[A-Za-z0-9][A-Za-z0-9.-]{0,252}', target):
        raise ValueError('invalid exact SSH target; passwords/options forbidden')
    paths = [str(local_socket), remote_socket]
    if any(not isinstance(path, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,100}', path) or '..' in Path(path).parts for path in paths):
        raise ValueError('invalid bounded absolute streamlocal socket path')
    return ['/usr/bin/ssh', '-N', '-T', '-o', 'BatchMode=yes', '-o',
            'StrictHostKeyChecking=yes', '-o', 'ExitOnForwardFailure=yes',
            '-o', 'StreamLocalBindUnlink=no', '-o', 'ConnectTimeout=5',
            '-L', paths[0] + ':' + paths[1], '--', target]
