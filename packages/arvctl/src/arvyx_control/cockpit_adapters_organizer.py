"""Existing AMC organizer context adapter, not a replacement Hermes chat runtime.

Call is an explicitly configured authenticated AMC API adapter. No token minting,
ambient credentials, provider invocation, agent config changes or parallel store.
The integrator may pass TeamAuthority._call (same existing API) or an equivalent
configured handle_api_request wrapper; authorization is checked for every call.
"""
import re
from urllib.parse import urlencode
from .control import _reject_secret_shaped_text


class OrganizerContext:
    def __init__(self, call):
        self.call = call

    @staticmethod
    def _agent(agent):
        if not isinstance(agent, str) or not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', agent):
            raise ValueError('exact registered agent ID required')
        return agent

    def read(self, agent):
        return self.call('GET', '/memory/session?' + urlencode({'agent': self._agent(agent)}), None)

    def write(self, agent, content, *, consent, idempotency_key):
        if consent is not True:
            raise ValueError('explicit organizer context consent required')
        if not isinstance(content, str) or not content.strip() or len(content.encode()) > 8192:
            raise ValueError('bounded organizer context required')
        if not isinstance(idempotency_key, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', idempotency_key):
            raise ValueError('explicit write idempotency key required')
        _reject_secret_shaped_text(organizer_context=content)
        return self.call('POST', '/memory/session', {'agent': self._agent(agent), 'content': content,
                                                    'idempotency_key': idempotency_key})
