"""Test callers explicitly exercise the durable review before protected actions."""
from arvyx_control.reviewed_actions import ACTIONS


def reviewed_call(raw,path,body=None,**kwargs):
    if path in ACTIONS and isinstance(body,dict) and body.get('confirmed') is True:
        status,review=raw('actions/prepare',dict(action=path,request=body),**kwargs)
        if status!=200:return status,review
        return raw('actions/commit',dict(consent_id=review['consent_id'],consent_sha256=review['sha256'],confirmed=True),**kwargs)
    return raw(path,body,**kwargs)
