"""Exact watchdog HOLD notification wire format, shared by all consumers."""


def hold_alert_body(*, target: str, subject_type: str, subject_id: str, hold_reason: str) -> str:
    """Current producer format: the recorded reason followed by one period."""
    return f"target={target} subject={subject_type} {subject_id}; {hold_reason}."


def operator_hold_alert_bodies(*, target: str, subject_type: str, subject_id: str,
                               hold_reason: str) -> tuple[str, str]:
    """Accept only the canonical body and the historical undotted body.

    Never normalize the recorded reason or strip punctuation from input. Agent
    investigation guidance is not an operator notification and is not accepted.
    """
    canonical = hold_alert_body(target=target, subject_type=subject_type,
                               subject_id=subject_id, hold_reason=hold_reason)
    return canonical, canonical[:-1]
