from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


BASE_URL = "http://127.0.0.1:8765"


def _status(
    path: str,
    *,
    authorization: str | None = None,
    data: bytes | None = None,
    key: str | None = None,
) -> tuple[int, dict[str, object]]:
    headers = {"Content-Type": "application/json"}
    if authorization is not None:
        headers["Authorization"] = authorization
    if key is not None:
        headers["Idempotency-Key"] = key
    request = Request(
        BASE_URL + path,
        headers=headers,
        data=data,
        method="POST" if data is not None else "GET",
    )
    try:
        with urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def main() -> int:
    credential = Path("/data/.arvyx-control-secret").read_text(encoding="ascii").strip()
    if _status("/summary")[0] != 401:
        raise RuntimeError("anonymous protected route was not rejected")
    wrong_authorization = " ".join(("Bearer", "deliberately-wrong"))
    if _status("/summary", authorization=wrong_authorization)[0] != 401:
        raise RuntimeError("wrong bearer was not rejected")
    authorization = " ".join(("Bearer", credential))
    if _status("/summary", authorization=authorization)[0] != 200:
        raise RuntimeError("valid bearer was rejected")
    mutation_status, _ = _status(
        "/tasks",
        authorization=authorization,
        key=os.environ["ARVYX_RESTORE_OPERATION_KEY"],
        data=json.dumps(
            {"title": "restore acceptance probe", "owner": "restore-probe"}
        ).encode("utf-8"),
    )
    if mutation_status != 201:
        raise RuntimeError("protected mutation probe failed")
    audit_status, audit = _status("/audit/events?limit=25", authorization=authorization)
    body = audit.get("body") if isinstance(audit, dict) else None
    chain = body.get("chain") if isinstance(body, dict) else None
    if audit_status != 200 or not isinstance(chain, dict) or not chain.get("ok"):
        raise RuntimeError("audit chain probe failed")
    print("restore-acceptance-ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
