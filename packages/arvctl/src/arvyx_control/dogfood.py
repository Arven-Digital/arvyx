from __future__ import annotations

from dataclasses import dataclass
from http.server import ThreadingHTTPServer
import json
from pathlib import Path, PurePosixPath
import tempfile
import threading
import uuid
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request
from .http_bounds import BoundedOpener

from .api import make_handler
from .security import is_http_url, RELEASE_MANIFEST_RELATIVE, RELEASE_CLASSIFICATIONS
from .evidence import export_evidence
from .importers import import_markdown
from .recall import context_pack, recall
from .vault import init_vault, run_demo


@dataclass(frozen=True)
class DogfoodCheck:
    name: str
    ok: bool
    detail: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, **self.detail}


@dataclass(frozen=True)
class DogfoodResult:
    ok: bool
    checks: list[DogfoodCheck]

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "checks": [check.to_dict() for check in self.checks]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def dogfood_self(
    repo: Path,
    *,
    run_docker: bool = False,
    run_bridge: bool = False,
    mcp_client_evidence: Path | None = None,
    require_provenance: bool = False,
    provenance_dir: Path | None = None,
    _operation=None,
) -> DogfoodResult:
    repo = repo.resolve()
    checks: list[DogfoodCheck] = []
    with tempfile.TemporaryDirectory() as tmp:
        vault = Path(tmp) / "vault"
        init_result = init_vault(vault)
        checks.append(
            DogfoodCheck(
                name="init_vault",
                ok=bool(init_result.files_created),
                detail={"files_created": len(init_result.files_created)},
            )
        )

        # Classify before import: secret scanners cannot identify private prose.
        public_docs = Path(tmp) / "public-docs"
        _stage_public_docs(repo, public_docs)
        docs_import = import_markdown(source=public_docs, vault=vault, project="demo-agent")
        imported = docs_import.imported
        checks.append(
            DogfoodCheck(
                name="import_repo_docs",
                ok=bool(imported) and bool(docs_import.manifest_path),
                detail={
                    "imported_count": len(imported),
                    "manifest_path": docs_import.manifest_path,
                },
            )
        )

        release_recall = recall(
            "deterministic citation backed BM25 hybrid char trigram retrieval",
            vault=vault,
            project="demo-agent",
            max_tokens=140,
        )
        release_sources = [source.path for source in release_recall.sources]
        checks.append(
            DogfoodCheck(
                name="recall_public_docs",
                ok=any(source.endswith("imported/retrieval.md") for source in release_sources),
                detail={"confidence": release_recall.confidence, "sources": release_sources},
            )
        )

        release_pack = context_pack(
            "deterministic citation backed BM25 hybrid char trigram retrieval",
            vault=vault,
            project="demo-agent",
            max_tokens=260,
        )
        checks.append(
            DogfoodCheck(
                name="context_pack_public_docs",
                ok=bool(release_pack.excerpts)
                and any(excerpt.path.endswith("imported/retrieval.md") for excerpt in release_pack.excerpts),
                detail={"excerpt_count": len(release_pack.excerpts)},
            )
        )

        demo = run_demo(vault)
        checks.append(
            DogfoodCheck(
                name="demo_after_self_import",
                ok=demo.ok,
                detail={"check_count": len(demo.checks)},
            )
        )

        evidence = export_evidence(
            repo=repo,
            vault=vault,
            benchmark_cases=repo / "fixtures/recall-benchmark.json",
            run_docker=run_docker,
            run_bridge=run_bridge,
            mcp_client_evidence=mcp_client_evidence,
            require_provenance=require_provenance,
            provenance_dir=provenance_dir,
            _operation=_operation,
        )
        checks.append(
            DogfoodCheck(
                name="evidence_after_self_import",
                ok=all(evidence.recall_benchmarks.get(mode, {}).get("ok") is True
                       for mode in ("lexical", "hybrid")) and evidence.audit["ok"] is True,
                detail={"release_blockers": evidence.release_blockers,
                        "recall_benchmarks": evidence.recall_benchmarks},
            )
        )

    return DogfoodResult(ok=all(check.ok for check in checks), checks=checks)


def _stage_public_docs(repo: Path, destination: Path) -> None:
    """Copy explicitly exportable documentation, never private/unclassified prose.

    This is a local input-selection policy, not permission to publish the tree.
    A malformed classification or symlink input fails closed; contradictory
    in-file privacy notices veto otherwise public-classified bodies.
    """
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key in release classification")
            result[key] = value
        return result

    # Validate the same policy generation used for input selection.
    policy = json.loads((repo / RELEASE_MANIFEST_RELATIVE).read_text(encoding="utf-8"),
                        object_pairs_hook=unique_keys)
    if not isinstance(policy, dict) or policy.get("version") != 1 or not isinstance(policy.get("paths"), dict):
        raise ValueError("valid release classification is required for self dogfood")
    for relative, classification in policy["paths"].items():
        path = PurePosixPath(relative)
        if (not isinstance(classification, str) or classification not in RELEASE_CLASSIFICATIONS
                or path.as_posix() != relative or path.is_absolute()
                or relative in {"", "."} or ".." in path.parts or "\\" in relative):
            raise ValueError("invalid release classification entry")
    destination.mkdir()
    for relative, classification in sorted(policy["paths"].items()):
        if classification not in {"public-approved", "reimplemented-clean-room"}:
            continue
        parts = Path(relative).parts
        if not (relative == "README.md" or (parts[0] == "docs" and relative.endswith(".md"))):
            continue
        source = repo / relative
        if any(repo.joinpath(*parts[:end]).is_symlink() for end in range(1, len(parts) + 1)):
            raise ValueError("public dogfood input must not be a symlink")
        with source.open("rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("public dogfood input exceeds byte budget")
        text = data.decode("utf-8")
        if "PRIVATE:" in text.upper() or "DO NOT PUBLISH" in text.upper():
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def dogfood_live_api(vault: Path) -> DogfoodResult:
    vault = vault.resolve()
    checks: list[DogfoodCheck] = []
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp) / "control-events.jsonl"
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(vault=vault, state=state, bearer_secret="demo"),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"

        try:
            checks.append(_check_health(base_url))
            checks.append(_check_dashboard(base_url))
            checks.append(_check_unauthorized_recall(base_url))
            checks.append(_check_authorized_recall(base_url))
            checks.append(_check_mcp(base_url))
            checks.append(_check_tasks(base_url))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    return DogfoodResult(ok=all(check.ok for check in checks), checks=checks)


def _check_health(base_url: str) -> DogfoodCheck:
    payload = _get_json(f"{base_url}/health")
    return DogfoodCheck(
        name="health",
        ok=payload["body"]["ok"] is True and payload["body"]["service"] == "arvyx-control-api",
        detail={},
    )


def _check_dashboard(base_url: str) -> DogfoodCheck:
    html = _get_text(f"{base_url}/dashboard")
    required_markers = ("Arvyx Control Plane", "Work Board", 'id="agent-orbit"', 'id="kanban"')
    return DogfoodCheck(
        name="dashboard",
        ok=all(marker in html for marker in required_markers),
        detail={"surface": "arvyx-control-plane/v1"},
    )


def _check_unauthorized_recall(base_url: str) -> DogfoodCheck:
    try:
        _post_json(
            f"{base_url}/memory/recall",
            {"question": "which guardrail proxy protects credentials", "project": "demo-agent"},
            authorized=False,
        )
    except HTTPError as exc:
        exc.close()
        return DogfoodCheck(name="unauthorized_recall", ok=exc.code == 401, detail={})
    return DogfoodCheck(name="unauthorized_recall", ok=False, detail={})


def _check_authorized_recall(base_url: str) -> DogfoodCheck:
    payload = _post_json(
        f"{base_url}/memory/recall",
        {"question": "which guardrail proxy protects credentials", "project": "demo-agent", "max_tokens": 120},
    )
    body = payload["body"]
    sources = [source["path"] for source in body["sources"]]
    return DogfoodCheck(
        name="authorized_recall",
        ok=body["confidence"] >= 0.3 and "projects/demo-agent/DECISIONS.md" in sources,
        detail={"confidence": body["confidence"]},
    )


def _check_mcp(base_url: str) -> DogfoodCheck:
    mcp_payload = _post_json(
        f"{base_url}/mcp",
        {"jsonrpc": "2.0", "id": "live-api-smoke", "method": "tools/list"},
    )
    tools = [tool["name"] for tool in mcp_payload["result"]["tools"]]
    return DogfoodCheck(
        name="mcp_tools_list",
        ok="memory.recall" in tools and "control.task_create" not in tools,
        detail={"tool_count": len(tools)},
    )


def _check_tasks(base_url: str) -> DogfoodCheck:
    created = _post_json(f"{base_url}/tasks", {"title": "Live API smoke task", "owner": "vesper"})
    listed = _get_json(f"{base_url}/tasks", authorized=True)
    task_id = created["body"]["task"]["id"]
    task_ids = [task["id"] for task in listed["body"]["tasks"]]
    return DogfoodCheck(name="tasks_round_trip", ok=task_id in task_ids, detail={})


def _require_http_url(url: str) -> None:
    if not is_http_url(url):
        raise ValueError(f"refusing non-http(s) dogfood target: {url}")


def _get_text(url: str, authorized: bool = False) -> str:
    _require_http_url(url)
    request = Request(url, headers=_headers(authorized=authorized), method="GET")
    with BoundedOpener().open(request, timeout=5) as response:
        return _bounded_body(response).decode("utf-8")


def _get_json(url: str, authorized: bool = False) -> dict[str, Any]:
    return json.loads(_get_text(url, authorized=authorized))


def _post_json(url: str, body: dict[str, Any], authorized: bool = True) -> dict[str, Any]:
    _require_http_url(url)
    data = json.dumps(body).encode("utf-8")
    request = Request(url, data=data, headers=_headers(authorized=authorized), method="POST")
    with BoundedOpener().open(request, timeout=5) as response:
        return json.loads(_bounded_body(response).decode("utf-8"))


def _bounded_body(response) -> bytes:
    data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("dogfood response exceeds limit")
    return data


def _headers(authorized: bool) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if authorized:
        headers["Authorization"] = "Bearer demo"
        headers["Idempotency-Key"] = f"dogfood-{uuid.uuid4().hex}"
    return headers
