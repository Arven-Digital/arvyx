#!/usr/bin/env python3
"""Produce real external stdio MCP client evidence for the ``mcp_client_real`` gate.

Why this exists
---------------
The public-release gate requires a signed evidence file recorded from a real
external stdio MCP client and bound to the exact release tree. Two things made
that structurally impossible before this script:

* ``arvyx evidence mcp-client`` drives the server through arvyx's own CLI, so the
  file records ``client=arvyx-cli`` and the gate rejects it as self-attested.
* The only pinned signer available to an operator is the temporary local drill
  key, which is deliberately absent from ``docs/release-grade-signers.allowed``.
  A locally signed file therefore verifies but can never open a public release.

This script is what the ``release-provenance`` workflow runs *inside CI*, on the
exact tagged commit, so the release pipeline produces the evidence and signs it
with the CI principal, instead of an operator shell doing it on a laptop.

What the client actually is
---------------------------
The client is the official Model Context Protocol **Python SDK** stdio client
(``mcp.client.stdio``): a third-party implementation of the protocol, not arvyx's
own CLI. It is *not* an agent-UI client such as Claude Desktop or Codex, and the
evidence says so in ``client`` and ``notes``. Nothing here claims more than what
ran: ``client_version`` and ``protocol_version`` are recorded, and ``notes`` records
the workflow name, ref type and ref name when ``GITHUB_WORKFLOW`` is set and says
"local run" otherwise, rather than calling every GitHub Actions run a release.

What it measures
----------------
``result.private_paths_leaked`` is **measured, never asserted**: the ``initialize``,
``tools/list`` and ``memory.recall`` responses are serialized and scanned against
the same private-marker set the gate uses, an absolute repository or vault path in
that traffic counts as a leak, and a positive hit fails the run. The server is
launched with ``cwd`` at the repository root and the same repository-relative vault
argument that the evidence records, so a clean run stays clean, a real leak is
visible, and the signed ``command`` describes the argument that actually ran.

Fail-closed
-----------
If the SDK is missing, the handshake fails, recall returns no answers or no
sources, a private marker is found, or the resulting file would not pass
``validate_mcp_client_evidence``, this script exits non-zero. It never falls back
to arvyx's self client and never invents flags.

Usage
-----
    python3 scripts/mcp_client_real_evidence.py --output dist/evidence.mcp-client.json
    python3 scripts/mcp_client_real_evidence.py --check dist/evidence.mcp-client.json --release
    # audit: keep the traffic and let anyone replay the leak scan
    python3 scripts/mcp_client_real_evidence.py --output e.json --capture-out audit/capture.json
    python3 scripts/mcp_client_real_evidence.py --check e.json --verify-capture audit/capture.json
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "arvctl" / "src"))

from arvyx_control.mcp_client_evidence import (  # noqa: E402
    DEFAULT_MAX_AGE_HOURS,
    PRIVATE_MARKERS,
    validate_mcp_client_evidence,
    validate_release_mcp_client_evidence,
)

# The recorded client identity. Free text by design in the gate, so it must be
# accurate: this is the official MCP Python SDK client, nothing else.
CLIENT_ID = "python-mcp-sdk"
DEFAULT_VAULT = "fixtures/synthetic-vault"
DEFAULT_PROFILE = "read-only"
RECALL_QUESTION = "what did we decide about safe mcp bridge"
RECALL_PROJECT = "demo-agent"
PER_CALL_TIMEOUT_SECONDS = 120
# What the leak scan actually looked at. Recorded so a reader can see the boundary of
# the measurement instead of assuming it covered everything.
SCAN_SCOPE = ("initialize", "tools/list", "memory.recall")
TOTAL_TIMEOUT_SECONDS = PER_CALL_TIMEOUT_SECONDS * 3


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else ""


def capture_digest(captured: str) -> tuple[str, int]:
    """sha256 and byte length of the captured traffic, as recorded in the evidence."""
    encoded = captured.encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


def marker_set_digest() -> str:
    """sha256 of the marker set the scan used, without putting the markers in the file."""
    joined = "\n".join(sorted(PRIVATE_MARKERS)).encode("utf-8")
    return hashlib.sha256(joined).hexdigest()


def scan_for_private_markers(captured: str) -> list[str]:
    """Return the private markers present in captured client traffic.

    This is the measured half of ``result.private_paths_leaked``: the gate's own
    tripwire must be computed from the bytes the client actually received, never
    asserted as a constant.
    """
    return sorted({marker for marker in PRIVATE_MARKERS if marker in captured})


def scan_capture(
    captured: str,
    *,
    repo: Path | None = None,
    vault: Path | None = None,
) -> list[str]:
    """The single leak measurement, shared by producing and by replaying.

    Beyond the gate's marker set, the producer counts an echo of the absolute
    repository or vault path as a leak: the server runs with ``cwd`` at the
    repository root, so a path only this process knows must never come back in
    the traffic. Replay calls this same function with the same local paths, so a
    replay measures what the producer measured instead of a weaker subset.

    The absolute-path half is bound to the local checkout path, and that is worth
    stating plainly: a replay run from a different directory compares against a
    different absolute string. The marker set is the path-independent half and
    still applies unchanged.
    """
    leaked = set(scan_for_private_markers(captured))
    for absolute in (repo, vault):
        if absolute is None:
            continue
        text = absolute.as_posix()
        if text and text in captured:
            leaked.add(text)
    return sorted(leaked)


def _require_sdk():
    try:
        from mcp import ClientSession, StdioServerParameters  # noqa: PLC0415
        from mcp.client.stdio import stdio_client  # noqa: PLC0415
    except ImportError as exc:  # fail closed, never downgrade to the self client
        raise SystemExit(
            "the MCP Python SDK client is not installed; install the pinned evidence-client "
            f"lock (requirements/mcp-client.lock) instead of falling back to arvyx-cli: {exc}"
        ) from exc
    return ClientSession, StdioServerParameters, stdio_client


def _argv_of(plan: dict[str, object]) -> list[object]:
    argv = plan["argv"]
    if not isinstance(argv, list):  # pragma: no cover - launch_plan always returns a list
        raise TypeError("launch plan is malformed")
    return argv


@contextlib.contextmanager
def isolated_client_environment():
    """CLI-only isolation before SDK import and its default-env merge.

    This temporarily replaces the process environment, so callers must not run
    concurrent tasks that depend on ambient environment variables. This is not
    a filesystem sandbox or a way to make an untrusted SDK safe.
    """
    previous = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="amc-mcp-evidence-") as temporary:
        root = Path(temporary)
        client_home = root / "client"
        server_home = root / "server"
        scratch = root / "tmp"
        for directory in (client_home, server_home, scratch):
            directory.mkdir(mode=0o700)

        def environment(home: Path) -> dict[str, str]:
            result = {
                "PATH": os.defpath, "LANG": "C.UTF-8", "HOME": str(home),
                "USERPROFILE": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
                "XDG_CACHE_HOME": str(home / ".cache"),
                "XDG_DATA_HOME": str(home / ".local" / "share"),
                "XDG_STATE_HOME": str(home / ".local" / "state"),
                "TMPDIR": str(scratch), "TMP": str(scratch), "TEMP": str(scratch),
                "PYTHONNOUSERSITE": "1", "PYTHONUTF8": "1",
            }
            # Windows subprocess creation needs its OS installation directory;
            # no proxy, credentials, shell startup, or provider config is copied.
            if os.name == "nt" and previous.get("SYSTEMROOT"):
                result["SYSTEMROOT"] = previous["SYSTEMROOT"]
            return result

        os.environ.clear()
        os.environ.update(environment(client_home))
        try:
            yield environment(server_home)
        finally:
            os.environ.clear()
            os.environ.update(previous)


async def _run_client(*, repo: Path, vault: Path) -> dict[str, object]:
    # The SDK itself and stdio_client's default environment see only this
    # allowlist; passing env= alone is insufficient when an SDK merges defaults.
    with isolated_client_environment() as server_environment:
        return await _run_isolated_client(repo=repo, vault=vault, server_environment=server_environment)


async def _run_isolated_client(*, repo: Path, vault: Path,
                               server_environment: dict[str, str]) -> dict[str, object]:
    ClientSession, StdioServerParameters, stdio_client = _require_sdk()

    # Measure the implementation actually loaded, before executing its client.
    provenance = _sdk_provenance(ClientSession, StdioServerParameters, stdio_client)
    plan = launch_plan(repo=repo, vault=vault)
    env = {**server_environment, "PYTHONPATH": str(repo / "packages" / "arvctl" / "src")}
    # `cwd` plus a relative vault path keeps any path the server echoes back
    # repository-relative, which is what makes the leak scan below meaningful.
    # The vault argument is the same value `launch_plan()` records, so the signed
    # `command` field describes the argument that really ran.
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(part) for part in _argv_of(plan)],
        env=env,
        cwd=str(plan["cwd"]),
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await asyncio.wait_for(
                session.initialize(), timeout=PER_CALL_TIMEOUT_SECONDS
            )
            tools = await asyncio.wait_for(
                session.list_tools(), timeout=PER_CALL_TIMEOUT_SECONDS
            )
            tool_names = {tool.name for tool in tools.tools}
            call = await asyncio.wait_for(
                session.call_tool(
                    "memory.recall",
                    {
                        "question": RECALL_QUESTION,
                        "project": RECALL_PROJECT,
                        "max_tokens": 120,
                    },
                ),
                timeout=PER_CALL_TIMEOUT_SECONDS,
            )

    structured = getattr(call, "structured_content", None)
    answer = ""
    sources = 0
    if isinstance(structured, dict):
        answer = str(structured.get("answer") or "")
        sources = len(structured.get("sources") or [])

    # Measure the leak tripwire over the bytes the client actually received:
    # handshake, tool listing and recall traffic alike.
    captured = json.dumps(
        {
            "initialize": init.model_dump(mode="json", by_alias=True),
            "tools": tools.model_dump(mode="json", by_alias=True),
            "recall": call.model_dump(mode="json", by_alias=True),
        },
        sort_keys=True,
    )
    # The server runs with cwd at the repository root, so an echo of an absolute
    # path that only this process knows is a leak even though the launched vault
    # argument is relative. `verify_capture` calls the same function, so the
    # measurement a reader replays is the measurement recorded here.
    leaked = scan_capture(captured, repo=repo, vault=vault)

    protocol_version = str(getattr(init, "protocol_version", "") or "")

    return {
        "tools_list_ok": "memory.recall" in tool_names,
        "recall_ok": bool(answer) and not bool(getattr(call, "is_error", True)),
        "sources_returned": sources > 0,
        "private_paths_leaked": bool(leaked),
        "leaked_markers": leaked,
        "protocol_version": protocol_version,
        "captured": captured,
        "client_provenance": provenance,
    }


def _sdk_provenance(*implementations) -> dict[str, str]:
    """Bind imported client objects to installed distribution-owned source bytes.

    The pinned release signer attests this observation; no display label is an
    execution proof. Refuse shadow modules outside the installed distribution.
    """
    import inspect
    from importlib.metadata import distribution

    dist = distribution("mcp")
    owned = {Path(str(dist.locate_file(entry))).resolve() for entry in dist.files or ()}
    observed = {}
    for implementation in implementations:
        source = inspect.getsourcefile(inspect.unwrap(implementation))
        if source is None or Path(source).resolve() not in owned:
            raise ValueError("MCP client implementation is not distribution-owned")
        path = Path(source).resolve()
        observed[path.relative_to(Path(str(dist.locate_file(""))).resolve()).as_posix()] = (
            hashlib.sha256(path.read_bytes()).hexdigest()
        )
    digest = hashlib.sha256(json.dumps(observed, sort_keys=True).encode("utf-8")).hexdigest()
    return {"kind": "third-party-sdk", "distribution": "mcp",
            "version": dist.version, "implementation_sha256": digest}


def _sdk_version() -> str:
    try:
        return version("mcp")
    except PackageNotFoundError:
        return ""


def launch_plan(*, repo: Path, vault: Path) -> dict[str, object]:
    """The single source for what the server is launched with and what is recorded.

    The vault argument must be the same value in both places: the evidence's
    ``command`` field claims to describe the run, so a recorded argument that was
    not executed would be a signed misstatement. A vault outside the repository
    keeps its absolute path (and the leak scan then looks for that absolute path),
    while an in-repository vault is launched repository-relative with ``cwd`` at
    the repository root.
    """
    try:
        vault_arg = vault.relative_to(repo).as_posix()
        outside_repo = False
    except ValueError:
        vault_arg = vault.as_posix()
        outside_repo = True
    argv = [
        "-m",
        "arvyx_control.cli",
        "mcp",
        "--profile",
        DEFAULT_PROFILE,
        "--vault",
        vault_arg,
    ]
    interpreter = Path(sys.executable).name
    return {
        "command": interpreter,
        "argv": argv,
        "cwd": repo,
        "vault_arg": vault_arg,
        "outside_repo": outside_repo,
        "display": (
            f"{interpreter} -m arvyx_control.cli mcp "
            f"--profile {DEFAULT_PROFILE} --vault {vault_arg}"
        ),
    }


def _notes() -> str:
    workflow = os.environ.get("GITHUB_WORKFLOW", "")
    if workflow:
        ref_type = os.environ.get("GITHUB_REF_TYPE", "unknown")
        ref_name = os.environ.get("GITHUB_REF_NAME", "unknown")
        where = (
            f"GitHub Actions workflow {workflow!r} "
            f"(ref_type={ref_type}, ref_name={ref_name})"
        )
    else:
        where = "a local run (no GITHUB_WORKFLOW in the environment)"
    return (
        f"Recorded by {where} with the official MCP Python SDK stdio client against the "
        "read-only AMC MCP server. This is a third-party protocol client, not an agent UI; "
        "it proves the stdio surface is consumable by external client code on this exact "
        "tree, and result.private_paths_leaked is measured from the captured initialize, "
        "tools/list and memory.recall responses."
    )


def write_private_file(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` in a file that is never readable by others.

    ``Path.write_text`` creates the destination with the process umask, so a
    capture holding raw client traffic is world-readable for the window between
    the write and a following ``chmod``, and stays that way if the process dies
    inside that window. Creating a private temporary file and renaming it into
    place means no such copy ever exists: ``mkstemp`` opens at ``0600`` and
    ``os.replace`` keeps the mode.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def _produce(
    *,
    repo: Path,
    vault: Path,
    output: Path | None,
    json_output: bool,
    capture_out: Path | None = None,
) -> int:
    if output is None:
        print("error: --output is required to produce evidence", file=sys.stderr)
        return 2
    git_head = _git(repo, "rev-parse", "HEAD")
    git_tree = _git(repo, "rev-parse", "HEAD^{tree}")
    if not git_head or not git_tree:
        print("error: cannot read git HEAD/tree for the evidence binding", file=sys.stderr)
        return 1

    try:
        result = asyncio.run(
            asyncio.wait_for(_run_client(repo=repo, vault=vault), timeout=TOTAL_TIMEOUT_SECONDS)
        )
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - any client failure must fail closed
        print(f"error: external MCP client run failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    provenance = result.get("client_provenance")
    if not isinstance(provenance, dict):
        print("error: measured client provenance is required", file=sys.stderr)
        return 1
    captured = str(result.get("captured") or "")
    digest, captured_bytes = capture_digest(captured)
    payload = {
        "schema_version": 1,
        "client": CLIENT_ID,
        "client_provenance": provenance,
        "client_version": provenance.get("version", ""),
        "protocol_version": str(result.get("protocol_version") or ""),
        "checked_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "git_head": git_head,
        "git_tree": git_tree,
        "transport": "stdio",
        "command": str(launch_plan(repo=repo, vault=vault)["display"]),
        "result": {
            "tools_list_ok": bool(result["tools_list_ok"]),
            "recall_ok": bool(result["recall_ok"]),
            "sources_returned": bool(result["sources_returned"]),
            "private_paths_leaked": bool(result["private_paths_leaked"]),
        },
        # What the scan looked at and which bytes it looked at, as digests: the traffic
        # itself can carry private content, so it is not put in a signed release
        # artifact, but a reader can still bind the measurement to exact bytes and
        # replay it with --verify-capture against a locally kept capture.
        "scan_scope": list(SCAN_SCOPE),
        "capture_sha256": digest,
        "capture_bytes": captured_bytes,
        "marker_set_sha256": marker_set_digest(),
        "notes": _notes(),
    }

    if capture_out is not None:
        # Raw client traffic: it must never exist as a world-readable file, not
        # even for the instant between creating it and chmod'ing it.
        write_private_file(capture_out, captured)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

    validation = validate_mcp_client_evidence(
        output,
        expected_git_head=git_head,
        expected_git_tree=git_tree,
        max_age_hours=DEFAULT_MAX_AGE_HOURS,
    )
    ok = bool(validation.get("ok")) and all(
        payload["result"][flag] is True
        for flag in ("tools_list_ok", "recall_ok", "sources_returned")
    ) and payload["result"]["private_paths_leaked"] is False

    if json_output:
        print(
            json.dumps(
                {"ok": ok, "validation": validation, "payload": payload},
                sort_keys=True,
            )
        )
    else:
        print(f"client           : {CLIENT_ID} {payload['client_version']}")
        print(f"protocol_version : {payload['protocol_version']}")
        print(f"command          : {payload['command']}")
        print(f"git_head/git_tree: {git_head[:12]} / {git_tree[:12]}")
        print(f"result           : {payload['result']}")
        print(f"scan_scope       : {', '.join(payload['scan_scope'])}")
        print(f"capture          : sha256={payload['capture_sha256'][:16]}... bytes={captured_bytes}")
        print(f"output           : {output}")
        for error in validation.get("errors", []):
            print(f"error: {error}")
        if result.get("leaked_markers"):
            print(f"error: private markers found in captured client traffic: {result['leaked_markers']}")
        print("verdict          :", "ok" if ok else "FAILED")
    if not ok:
        print(
            "error: produced evidence would not pass the release gate; refusing to bless it",
            file=sys.stderr,
        )
        return 1
    return 0


def verify_capture(
    *,
    evidence: Path,
    capture: Path,
    repo: Path,
    vault: Path,
) -> tuple[bool, list[str], dict[str, object]]:
    """Replay the leak measurement from a locally kept capture.

    The signed evidence carries digests, not the traffic, because the traffic can
    contain private content. A reader who kept the capture (``--capture-out``) can
    replay the exact scan: the bytes must hash to the recorded digest, the record
    must name the same scan configuration this replay uses, and the scan must come
    back clean. This is the honest form of "independently repeatable": it repeats
    the measurement over the exact bytes that were measured, and it fails closed
    when the capture is missing, altered or dirty, or when the evidence does not
    record enough to say *which* measurement it is claiming.

    ``repo`` and ``vault`` are required because the producer counts an echo of
    those absolute paths as a leak. A replay without the same local path context
    would quietly check less than the producer did.
    """
    errors: list[str] = []
    details: dict[str, object] = {"path": str(capture)}
    try:
        payload = json.loads(evidence.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        return False, [f"cannot read evidence file: {exc}"], details
    if not isinstance(payload, dict):
        return False, ["evidence must be a JSON object"], details
    recorded = payload.get("capture_sha256")
    if not isinstance(recorded, str) or not recorded:
        return False, ["evidence records no capture_sha256, so nothing can be replayed"], details

    # The rest of the measurement record is required rather than optional. A digest
    # with no marker-set identity, no scope and no byte count can otherwise be
    # "replayed" to a success against a different scan configuration than the one
    # the evidence claims to have used.
    recorded_bytes = payload.get("capture_bytes")
    if not isinstance(recorded_bytes, int) or isinstance(recorded_bytes, bool) or recorded_bytes < 0:
        errors.append(
            "evidence records no usable capture_bytes, so the replay is not bound to a length"
        )
    recorded_markers = payload.get("marker_set_sha256")
    if not isinstance(recorded_markers, str) or not recorded_markers:
        errors.append(
            "evidence records no marker_set_sha256, so the replay cannot prove which marker set ran"
        )
    elif recorded_markers != marker_set_digest():
        errors.append("marker_set_sha256 does not match the marker set this replay scans with")
    recorded_scope = payload.get("scan_scope")
    if not isinstance(recorded_scope, list) or list(recorded_scope) != list(SCAN_SCOPE):
        errors.append(
            "scan_scope must record the supported scope "
            f"({', '.join(SCAN_SCOPE)}), not {recorded_scope!r}"
        )
    details.update({"marker_set_sha256": recorded_markers, "scan_scope": recorded_scope})

    try:
        captured = capture.read_text(encoding="utf-8")
    except OSError as exc:
        return False, [f"cannot read capture file: {exc}"], details
    digest, captured_bytes = capture_digest(captured)
    details.update({"capture_sha256": digest, "capture_bytes": captured_bytes})
    if digest != recorded:
        errors.append("capture does not hash to the digest recorded in the evidence")
    if isinstance(recorded_bytes, int) and not isinstance(recorded_bytes, bool):
        if recorded_bytes != captured_bytes:
            errors.append("capture byte length differs from the recorded length")
    # Same function the producer measured with, same local path context.
    leaked = scan_capture(captured, repo=repo, vault=vault)
    details["leaked_markers"] = leaked
    if leaked:
        errors.append(f"private markers present in the replayed capture: {leaked}")
    result = payload.get("result")
    if not isinstance(result, dict) or result.get("private_paths_leaked") is not False:
        errors.append("evidence does not record a clean leak flag")
    return not errors, errors, details


def _check(
    *,
    path: Path,
    repo: Path,
    vault: Path,
    release: bool,
    json_output: bool,
    capture: Path | None = None,
) -> int:
    validation = (validate_release_mcp_client_evidence(path, repo=repo)
                  if release else validate_mcp_client_evidence(path))
    errors = list(validation.get("errors", []))
    principal = validation.get("attestation_principal")
    self_attested = bool(validation.get("self_attested"))
    if self_attested and not release:
        errors.append("client is arvyx's own self client")
    replay: dict[str, object] | None = None
    if capture is not None:
        replayed, replay_errors, replay_details = verify_capture(
            evidence=path, capture=capture, repo=repo, vault=vault
        )
        replay = replay_details
        if not replayed:
            errors.extend(replay_errors)
    ok = bool(validation.get("ok")) and not errors
    if json_output:
        print(json.dumps({"ok": ok, "principal": principal, "errors": errors,
                          "capture_replay": replay, "validation": validation}, sort_keys=True))
    else:
        print(f"path      : {path}")
        print(f"client    : {validation.get('client')} | self_attested: {self_attested}")
        print(f"principal : {principal}")
        if replay is not None:
            print(
                "replay    : capture sha256="
                f"{replay.get('capture_sha256')} bytes={replay.get('capture_bytes')} "
                f"markers={replay.get('leaked_markers')}"
            )
        for error in errors:
            print(f"error: {error}")
        print("verdict   :", "ok" if ok else "FAILED")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Produce or check real external stdio MCP client evidence for the "
            "mcp_client_real release gate."
        )
    )
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--vault", type=Path, default=None, help=f"default: {DEFAULT_VAULT}")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--check", type=Path, default=None, help="validate an existing file instead")
    parser.add_argument(
        "--release",
        action="store_true",
        help="with --check: read the file the way the release gate does (tree, signature, grade)",
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument(
        "--capture-out",
        type=Path,
        default=None,
        help=(
            "also write the raw captured traffic here (mode 0600) so the leak scan can be "
            "replayed; keep it local, it is never a release artifact"
        ),
    )
    parser.add_argument(
        "--verify-capture",
        type=Path,
        default=None,
        help="with --check: replay the recorded leak measurement from a saved capture",
    )
    args = parser.parse_args()

    repo = args.repo.resolve()
    # Resolved before the `--check` branch: replaying a capture needs the same local
    # path context the producer measured with.
    vault = args.vault.resolve() if args.vault else (repo / DEFAULT_VAULT)
    if args.check is not None:
        return _check(
            path=args.check,
            repo=repo,
            vault=vault,
            release=args.release,
            json_output=args.json_output,
            capture=args.verify_capture,
        )
    if args.verify_capture is not None:
        print("error: --verify-capture is only meaningful with --check", file=sys.stderr)
        return 2
    if not vault.is_dir():
        print(f"error: synthetic vault not found: {vault}", file=sys.stderr)
        return 1
    return _produce(
        repo=repo,
        vault=vault,
        output=args.output,
        json_output=args.json_output,
        capture_out=args.capture_out,
    )


if __name__ == "__main__":
    raise SystemExit(main())
