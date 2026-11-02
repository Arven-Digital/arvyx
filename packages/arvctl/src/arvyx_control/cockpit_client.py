"""Explicit, isolated human-only local cockpit pilot launcher."""
from __future__ import annotations

import argparse
import base64
import json
import math
import os
from pathlib import Path
import select
import socket
import sys
import time
from contextlib import contextmanager
from contextvars import ContextVar

from .control import create_task
from .vault import init_vault


def initialize(root: Path):
    root = root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.stat().st_mode & 0o077:
        raise ValueError("pilot home must be owner-private")
    marker = root / "pilot.json"
    expected = {"schema": 1, "project": "demo-agent", "host": "laptop-a", "scope": "isolated-local-pilot"}
    if marker.exists():
        if json.loads(marker.read_text()) != expected:
            raise ValueError("unknown pilot configuration")
    else:
        if (root / "vault").exists() or (root / "events.jsonl").exists():
            raise ValueError("refusing to adopt existing non-pilot state")
        init_vault(root / "vault")
        marker.write_text(json.dumps(expected) + "\n")
    return expected


REQUEST_TIMEOUT = 5
REQUEST_CAP = 16384
RESPONSE_CAP = 1048576
_deadline = ContextVar("cockpit_deadline", default=None)


def validate_budget(seconds):
    if type(seconds) not in (int, float) or not 0 < seconds <= REQUEST_TIMEOUT or not math.isfinite(seconds):
        raise ValueError('finite positive cockpit budget <= 5 seconds required')
    return seconds


def checkpoint():
    """Check the current absolute deadline without creating a new allowance."""
    end = _deadline.get()
    return remaining(end) if end is not None else REQUEST_TIMEOUT


@contextmanager
def deadline_lock(lock):
    """Bound Python lock admission; never leave a background worker behind."""
    if not lock.acquire(timeout=checkpoint()):
        raise TimeoutError('cockpit lock deadline exceeded')
    try:
        checkpoint()
        yield
    finally:
        lock.release()


@contextmanager
def exchange_deadline(seconds):
    end = time.monotonic() + validate_budget(seconds)
    inherited = _deadline.get()
    token = _deadline.set(min(end, inherited) if inherited is not None else end)
    try:
        yield _deadline.get()
    finally:
        _deadline.reset(token)


@contextmanager
def absolute_deadline(end):
    """Install an owner-local monotonic deadline; never serialize clock epochs."""
    inherited = _deadline.get()
    token = _deadline.set(min(end, inherited) if inherited is not None else end)
    try:
        checkpoint()
        yield _deadline.get()
    finally:
        _deadline.reset(token)


@contextmanager
def reserved_deadline(seconds, reserve):
    """Bound read fanout while retaining the inherited response budget."""
    inherited = _deadline.get()
    end = time.monotonic() + seconds
    if inherited is not None:
        end = min(end, inherited - reserve)
    token = _deadline.set(end)
    try:
        remaining(end)
        yield end
    finally:
        _deadline.reset(token)


def remaining(end):
    seconds = end - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("cockpit total deadline exceeded; outcome may be uncertain; not retried")
    return seconds


def send_frame(client, payload, end, cap):
    remaining(end)
    if len(payload) > cap or not payload.endswith(b"\n"):
        raise ValueError("frame exceeds cap or missing newline")
    client.settimeout(remaining(end))
    client.sendall(payload)
    remaining(end)


def receive_frame(client, end, cap):
    raw = bytearray()
    while len(raw) < cap:
        client.settimeout(remaining(end))
        chunk = client.recv(min(65536, cap - len(raw)))
        remaining(end)
        if not chunk:
            break
        raw.extend(chunk)
        if b"\n" in chunk:
            return bytes(raw).split(b"\n", 1)[0] + b"\n"
    raise ValueError("frame exceeds cap or missing newline")


def exchange(endpoint, payload, *, owner_budget=True):
    """Bounded single-frame exchange.

    ``owner_budget`` propagates the remaining deadline as the AMC owner's private
    ``_budget_seconds`` envelope field. A foreign protocol (the native frontend's
    JSON API) must receive its exact request: the same total deadline applies,
    but no AMC metadata is injected into that request.
    """
    envelope = json.loads(payload)
    if not isinstance(envelope, dict):
        raise ValueError('request must be an object')
    if not owner_budget and '_budget_seconds' in envelope:
        raise ValueError('owner budget metadata is not part of a foreign request')
    supplied = validate_budget(envelope.pop('_budget_seconds', REQUEST_TIMEOUT))
    with exchange_deadline(supplied) as end:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(remaining(end))
            client.connect(str(endpoint))
            if owner_budget:
                envelope['_budget_seconds'] = remaining(end)
            payload = json.dumps(envelope).encode() + b'\n'
            send_frame(client, payload, end, REQUEST_CAP)
            return receive_frame(client, end, RESPONSE_CAP)


def request(root: Path, operation: str, **fields):
    result = json.loads(exchange(root / "runtime/cockpit.sock",
                                 json.dumps(dict(operation=operation, **fields)).encode() + b"\n"))
    if not result["ok"]:
        raise ValueError(result["error"])
    return result["result"]


def attach(root: Path, sid: str, *, takeover=False, existing_lease=None):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError("attach requires an interactive terminal")
    import termios
    import tty
    if request(root, "capabilities").get("protocol") != 2:
        raise ValueError("incompatible cockpit protocol; do not attach")
    original = termios.tcgetattr(sys.stdin)
    lease = existing_lease if existing_lease is not None else request(root, "attach", sid=sid, actor="operator", takeover=takeover)
    if existing_lease is not None and (type(lease) is not dict or lease.get('id')!=sid or not isinstance(lease.get('attachment'),str)):
        raise ValueError('exact existing attachment lease required')
    token = lease["attachment"]
    cursor = 0
    dimensions = None
    try:
        tty.setraw(sys.stdin.fileno())
        while True:
            size = os.get_terminal_size(sys.stdout.fileno())
            if dimensions != size:
                request(root, "resize", sid=sid, rows=size.lines, columns=size.columns, actor="operator", attachment=token)
                dimensions = size
            result = request(root, "read", sid=sid, cursor=cursor, actor="operator", binary=True, attachment=token)
            if result["truncated"]:
                # Discard the discontinuous tail: it may start inside an escape sequence.
                os.write(sys.stdout.fileno(), b"\x1bc\r\n[REPLAY GAP: retained output skipped; terminal reset. Redraw the application manually.]\r\n")
            else:
                output = base64.b64decode(result["data"], validate=True)
                while output:
                    count = os.write(sys.stdout.fileno(), output)
                    if count <= 0:
                        raise OSError("terminal output closed")
                    output = output[count:]
            cursor = result["cursor"]
            status = result.get("input_status", {})
            if status.get("input_error"):
                raise ValueError("PTY input closed/failed; queued input may be lost; reconcile manually")
            if select.select([sys.stdin], [], [], .05)[0]:
                data = os.read(sys.stdin.fileno(), 1024)
                if not data or b"\x1d" in data:
                    break
                ack = request(root, "write", sid=sid, data=base64.b64encode(data).decode("ascii"), attachment=token, actor="operator")
                if not ack["accepted"]:
                    raise ValueError("input rejected (backpressure/failure); not retried; reconcile manually")
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, original)
        try:
            request(root, "detach", sid=sid, actor="operator", attachment=token)
        except (ValueError, OSError):
            pass  # A newer explicit takeover must not be detached by this client.
        print("\r\nDetached. The shell remains alive.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home() / ".local/state/amc-cockpit-pilot")
    commands = parser.add_subparsers(dest="command", required=True)
    organizer = commands.add_parser('organizer', help='Existing authenticated AMC session context (not native live chat)')
    organizer.add_argument('agent')
    organizer.add_argument('--content')
    organizer.add_argument('--consent', action='store_true')
    organizer.add_argument('--idempotency-key')
    native_organizer = commands.add_parser('native-organizer', help='Open configured persistent native organizer record; never auto-start its provider')
    native_organizer.add_argument('agent')
    native = commands.add_parser('native', help='Bind an exact native conversation and explicitly resume; never infer identity from output')
    native.add_argument('action', choices=['bind', 'status', 'resume'])
    native.add_argument('sid')
    native.add_argument('--tool', choices=['codex', 'claude', 'hermes', 'gemini', 'fixture'])
    native.add_argument('--conversation')
    native.add_argument('--fixture', action='store_true')
    native.add_argument('--allow-provider', action='store_true', help='Explicitly authorize this native provider process launch')
    draft = commands.add_parser('draft', help='Store a local draft; reconnection NEVER sends it')
    draft.add_argument('action', choices=['stage', 'list', 'send'])
    draft.add_argument('identifier', help='Session ID for stage/list; draft ID for send')
    draft.add_argument('--text')
    draft.add_argument('--context', default='')
    draft.add_argument('--context-consent', action='store_true')
    draft.add_argument('--consent', help='Exact content SHA-256 returned by stage')
    draft.add_argument('--attachment')
    draft.add_argument('--session', help='Exact host:session binding required for fleet draft send')
    archive = commands.add_parser('archive', help='Explicit private transcript records, not curated memory')
    archive.add_argument('sid')
    archive.add_argument('--event-id')
    archive.add_argument('--source', choices=['native-transcript', 'operator-note', 'terminal-preview'])
    archive.add_argument('--text')
    archive.add_argument('--after', type=int, default=0)
    autopilot_help = ('Explicit local delegation; no runner by default. An owner with an '
                      'explicitly configured operator driver can execute active delegations; '
                      'assignment does not configure a driver or authorize provider access.')
    autopilot = commands.add_parser('autopilot', help=autopilot_help,
                                   description=autopilot_help)
    autopilot.add_argument('action', choices=['assign', 'status', 'take-control'])
    autopilot.add_argument('sid')
    autopilot.add_argument('--operator')
    autopilot.add_argument('--goal')
    autopilot.add_argument('--limits')
    stop = commands.add_parser('stop-operator', help='Explicit fleet operator revocation scopes; never interrupts native children')
    stop.add_argument('scope', choices=['session', 'host', 'operator', 'fleet'])
    stop.add_argument('--target')
    layout = commands.add_parser('layout', help='Mirror ordered session panels and focus with revision fencing')
    layout.add_argument('--revision', required=True, type=int)
    layout.add_argument('--selected')
    layout.add_argument('panels', nargs='*')
    reconcile = commands.add_parser('reconcile-input', help='Attest native editor is clean after manual reconciliation; never sends keys')
    reconcile.add_argument('sid')
    reconcile.add_argument('--attachment', required=True)
    reconcile.add_argument('--confirmed-clean', action='store_true')
    commands.add_parser("init", help="Initialize isolated synthetic AMC vault/state")
    serve_command = commands.add_parser("serve", help="Run only this pilot's local Unix-socket PTY owner")
    serve_command.add_argument('--execution-policy', type=Path, help='Explicit private owner ExecutionPolicy JSON; absent means deny launch')
    commands.add_parser("list", help="List fixed project/task/workspace sessions")
    commands.add_parser("ui", help="Open the local multi-session terminal navigator")
    web = commands.add_parser("web", help="Export team snapshot or open capability-protected live local dashboard")
    web.add_argument("--live", action="store_true", help="Serve only on 127.0.0.1 with per-run browser capability")
    web.add_argument("--port", type=int, default=0, help="Local live-dashboard port; 0 chooses an unused port")
    new = commands.add_parser("new", help="Create a pilot AMC task and shell session")
    new.add_argument("name")
    new.add_argument("--title", required=True)
    for command in ("attach", "start", "end"):
        child = commands.add_parser(command)
        child.add_argument("sid")
        if command == "attach":
            child.add_argument("--takeover", action="store_true", help="Explicitly revoke the previous attachment")
    def execution_arguments(command, *, required):
        command.add_argument('--environment', choices=['sandbox','host','root'], required=required)
        command.add_argument('--root-acknowledged', action='store_true', help='Acknowledge the risk of this root execution')
    execution_arguments(new, required=True)
    execution_arguments(commands.choices['start'], required=True)
    execution_arguments(native, required=False)
    args = parser.parse_args()
    launching=args.command in ('start','new') or (args.command=='native' and args.action=='resume')
    if launching and args.environment is None:parser.error('launch requires explicit --environment')
    if launching and args.environment=='root' and not args.root_acknowledged:
        parser.error('root execution requires --root-acknowledged')
    root = args.home.resolve()
    try:
        if args.command == "init":
            result = initialize(root)
        else:
            if not (root / "pilot.json").is_file():
                raise ValueError("run init first; no production state is adopted")
            config = initialize(root)
            if args.command == "serve":
                from .cockpit import main as serve
                sys.argv = [sys.argv[0], "--root", str(root / "runtime"), "--vault", str(root / "vault"),
                            "--state", str(root / "events.jsonl"), "--host", config["host"], "serve"]
                if args.execution_policy is not None:
                    sys.argv[1:1]=['--execution-policy',str(args.execution_policy)]
                serve()
                return
            if args.command == "ui":
                from .cockpit_surface import navigator
                navigator(root)
                return
            if args.command == "web":
                if args.live:
                    from .cockpit_web import serve
                    serve(root, args.port)
                    return
                from .cockpit_surface import export_dashboard
                print(export_dashboard(root))
                return
            if args.command == 'reconcile-input':
                result = request(root, 'reconcile_input', sid=args.sid, actor='operator',
                                 attachment=args.attachment, confirmed_clean=args.confirmed_clean)
            elif args.command == 'native-organizer':
                result = request(root, 'open_organizer', agent=args.agent, actor='operator')
            elif args.command == 'stop-operator':
                result = request(root, 'take_control_scope', scope=args.scope, target=args.target, actor='operator')
            elif args.command == 'organizer':
                result = request(root, 'organizer', agent=args.agent, content=args.content,
                                 consent=args.consent, idempotency_key=args.idempotency_key, actor='operator')
            elif args.command == 'native':
                payload = dict(sid=args.sid, actor='operator')
                operation = {'bind': 'bind_native', 'status': 'native', 'resume': 'start_native'}[args.action]
                if args.action == 'bind':
                    payload.update(tool=args.tool, conversation=args.conversation)
                elif args.action == 'resume':
                    payload.update(fixture=args.fixture, allow_provider=args.allow_provider, environment=args.environment, root_acknowledged=args.root_acknowledged)
                result = request(root, operation, **payload)
            elif args.command == 'draft':
                if args.action == 'stage':
                    result = request(root, 'stage_draft', sid=args.identifier, text=args.text,
                                     context=args.context, context_consent=args.context_consent, actor='operator')
                elif args.action == 'list':
                    result = request(root, 'drafts', sid=args.identifier, actor='operator')
                else:
                    binding = {'sid': args.session} if args.session is not None else {}
                    result = request(root, 'send_draft', identifier=args.identifier, consent=args.consent,
                                     attachment=args.attachment, actor='operator', **binding)
            elif args.command == 'archive':
                result = request(root, 'archive', sid=args.sid, event_id=args.event_id,
                                 source=args.source, text=args.text, after=args.after, actor='operator')
            elif args.command == 'autopilot':
                operation = {'assign': 'delegate', 'status': 'delegation', 'take-control': 'take_control'}[args.action]
                payload = dict(sid=args.sid, actor='operator')
                if args.action == 'assign':
                    payload.update(operator=args.operator, goal=args.goal, limits=args.limits)
                result = request(root, operation, **payload)
            elif args.command == 'layout':
                result = request(root, 'layout', panels=args.panels, selected=args.selected,
                                 revision=args.revision, actor='operator')
            elif args.command == "list":
                result = request(root, "list")
            elif args.command == "new":
                import re
                if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", args.name):
                    raise ValueError("invalid exact short name")
                sessions = request(root, "list")
                if any(item["name"] == args.name and item["status"] != "ended" for item in sessions):
                    raise ValueError("active name already exists")
                # The existing AMC writer remains authoritative for task creation.
                from .replica_authority import authority_context
                with authority_context(root / "vault", root / "events.jsonl"):
                    task = create_task(root / "events.jsonl", args.title, owner="demobot").task
                try:
                    result = request(root, "open", project=config["project"], task=task.id, name=args.name, actor="operator")
                    result = request(root, "start", sid=result["id"], actor="operator", environment=args.environment, root_acknowledged=args.root_acknowledged)
                except (ValueError, OSError) as exc:
                    raise ValueError(f"task {task.id} created; session outcome uncertain; inspect list and reconcile before retry: {exc}") from exc
            elif args.command == "start":
                result = request(root, "start", sid=args.sid, actor="operator", environment=args.environment, root_acknowledged=args.root_acknowledged)
            elif args.command == "attach":
                attach(root, args.sid, takeover=args.takeover)
                return
            else:
                result = request(root, args.command, sid=args.sid, actor="operator")
        print(json.dumps(result, indent=2))
    except (ValueError, OSError) as exc:
        parser.exit(1, f"cockpit: {exc}\n")


if __name__ == "__main__":
    main()
