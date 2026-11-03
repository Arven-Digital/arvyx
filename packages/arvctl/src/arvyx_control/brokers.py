from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
import ipaddress
import json
import math
import os
import selectors
import signal
from pathlib import Path
import re
import socket
import subprocess
import threading
import time
from urllib.parse import urlsplit

from .http_bounds import parse_complete_response
from .security import bounded_json_loads, contains_literal_secret


# A secret REFERENCE is a sanctioned pointer that is safe to store in the
# vault: secret://<broker>/<path>. The broker resolves it to a real value
# at access time. The value itself never enters the vault, recall output,
# or the audit log — only the reference does.
SECRET_REF_RE = re.compile(r"secret://([a-z0-9][a-z0-9_-]{0,63})/([^\s'\"<>`]+)")
BROKER_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

CONFIG_ENV = "ARVYX_SECRET_BROKERS"
CONFIG_RELATIVE = Path(".arvyx") / "secret-brokers.json"
SUPPORTED_PROVIDERS = {"env", "envfile", "file", "command"}
INSPECTABLE_PROVIDERS = SUPPORTED_PROVIDERS | {"http-broker"}
MAX_SECRET_BYTES = 64 * 1024
MAX_ENVFILE_BYTES = 1024 * 1024
MAX_COMMAND_SECONDS = 300.0
MAX_HEALTH_BODY_BYTES = 4096
MAX_HEALTH_RESPONSE_BYTES = 8192
HEALTH_TIMEOUT_SECONDS = 2.0
SAFE_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){0,3}(?:[-.][A-Za-z0-9]+)?$")


class BrokerError(ValueError):
    """Resolution failure. Its message never contains a secret value."""


@dataclass
class _TokenBucket:
    tokens: float
    updated_at: float


@dataclass
class _CircuitState:
    failures: int = 0
    open_until: float = 0.0


class InspectionGuard:
    """Process-local admission and circuit controls for value-free inspection."""

    def __init__(
        self,
        *,
        global_capacity: int = 24,
        global_refill_per_second: float = 0.4,
        principal_capacity: int = 6,
        principal_refill_per_second: float = 0.1,
        max_concurrent: int = 2,
        circuit_failure_threshold: int = 3,
        circuit_cooldown_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if min(global_capacity, principal_capacity, max_concurrent, circuit_failure_threshold) < 1:
            raise ValueError("inspection guard limits must be positive")
        if global_refill_per_second < 0 or principal_refill_per_second < 0 or circuit_cooldown_seconds <= 0:
            raise ValueError("inspection guard timing must be non-negative with a positive cooldown")
        self._global_capacity = float(global_capacity)
        self._global_refill = global_refill_per_second
        self._principal_capacity = float(principal_capacity)
        self._principal_refill = principal_refill_per_second
        self._circuit_threshold = circuit_failure_threshold
        self._circuit_cooldown = circuit_cooldown_seconds
        self._clock = clock
        now = self._now()
        self._global = _TokenBucket(self._global_capacity, now)
        self._principals: dict[str, _TokenBucket] = {}
        self._circuits: dict[str, _CircuitState] = {}
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(max_concurrent)

    def _now(self) -> float:
        return float(self._clock())

    @staticmethod
    def _refill(bucket: _TokenBucket, capacity: float, refill: float, now: float) -> None:
        elapsed = max(0.0, now - bucket.updated_at)
        bucket.tokens = min(capacity, bucket.tokens + elapsed * refill)
        bucket.updated_at = now

    @contextmanager
    def admit(self, principal: str):
        if not self._slots.acquire(blocking=False):
            raise ValueError("secret inspection unavailable")
        try:
            safe_principal = principal if BROKER_NAME_RE.fullmatch(principal) else "unknown"
            with self._lock:
                now = self._now()
                principal_bucket = self._principals.setdefault(
                    safe_principal,
                    _TokenBucket(self._principal_capacity, now),
                )
                self._refill(self._global, self._global_capacity, self._global_refill, now)
                self._refill(
                    principal_bucket,
                    self._principal_capacity,
                    self._principal_refill,
                    now,
                )
                if self._global.tokens < 1.0 or principal_bucket.tokens < 1.0:
                    raise ValueError("secret inspection unavailable")
                self._global.tokens -= 1.0
                principal_bucket.tokens -= 1.0
            yield
        finally:
            self._slots.release()

    def circuit_allows(self, provider_key: str) -> bool:
        now = self._now()
        with self._lock:
            state = self._circuits.get(provider_key)
            if state is None:
                return True
            if state.open_until > 0.0 and state.open_until <= now:
                state.open_until = 0.0
                state.failures = 0
                return True
            return state.open_until <= 0.0

    def record_provider_result(self, provider_key: str, *, healthy: bool) -> None:
        now = self._now()
        with self._lock:
            state = self._circuits.setdefault(provider_key, _CircuitState())
            if healthy:
                state.failures = 0
                state.open_until = 0.0
                return
            state.failures += 1
            if state.failures >= self._circuit_threshold:
                state.open_until = now + self._circuit_cooldown


@dataclass(frozen=True)
class SecretRef:
    broker: str
    path: str

    @property
    def uri(self) -> str:
        return f"secret://{self.broker}/{self.path}"


@dataclass(frozen=True)
class ResolveResult:
    ref: str
    broker: str
    provider: str
    value: str

    def to_dict(self, include_value: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {"ref": self.ref, "broker": self.broker, "provider": self.provider}
        if include_value:
            payload["value"] = self.value
        return payload


def is_secret_ref(text: str) -> bool:
    try:
        parse_ref(text)
    except BrokerError:
        return False
    return True


def find_secret_refs(text: str) -> list[SecretRef]:
    seen: set[tuple[str, str]] = set()
    refs: list[SecretRef] = []
    for match in SECRET_REF_RE.finditer(text):
        if contains_literal_secret(match.group(1) + '/' + match.group(2)):
            continue
        key = (match.group(1), match.group(2))
        if key not in seen:
            seen.add(key)
            refs.append(SecretRef(broker=key[0], path=key[1]))
    return refs


def parse_ref(text: str) -> SecretRef:
    match = SECRET_REF_RE.fullmatch(text.strip())
    if not match:
        raise BrokerError("not a secret reference (expected secret://broker/path)")
    if contains_literal_secret(match.group(1) + '/' + match.group(2)):
        raise BrokerError("secret reference contains secret-shaped material")
    return SecretRef(broker=match.group(1), path=match.group(2))


def load_broker_config(repo: Path | None = None) -> dict[str, dict[str, object]]:
    """Load broker definitions from outside the tracked tree.

    Providers point at real secret material, so the config is never
    committed: it comes from $ARVYX_SECRET_BROKERS or the gitignored
    .arvyx/secret-brokers.json.
    """
    for candidate in _config_candidates(repo):
        if not candidate.is_file():
            continue
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BrokerError(f"invalid broker config JSON: {exc.msg}") from exc
        brokers = payload.get("brokers") if isinstance(payload, dict) else None
        if not isinstance(brokers, dict):
            raise BrokerError("broker config must have a 'brokers' object")
        return {str(name): dict(spec) for name, spec in brokers.items() if isinstance(spec, dict)}
    return {}


def list_brokers(repo: Path | None = None) -> list[dict[str, str]]:
    config = load_broker_config(repo)
    return [
        {"name": name, "provider": str(spec.get("provider", "?"))}
        for name, spec in sorted(config.items())
    ]


def inspect_brokers(
    repo: Path | None = None,
    *,
    guard: InspectionGuard | None = None,
) -> list[dict[str, str]]:
    """Return provider health metadata without resolving or exposing config."""
    config = load_broker_config(repo)
    active_guard = guard or InspectionGuard()
    return [_inspect_broker(name, spec, guard=active_guard) for name, spec in sorted(config.items())]


def pointer_status(ref: str, repo: Path | None = None) -> dict[str, object]:
    """Validate pointer syntax and provider existence without echo, network, or resolution."""
    parsed = parse_ref(ref)
    config = load_broker_config(repo)
    spec = config.get(parsed.broker)
    if spec is None:
        return {
            "syntax_valid": True,
            "provider_known": False,
            "provider": "unknown",
            "status": "unknown_broker",
        }
    provider = str(spec.get("provider", ""))
    safe_provider = provider if provider in INSPECTABLE_PROVIDERS else "unknown"
    provider_known = safe_provider != "unknown"
    status = "configured" if provider_known else "invalid_config"
    return {
        "syntax_valid": True,
        "provider_known": provider_known,
        "provider": safe_provider,
        "status": status,
    }


def _inspect_broker(
    name: str,
    spec: dict[str, object],
    *,
    guard: InspectionGuard,
) -> dict[str, str]:
    provider = str(spec.get("provider", ""))
    safe_name = name if BROKER_NAME_RE.fullmatch(name) and not contains_literal_secret(name) else "invalid-broker"
    safe_provider = provider if provider in INSPECTABLE_PROVIDERS else "unknown"
    base = {"name": safe_name, "provider": safe_provider}
    if safe_name == "invalid-broker" or provider not in INSPECTABLE_PROVIDERS:
        return {**base, "status": "invalid_config"}
    if provider != "http-broker":
        return {**base, "status": "configured"}
    health_url = spec.get("health_url")
    if not isinstance(health_url, str):
        return {**base, "status": "invalid_config"}
    try:
        valid_url = _is_loopback_health_url(health_url)
    except Exception:
        return {**base, "status": "invalid_config"}
    if not valid_url:
        return {**base, "status": "invalid_config"}
    circuit_key = f"{safe_name}:{safe_provider}"
    if not guard.circuit_allows(circuit_key):
        return {**base, "status": "unavailable"}
    try:
        status, version = _probe_loopback_health(health_url)
    except Exception:
        # Provider-controlled bytes and exception text must never cross this
        # boundary into MCP results, stderr, logs, or audit records.
        guard.record_provider_result(circuit_key, healthy=False)
        return {**base, "status": "unavailable"}
    guard.record_provider_result(circuit_key, healthy=status == "ok")
    result = {**base, "status": status}
    if version:
        result["version"] = version
    return result


def _is_loopback_health_url(value: str) -> bool:
    parsed = urlsplit(value)
    path = parsed.path
    return (
        parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "::1"}
        and parsed.username is None
        and parsed.password is None
        and parsed.query == ""
        and parsed.fragment == ""
        and path.startswith("/")
        and all(0x21 <= ord(character) <= 0x7E for character in path)
    )


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("provider health deadline exceeded")
    return remaining


def _format_host_header(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _probe_loopback_health(url: str) -> tuple[str, str]:
    """Probe one literal-loopback endpoint under a wall-clock deadline."""
    if not _is_loopback_health_url(url):
        raise ValueError("health endpoint must be literal loopback HTTP")
    parsed = urlsplit(url)
    host = parsed.hostname
    if host is None:
        raise ValueError("health endpoint host is required")
    port = parsed.port or 80
    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    connection = socket.create_connection((host, port), timeout=_remaining(deadline))
    try:
        peer = ipaddress.ip_address(connection.getpeername()[0])
        if not peer.is_loopback:
            raise OSError("provider peer is not loopback")
        request = (
            f"GET {parsed.path} HTTP/1.0\r\n"
            f"Host: {_format_host_header(host, port)}\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        connection.settimeout(_remaining(deadline))
        connection.sendall(request)
        response = bytearray()
        while True:
            connection.settimeout(_remaining(deadline))
            chunk = connection.recv(1024)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > MAX_HEALTH_RESPONSE_BYTES:
                raise ValueError("provider health response too large")
    finally:
        connection.close()

    status, body = parse_complete_response(bytes(response), MAX_HEALTH_BODY_BYTES)
    if status != 200:
        raise ValueError("provider health check failed")
    payload = bounded_json_loads(body.decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        raise ValueError("provider health response is not ready")
    raw_version = payload.get("version", "")
    version = (
        raw_version
        if isinstance(raw_version, str)
        and len(raw_version) <= 32
        and SAFE_VERSION_RE.fullmatch(raw_version)
        and not contains_literal_secret(raw_version)
        else ""
    )
    return "ok", version


def resolve_ref(ref: str, repo: Path | None = None) -> ResolveResult:
    parsed = parse_ref(ref)
    config = load_broker_config(repo)
    spec = config.get(parsed.broker)
    if spec is None:
        raise BrokerError(f"unknown secret broker: {parsed.broker}")
    provider = str(spec.get("provider", ""))
    if provider not in SUPPORTED_PROVIDERS:
        raise BrokerError(f"broker {parsed.broker} uses unsupported provider: {provider or '(none)'}")
    value = _PROVIDERS[provider](parsed, spec)
    if not value:
        raise BrokerError(f"broker {parsed.broker} resolved {parsed.uri} to an empty value")
    if len(value.encode("utf-8")) > MAX_SECRET_BYTES:
        raise BrokerError(f"resolved secret exceeds size cap for {parsed.uri}")
    return ResolveResult(ref=parsed.uri, broker=parsed.broker, provider=provider, value=value)


def _resolve_env(ref: SecretRef, spec: dict[str, object]) -> str:
    # secret://env/VAR_NAME  ->  os.environ[VAR_NAME], optionally prefixed
    prefix = str(spec.get("prefix", ""))
    name = prefix + ref.path
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise BrokerError(f"invalid environment variable name for {ref.uri}")
    value = os.environ.get(name)
    if value is None:
        raise BrokerError(f"environment variable not set for {ref.uri}")
    return value


def _read_bounded_source(path: Path, limit: int, ref: SecretRef) -> str:
    # The sentinel byte detects oversize before decoding, stripping or splitting.
    with path.open("rb") as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise BrokerError(f"broker source exceeds size cap for {ref.uri}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise BrokerError(f"broker source is not UTF-8 for {ref.uri}") from None


def _resolve_envfile(ref: SecretRef, spec: dict[str, object]) -> str:
    # secret://name/KEY  ->  KEY's value in a dotenv-style file
    path = spec.get("path")
    if not isinstance(path, str) or not path:
        raise BrokerError(f"broker {ref.broker} is missing 'path'")
    file_path = Path(path)
    if not file_path.is_file():
        raise BrokerError(f"envfile not found for broker {ref.broker}")
    for line in _read_bounded_source(file_path, MAX_ENVFILE_BYTES, ref).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, val = stripped.partition("=")
        if key.strip() == ref.path:
            value = val.strip()
            if len(value) >= 2 and value[0] in "'\"" and value[-1] == value[0]:
                value = value[1:-1]
            return value
    raise BrokerError(f"key not found in envfile for {ref.uri}")


def _resolve_file(ref: SecretRef, spec: dict[str, object]) -> str:
    # secret://name/relpath  ->  contents of <base>/<relpath>
    base = spec.get("base")
    if not isinstance(base, str) or not base:
        raise BrokerError(f"broker {ref.broker} is missing 'base'")
    base_root = Path(base).resolve()
    target = (base_root / ref.path).resolve()
    if base_root != target and base_root not in target.parents:
        raise BrokerError(f"secret path escapes broker base for {ref.uri}")
    if not target.is_file():
        raise BrokerError(f"secret file not found for {ref.uri}")
    return _read_bounded_source(target, MAX_SECRET_BYTES, ref).strip()


def _require_owned_command_support():
    from .posix_support import owned_command_supported
    if not owned_command_supported():
        raise BrokerError('owned command supervision unavailable on this platform')


def _wait_owned_command(process, deadline):
    """Observe exit WITHOUT reaping on Linux: the owned leader pins the session ID.

    These POSIX adapters exclusively reap their own Popen children. Never poll
    or wait before group cleanup, even when pipes reached EOF successfully.
    macOS has no waitid(WNOWAIT). A kqueue NOTE_EXIT proves the zombie still
    holds the process group, so the group is signalled and then reaped here.
    """
    from .posix_support import exited_unreaped
    while True:
        if exited_unreaped(process.pid):
            if hasattr(os, 'waitid'):
                result = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if result is None:
                    return 0
                return result.si_status if result.si_code == os.CLD_EXITED else -result.si_status
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            return process.wait(timeout=1.0)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('owned command deadline exceeded')
        time.sleep(min(.01, remaining))


def _cleanup_owned_command(process):
    """Bounded cleanup; never signal a numeric group after reaping its leader."""
    failed = False
    try:
        if process.returncode is None:
            # ChildProcessError means someone else reaped it: ownership is lost,
            # so fail safely instead of signaling a potentially recycled group.
            if hasattr(os, 'waitid'):
                os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            elif process.poll() is not None:
                return
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    except (OSError, ChildProcessError):
        failed = True
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    failed = True
        try:
            process.wait(timeout=1.0)
        except (OSError, subprocess.SubprocessError):
            failed = True
    if failed:
        raise BrokerError('owned command cleanup incomplete; reconcile process ownership') from None


def _resolve_command(ref: SecretRef, spec: dict[str, object]) -> str:
    # secret://name/arg  ->  stdout of a configured command with {path}
    # substituted as a single argv element (no shell, no injection).
    template = spec.get("command")
    if not isinstance(template, list) or not all(isinstance(item, str) for item in template):
        raise BrokerError(f"broker {ref.broker} 'command' must be a list of strings")
    if "{path}" not in " ".join(template):
        raise BrokerError(f"broker {ref.broker} command must include a {{path}} placeholder")
    argv = [part.replace("{path}", ref.path) for part in template]
    _require_owned_command_support()
    try:
        timeout = float(spec.get("timeout_seconds", 15))
    except (TypeError, ValueError, OverflowError):
        raise BrokerError(f"broker {ref.broker} command timeout is invalid") from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise BrokerError(f"broker {ref.broker} command timeout is invalid")
    deadline = time.monotonic() + min(timeout, MAX_COMMAND_SECONDS)
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True, bufsize=0,
        )
    except FileNotFoundError:
        raise BrokerError(f"broker {ref.broker} command not found") from None
    stdout = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, 0)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, _ in selector.select(remaining):
                    # Per-stream counts include discarded stderr, without retaining it.
                    chunk = os.read(key.fd, min(4096, MAX_SECRET_BYTES + 1 - key.data))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    count = key.data + len(chunk)
                    if count > MAX_SECRET_BYTES:
                        raise BrokerError(f"broker {ref.broker} command output exceeds size cap")
                    selector.modify(key.fileobj, selectors.EVENT_READ, count)
                    if key.fileobj is process.stdout:
                        stdout.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv, timeout)
        returncode = _wait_owned_command(process, deadline)
        if returncode != 0:
            raise BrokerError(f"broker {ref.broker} command failed (exit {returncode})")
        try:
            return stdout.decode("utf-8").strip()
        except UnicodeDecodeError:
            raise BrokerError(f"broker {ref.broker} command output is not UTF-8") from None
    except (subprocess.TimeoutExpired, TimeoutError):
        raise BrokerError(f"broker {ref.broker} command timed out") from None
    finally:
        _cleanup_owned_command(process)


_PROVIDERS = {
    "env": _resolve_env,
    "envfile": _resolve_envfile,
    "file": _resolve_file,
    "command": _resolve_command,
}


def _config_candidates(repo: Path | None) -> list[Path]:
    candidates: list[Path] = []
    env_path = os.environ.get(CONFIG_ENV)
    if env_path:
        candidates.append(Path(env_path))
    if repo is not None:
        candidates.append(repo / CONFIG_RELATIVE)
    return candidates
