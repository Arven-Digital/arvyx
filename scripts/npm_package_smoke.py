"""Build the local npm tarball, install it into empty prefixes and exercise setup.

This is the executed gate for the npm CLI/web delivery chain: the tarball must
carry exactly one wheel plus a self-consistent built React frontend, setup must
install it into a new private virtualenv, and doctor/amc must work from that
prefix. Negative controls prove the chain fails closed: existing destinations,
unapproved native bytes, capability without bytes, and tampered setup intent.

It never downloads native bytes, never enrolls a digest and never executes a
native binary. The synthetic native file is read as bytes only and must be
refused by the shared artifact policy. Passing this gate is not clean-machine
native provisioning, cross-platform acceptance or release approval.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

_WINDOWS = os.name == "nt"
MIN_NODE = (24, 11)
# The tarball is named after the package manifest, whatever the package is called
# in this tree (the private tree ships `arvyx-local`, the public one `arvyx`).
_PACKAGE_NAME = json.loads((Path(__file__).resolve().parents[1] / "packaging" / "npm" / "package.json")
                           .read_text(encoding="utf-8"))["name"]
TARBALL_NAME = re.compile(re.escape(_PACKAGE_NAME) + r"-[0-9A-Za-z.\-]+\.tgz")
ASSET_REFERENCE = re.compile(r"""(?:src|href)="/([^"#?]+)\"""")
# Served by the installed Python package (cockpit_paperclip), not by the build.
SERVER_BRAND_ASSETS = {"assets/favicon.png": "arvyx_control/static/brand/favicon.png",
                       "assets/arvyx-wordmark.png": "arvyx_control/static/brand/arvyx-wordmark.png"}


class SmokeError(RuntimeError):
    pass


def _run(command, *, cwd, env=None, expect=0):
    # Windows npm exposes .cmd shims, which CreateProcess cannot execute directly.
    shell = _WINDOWS and str(command[0]).lower().endswith((".cmd", ".bat"))
    process = subprocess.run([str(part) for part in command], cwd=cwd, env=env, text=True, capture_output=True, shell=shell)
    if expect == 0 and process.returncode != 0:
        raise SmokeError(f"command failed ({process.returncode}): {command[:3]}: {process.stderr[-2000:]}")
    if expect != 0 and process.returncode == 0:
        raise SmokeError(f"command unexpectedly succeeded: {command[:3]}")
    return process


def _refused(command, *, cwd, env, needle):
    process = _run(command, cwd=cwd, env=env, expect=2)
    if process.returncode != 2 or needle not in process.stderr:
        raise SmokeError(f"expected refusal containing {needle!r}, got {process.returncode}: {process.stderr[-1000:]}")
    return needle


def _node_env():
    node = shutil.which("node")
    npm = shutil.which("npm.cmd" if _WINDOWS else "npm")
    if not node or not npm:
        raise SmokeError("node and npm are required on PATH")
    version = subprocess.run([node, "--version"], text=True, capture_output=True, check=True).stdout.strip()
    parts = tuple(int(part) for part in version.lstrip("v").split(".")[:2])
    if parts < MIN_NODE:
        raise SmokeError(f"Node >={MIN_NODE[0]}.{MIN_NODE[1]} required, found {version}")
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith(("PIP_", "PYTHON", "NPM_CONFIG_"))}
    env.update(npm_config_audit="false", npm_config_fund="false", npm_config_update_notifier="false")
    return env, version


def _verify_tarball(tarball: Path) -> dict[str, object]:
    with tarfile.open(tarball, "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
        for name, member in members.items():
            if not name.startswith("package/") or ".." in Path(name).parts or not (member.isfile() or member.isdir()):
                raise SmokeError(f"unexpected tarball member: {name}")
        wheels = [name for name in members if name.startswith("package/payload/") and name.endswith(".whl")]
        if len(wheels) != 1 or "/" in wheels[0].removeprefix("package/payload/"):
            raise SmokeError(f"exactly one top-level payload wheel required, found {wheels}")
        index = members.get("package/payload/web/index.html")
        if index is None:
            raise SmokeError("packaged frontend index.html missing")
        html = archive.extractfile(index).read().decode("utf-8")
        references = sorted(set(ASSET_REFERENCE.findall(html)))
        if not any(reference.endswith(".js") for reference in references):
            raise SmokeError("packaged frontend index.html references no script bundle")
        missing = [reference for reference in references
                   if f"package/payload/web/{reference}" not in members and reference not in SERVER_BRAND_ASSETS]
        if missing:
            raise SmokeError(f"packaged frontend references missing assets: {missing}")
        with zipfile.ZipFile(io.BytesIO(archive.extractfile(members[wheels[0]]).read())) as wheel:
            absent = [SERVER_BRAND_ASSETS[reference] for reference in references
                      if reference in SERVER_BRAND_ASSETS and SERVER_BRAND_ASSETS[reference] not in wheel.namelist()]
        if absent:
            raise SmokeError(f"bundled wheel lacks server-provided brand assets: {absent}")
        manifest = json.loads(archive.extractfile(members["package/package.json"]).read())
        hooks = {"install", "preinstall", "postinstall", "prepare"} & set(manifest.get("scripts", {}))
        if hooks:
            raise SmokeError(f"npm lifecycle hooks must not exist: {sorted(hooks)}")
    return {"wheel": Path(wheels[0]).name, "web_assets": references}


def _read_intent(prefix: Path) -> dict:
    return json.loads((prefix / "setup-intent.json").read_text(encoding="utf-8"))


def _write_intent(prefix: Path, record: dict) -> None:
    (prefix / "setup-intent.json").write_text(json.dumps(record) + "\n", encoding="utf-8")


def _make_private(path: Path, mode: int = 0o700) -> None:
    if _WINDOWS:
        from arvyx_control.windows_acl import make_private
        make_private(path)
    else:
        path.chmod(mode)


def _require_private(path: Path) -> None:
    if _WINDOWS:
        from arvyx_control.windows_acl import private_path_problem
        problem = private_path_problem(path)
        if problem:
            raise SmokeError(f"setup prefix is not private: {problem}")
    elif os.stat(path).st_mode & 0o077:
        raise SmokeError("setup prefix is not private")


def _synthetic_native(root: Path) -> tuple[Path, Path]:
    """Bytes that are never executed and never match the admitted digest."""
    directory = root / "synthetic-native"
    directory.mkdir(mode=0o700)
    binary = directory / "arvyx"
    binary.write_bytes(b"#!/bin/sh\n# synthetic, unapproved, never executed\nexit 64\n")
    _make_private(binary)
    receipt = directory / "receipt.json"
    receipt.write_text(json.dumps({"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}))
    _make_private(receipt, 0o600)
    return binary, receipt


def run(repo: Path) -> dict[str, object]:
    repo = repo.resolve()
    env, node_version = _node_env()
    checks: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _make_private(root)
        build = root / "build"
        _run([sys.executable, repo / "scripts/build_arvyx_npm.py", "--output", build], cwd=root, env=env)
        tarballs = [path for path in build.iterdir() if TARBALL_NAME.fullmatch(path.name)]
        if len(tarballs) != 1:
            raise SmokeError(f"expected one tarball, found {[path.name for path in tarballs]}")
        tarball = tarballs[0]
        contents = _verify_tarball(tarball)
        checks.append("tarball carries one wheel and a self-consistent built frontend")

        npm_prefix = root / "npm-prefix"
        npm_prefix.mkdir(mode=0o700)
        _run([shutil.which("npm.cmd" if _WINDOWS else "npm"), "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", "--prefix", npm_prefix, tarball],
             cwd=root, env=env)
        launcher = npm_prefix / ("node_modules/.bin/arvyx.cmd" if _WINDOWS else "node_modules/.bin/arvyx")
        if not launcher.exists():
            raise SmokeError("installed npm package exposes no arvyx launcher")
        venvs = root / "venvs"
        venvs.mkdir(mode=0o700)
        prefix = venvs / "complete"

        setup = _run([launcher, "setup", "--prefix", prefix, "--python", sys.executable], cwd=root, env=env)
        if "Setup complete" not in setup.stdout:
            raise SmokeError("setup did not report completion")
        intent = _read_intent(prefix)
        if intent.get("state") != "complete" or intent.get("native_requested") is not False or intent.get("native_capability") is not None:
            raise SmokeError(f"unexpected setup intent: {intent}")
        if intent.get("wheel") != contents["wheel"]:
            raise SmokeError("setup intent does not bind the bundled wheel")
        checks.append("setup installed the bundled wheel into a new private prefix")
        _require_private(prefix)

        doctor = _run([launcher, "doctor", "--prefix", prefix], cwd=root, env=env)
        if "Python package import OK" not in doctor.stdout or "Web assets OK" not in doctor.stdout:
            raise SmokeError("doctor did not verify imports and web assets")
        checks.append("doctor verified installed imports and packaged web assets")
        amc = _run([launcher, "amc", "--prefix", prefix, "--help"], cwd=root, env=env)
        if "usage: amc" not in amc.stdout:
            raise SmokeError("installed amc CLI did not run")
        checks.append("installed amc CLI runs from the prefix")
        web = _run([launcher, "web", "--prefix", prefix, "--help"], cwd=root, env=env)
        if "--connection" not in web.stdout:
            raise SmokeError("installed packaged web entry point did not run")
        checks.append("installed packaged web entry point runs from the prefix")

        # Negative controls. Each refusal is checked for its documented reason.
        checks.append(_refused([launcher, "setup", "--prefix", prefix, "--python", sys.executable], cwd=root, env=env,
                               needle="already exists"))
        checks.append(_refused([launcher, "web", "--prefix", prefix, "--frontend", root], cwd=root, env=env,
                               needle="bundled frontend"))
        binary, receipt = _synthetic_native(root)
        checks.append(_refused([launcher, "setup", "--prefix", venvs / "capability-only", "--native-capability", "onboarding-v1"],
                               cwd=root, env=env, needle="requires explicit native binary"))
        if (venvs / "capability-only").exists():
            raise SmokeError("refused setup created a prefix")
        unapproved = venvs / "unapproved-native"
        process = _run([launcher, "setup", "--prefix", unapproved, "--python", sys.executable,
                        "--native-binary", binary, "--native-receipt", receipt], cwd=root, env=env, expect=2)
        native_refusal = "no approved native artifact for this platform" if _WINDOWS else "unapproved native"
        if process.returncode != 2 or native_refusal not in process.stderr:
            raise SmokeError(f"native setup did not give its platform-specific refusal: {process.stderr[-1000:]}")
        if _read_intent(unapproved).get("state") != "incomplete" or (unapproved / "native").exists():
            raise SmokeError("refused native setup must retain an incomplete prefix without native bytes")
        checks.append(f"native setup refused: {native_refusal}")
        checks.append(_refused([launcher, "doctor", "--prefix", unapproved], cwd=root, env=env, needle="Setup incomplete"))

        # Tamper with the complete prefix, then restore and prove it is healthy again.
        original = (prefix / "setup-intent.json").read_bytes()
        tampers = [
            ({**intent, "wheel_sha256": "0" * 64}, "Setup provenance does not match"),
            ({**intent, "state": "incomplete"}, "Setup incomplete"),
            ({**intent, "native_requested": True, "native_capability": None}, "Setup incomplete"),
            ({**intent, "native_requested": False, "native_capability": "onboarding-v1"}, "Setup incomplete"),
            ({**intent, "native_requested": True, "native_capability": "onboarding-v1"}, "requested native component missing"),
        ]
        for record, needle in tampers:
            _write_intent(prefix, record)
            checks.append(_refused([launcher, "doctor", "--prefix", prefix], cwd=root, env=env, needle=needle))
        # Windows has no admitted native artifact; its install refusal is checked
        # above. The planted native-install metadata uses a POSIX-only verifier.
        if not _WINDOWS:
            native = prefix / "native"
            native.mkdir(mode=0o700)
            shutil.copy2(binary, native / "arvyx")
            (native / "native-install.json").write_text(receipt.read_text())
            _write_intent(prefix, {**intent, "native_requested": True, "native_capability": "onboarding-v1"})
            process = _run([launcher, "doctor", "--prefix", prefix], cwd=root, env=env, expect=2)
            if "unapproved native" not in process.stderr:
                raise SmokeError(f"doctor did not recheck planted native bytes: {process.stderr[-1000:]}")
            checks.append("doctor rechecks planted native bytes against the shared policy")
            _run([launcher, "amc", "--prefix", prefix, "--help"], cwd=root, env=env, expect=2)
            checks.append("amc refuses a prefix whose requested native component fails verification")
            shutil.rmtree(native)
        (prefix / "setup-intent.json").write_bytes(original)
        _run([launcher, "doctor", "--prefix", prefix], cwd=root, env=env)
        checks.append("restored intent is healthy again")
        return {
            "ok": True,
            "node": node_version,
            "python": sys.version.split()[0],
            "tarball": tarball.name,
            **contents,
            "checks": checks,
            "native_bundled": False,
            "native_runtime_acceptance": False,
            "release_approved": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()
    try:
        result = run(args.repo)
    except (OSError, SmokeError, subprocess.CalledProcessError, json.JSONDecodeError, tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
        if args.json_output:
            print(json.dumps({"ok": False, "error": type(exc).__name__, "message": str(exc)}, sort_keys=True))
        else:
            print(f"npm package smoke failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True) if args.json_output else "npm package smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
