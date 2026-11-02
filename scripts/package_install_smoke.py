from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import zipfile


BUILD_VERSION = "1.5.0"


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=True)


def _venv(root: Path, name: str) -> tuple[Path, Path]:
    venv = root / name
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    bindir = venv / ("Scripts" if sys.platform == "win32" else "bin")
    python = bindir / ("python.exe" if sys.platform == "win32" else "python")
    return bindir, python


def _verify_archives(wheel: Path, sdist: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if not any(name.endswith(".dist-info/licenses/LICENSE") for name in names):
            raise RuntimeError("wheel is missing LICENSE")
        if not any(name.endswith(".dist-info/licenses/NOTICE") for name in names):
            raise RuntimeError("wheel is missing NOTICE")
    with tarfile.open(sdist, "r:gz") as archive:
        names = archive.getnames()
        if not any(name.endswith("/LICENSE") for name in names):
            raise RuntimeError("sdist is missing LICENSE")
        if not any(name.endswith("/NOTICE") for name in names):
            raise RuntimeError("sdist is missing NOTICE")


def _install_and_probe(artifact: Path, *, root: Path, name: str, run_product: bool) -> dict[str, object]:
    bindir, python = _venv(root, name)
    suffix = ".exe" if sys.platform == "win32" else ""
    arvyx = bindir / f"arvyx{suffix}"
    bridge = bindir / f"safe-mcp-bridge{suffix}"
    _run([str(python), "-m", "pip", "install", str(artifact), "--quiet"], cwd=root)
    _run([str(python), "-m", "pip", "check"], cwd=root)
    _run([str(arvyx), "--help"], cwd=root)
    _run([str(bridge), "--help"], cwd=root)
    # The read-only Control Center API ships in the same distribution.
    _run([str(python), "-m", "arvyx_control_center_api", "--help"], cwd=root)
    result: dict[str, object] = {
        "console_scripts": [arvyx.name, bridge.name],
        "modules": ["arvyx_control_center_api"],
    }
    if run_product:
        demo = json.loads(_run([str(arvyx), "demo", "--json"], cwd=root).stdout)
        benchmark = json.loads(_run([str(arvyx), "benchmark", "recall", "--json"], cwd=root).stdout)
        if demo.get("ok") is not True:
            raise RuntimeError("installed artifact demo failed")
        if benchmark.get("score") != 100:
            raise RuntimeError("installed artifact benchmark failed")
        result.update({"demo": True, "benchmark_score": benchmark["score"]})
    return result


def run(repo: Path, artifacts: Path | None = None) -> dict[str, object]:
    repo = repo.resolve()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        if artifacts is None:
            dist = root / "dist"
            _, builder = _venv(root, "builder")
            _run([str(builder), "-m", "pip", "install", f"build=={BUILD_VERSION}", "--quiet"], cwd=root)
            _run([str(builder), "-m", "build", "--outdir", str(dist), str(repo)], cwd=root)
        else:
            dist = artifacts.resolve()
            if not dist.is_dir():
                raise RuntimeError("artifact directory does not exist")
        wheels = sorted(dist.glob("*.whl"))
        sdists = sorted(dist.glob("*.tar.gz"))
        if len(wheels) != 1 or len(sdists) != 1:
            raise RuntimeError(f"expected one wheel and one sdist, found {len(wheels)} and {len(sdists)}")
        _verify_archives(wheels[0], sdists[0])
        wheel_result = _install_and_probe(wheels[0], root=root, name="wheel-venv", run_product=True)
        sdist_result = _install_and_probe(sdists[0], root=root, name="sdist-venv", run_product=True)
        return {
            "ok": True,
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "wheel": wheels[0].name,
            "sdist": sdists[0].name,
            "licenses": True,
            "wheel_probe": wheel_result,
            "sdist_probe": sdist_result,
            **wheel_result,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and smoke-test wheel and sdist outside the checkout.")
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--artifacts", type=Path, help="Test existing wheel and sdist bytes instead of rebuilding.")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()
    try:
        result = run(args.repo, args.artifacts)
    except (OSError, RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError, tarfile.TarError, zipfile.BadZipFile) as exc:
        if args.json_output:
            print(json.dumps({"ok": False, "error": type(exc).__name__, "message": str(exc)}, sort_keys=True))
        else:
            print(f"package install smoke failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if args.json_output:
        print(json.dumps(result, sort_keys=True))
    else:
        print("package install smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
