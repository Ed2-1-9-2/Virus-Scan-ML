"""One-click launcher that auto-updates and starts the full stack reliably.

Behavior on startup:
1) Resolve local repository (or auto-download ZIP fallback).
2) Best-effort git update from GitHub main branch.
3) Ensure backend/frontend dependencies are installed.
4) Start backend + frontend in separate PowerShell windows.
5) Wait for readiness and open browser at http://localhost:3000
"""

from __future__ import annotations

import ctypes
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser
import zipfile
from pathlib import Path
from typing import Optional, Tuple

REPO_URL = "https://github.com/Ed2-1-9-2/Virus-Scan-ML.git"
REPO_DIR_NAME = "Virus-Scan-ML"
REPO_BRANCH = "main"
REPO_ZIP_URL = f"https://github.com/Ed2-1-9-2/Virus-Scan-ML/archive/refs/heads/{REPO_BRANCH}.zip"
FRONTEND_URL = "http://127.0.0.1:3000"


def message_box(text: str, title: str = "Start_MVirus_App") -> None:
    """Show a Windows message box and also print to stdout."""
    print(text)
    try:
        ctypes.windll.user32.MessageBoxW(0, text, title, 0x00000010)
    except Exception:
        pass


def base_dir() -> Path:
    """Return the directory that contains this script or executable."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def run_command(args: list[str], cwd: Path | None = None, timeout: int = 180) -> tuple[int, str]:
    """Run command and return (returncode, output)."""
    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=os.environ.copy(),
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        return completed.returncode, output.strip()
    except Exception as exc:
        return 1, str(exc)


def has_local_fullstack_layout(root: Path) -> bool:
    """Return True if root looks like unpacked app bundle."""
    return (root / "m-virus").exists() and (root / "m-virus-ui").exists()


def _find_layout_candidates(base: Path) -> list[Path]:
    candidates: list[Path] = []
    for candidate_name in ("Virus-Scan-ML-main", "Virus-Scan-ML", REPO_DIR_NAME):
        candidate = base / candidate_name
        if has_local_fullstack_layout(candidate):
            candidates.append(candidate)
    return candidates


def _download_repo_zip(base: Path) -> Path:
    """Download repository as ZIP and return extracted repo root with expected layout."""
    archive_path = base / f"{REPO_DIR_NAME}-{REPO_BRANCH}.zip"

    try:
        urllib.request.urlretrieve(REPO_ZIP_URL, archive_path)
    except Exception as exc:
        raise RuntimeError(f"ZIP download failed: {exc}") from exc

    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            archive.extractall(base)
    except Exception as exc:
        raise RuntimeError(f"ZIP extract failed: {exc}") from exc
    finally:
        try:
            archive_path.unlink()
        except Exception:
            pass

    candidates = _find_layout_candidates(base)
    if candidates:
        return candidates[0]

    raise RuntimeError("Downloaded ZIP is missing expected folders 'm-virus' and 'm-virus-ui'.")


def resolve_repo_root(base: Path) -> Path:
    """Resolve local repository root, clone, or ZIP-download when needed."""
    if has_local_fullstack_layout(base):
        return base

    candidates = _find_layout_candidates(base)
    if candidates:
        return candidates[0]

    if (base / ".git").exists():
        return base

    nested = base / REPO_DIR_NAME
    if has_local_fullstack_layout(nested):
        return nested
    if (nested / ".git").exists():
        return nested

    if nested.exists() and any(nested.iterdir()):
        raise RuntimeError(f"Folder exists but is incomplete: {nested}")

    git_path = shutil.which("git")
    clone_error = "git not available"
    if git_path:
        nested.mkdir(parents=True, exist_ok=True)
        code, output = run_command([git_path, "clone", REPO_URL, str(nested)], cwd=base, timeout=900)
        if code == 0 and has_local_fullstack_layout(nested):
            return nested
        clone_error = output or "git clone failed"

    # Fallback: no git available or clone failed -> download ZIP directly.
    try:
        return _download_repo_zip(base)
    except Exception as exc:
        raise RuntimeError(
            "Could not obtain project files automatically.\n"
            f"Git clone error: {clone_error}\n"
            f"ZIP fallback error: {exc}"
        ) from exc


def update_repo(repo_root: Path) -> None:
    """Best-effort git update (skip silently if unavailable/offline)."""
    if not (repo_root / ".git").exists():
        # Local ZIP/extracted bundle mode: skip git update and continue.
        return

    git_path = shutil.which("git")
    if not git_path:
        return

    code, output = run_command([git_path, "-C", str(repo_root), "fetch", "origin", REPO_BRANCH], timeout=180)
    if code != 0:
        print(f"[launcher] git fetch skipped: {output}")
        return

    code, output = run_command(
        [git_path, "-C", str(repo_root), "pull", "--ff-only", "origin", REPO_BRANCH],
        timeout=240,
    )
    if code != 0:
        print(f"[launcher] git pull skipped: {output}")


def start_in_new_console(powershell_command: str) -> None:
    """Run a PowerShell command in a new terminal window."""
    subprocess.Popen(
        [
            "powershell",
            "-NoExit",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            powershell_command,
        ],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )


def _python_candidates() -> list[list[str]]:
    """Return Python command candidates, preferring versions with better wheel support."""
    return [
        ["py", "-3.10"],
        ["py", "-3.11"],
        ["py", "-3.12"],
        ["py", "-3"],
        ["python"],
        ["python3"],
    ]


def _probe_python(cmd: list[str]) -> Optional[Tuple[int, int]]:
    """Return (major, minor) if command is a valid Python interpreter."""
    code, output = run_command(
        cmd + ["-c", "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')"],
        timeout=30,
    )
    if code != 0:
        return None

    raw = output.strip().splitlines()
    if not raw:
        return None

    version = raw[-1].strip()
    parts = version.split(".")
    if len(parts) != 2:
        return None

    try:
        major = int(parts[0])
        minor = int(parts[1])
    except ValueError:
        return None

    return major, minor


def _pick_python_command() -> list[str]:
    """Pick a usable Python command for creating backend venv."""
    fallback: Optional[list[str]] = None
    for cmd in _python_candidates():
        version = _probe_python(cmd)
        if not version:
            continue
        major, minor = version
        if major == 3 and 10 <= minor <= 12:
            return cmd
        if major == 3 and minor >= 10 and fallback is None:
            fallback = cmd

    if fallback:
        return fallback

    raise RuntimeError(
        "Python 3.10+ was not found.\n"
        "Install Python 3.10/3.11 and ensure command `py` or `python` is available in PATH."
    )


def _create_backend_venv(backend_dir: Path) -> Path:
    """Create backend virtual environment and return python executable path."""
    backend_python = backend_dir / ".venv" / "Scripts" / "python.exe"
    if backend_python.exists():
        return backend_python

    python_cmd = _pick_python_command()
    code, output = run_command(python_cmd + ["-m", "venv", ".venv"], cwd=backend_dir, timeout=900)
    if code != 0:
        raise RuntimeError(f"Could not create backend virtualenv using {' '.join(python_cmd)}:\n{output}")

    if not backend_python.exists():
        raise RuntimeError(f"Virtualenv creation completed but python not found: {backend_python}")

    return backend_python


def _install_backend_requirements(backend_python: Path, backend_dir: Path) -> None:
    """Install/repair mandatory backend requirements."""
    # Upgrade packaging tools best-effort; do not fail startup if this step fails.
    code, output = run_command(
        [
            str(backend_python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--upgrade",
            "pip",
            "setuptools",
            "wheel",
        ],
        cwd=backend_dir,
        timeout=1200,
    )
    if code != 0:
        print(f"[launcher] pip bootstrap warning: {output}")

    code, output = run_command(
        [
            str(backend_python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "-r",
            "config/requirements-api.txt",
        ],
        cwd=backend_dir,
        timeout=2400,
    )
    if code != 0:
        raise RuntimeError(f"Could not install backend dependencies:\n{output}")


def _backend_runtime_ready(backend_python: Path, backend_dir: Path) -> tuple[bool, str]:
    """Probe mandatory backend imports used at runtime."""
    code, output = run_command(
        [
            str(backend_python),
            "-c",
            (
                "import fastapi,uvicorn,xgboost,numpy,pandas,sklearn,pydantic;"
                "print('ok')"
            ),
        ],
        cwd=backend_dir,
        timeout=90,
    )
    return code == 0, output


def _ensure_optional_extractor(backend_python: Path, backend_dir: Path) -> Optional[str]:
    """
    Best-effort optional deps install for PE feature extraction.

    If installation fails, launcher still continues and the app remains usable for non-PE endpoints.
    """
    probe_code = (
        "from backend.pe_to_features import extractor_available, extractor_diagnostics;"
        "print('ready' if extractor_available() else 'missing');"
        "print(extractor_diagnostics())"
    )
    code, output = run_command([str(backend_python), "-c", probe_code], cwd=backend_dir, timeout=120)
    if code == 0 and output.splitlines() and output.splitlines()[0].strip() == "ready":
        return None

    optional_reqs = backend_dir / "config" / "requirements-optional.txt"
    if not optional_reqs.exists():
        return "Optional extractor dependencies file is missing (config/requirements-optional.txt)."

    code, install_output = run_command(
        [
            str(backend_python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "-r",
            "config/requirements-optional.txt",
        ],
        cwd=backend_dir,
        timeout=2400,
    )
    if code != 0:
        return (
            "Optional PE extractor dependencies could not be installed automatically.\n"
            f"{install_output}"
        )

    code, output = run_command([str(backend_python), "-c", probe_code], cwd=backend_dir, timeout=120)
    if code == 0 and output.splitlines() and output.splitlines()[0].strip() == "ready":
        return None

    return "PE extractor is still unavailable after optional dependency install."


def ensure_backend_python(backend_dir: Path) -> tuple[Path, Optional[str]]:
    """Ensure backend venv exists and required dependencies are installed."""
    backend_python = _create_backend_venv(backend_dir)
    _install_backend_requirements(backend_python, backend_dir)

    ready, output = _backend_runtime_ready(backend_python, backend_dir)
    if not ready:
        # One more repair attempt in case of partial/corrupt environment.
        _install_backend_requirements(backend_python, backend_dir)
        ready, output = _backend_runtime_ready(backend_python, backend_dir)
        if not ready:
            raise RuntimeError(f"Backend runtime probe failed after dependency install:\n{output}")

    optional_warning = _ensure_optional_extractor(backend_python, backend_dir)
    return backend_python, optional_warning


def _frontend_runtime_ready(frontend_dir: Path) -> tuple[bool, str]:
    """Probe critical frontend modules required by react-scripts start."""
    node_path = shutil.which("node.exe") or shutil.which("node")
    if not node_path:
        return False, "Node.js executable not found in PATH."

    probe_script = (
        "require.resolve('react-scripts/package.json');"
        "require.resolve('react-dev-utils/crossSpawn');"
        "console.log('ok');"
    )
    code, output = run_command([node_path, "-e", probe_script], cwd=frontend_dir, timeout=90)
    return code == 0, output


def _npm_install(frontend_dir: Path, npm_path: str, prefer_ci: bool) -> tuple[int, str]:
    """Install frontend deps with deterministic options when lockfile exists."""
    if prefer_ci and (frontend_dir / "package-lock.json").exists():
        return run_command([npm_path, "ci", "--no-audit", "--no-fund"], cwd=frontend_dir, timeout=3600)
    return run_command([npm_path, "install", "--no-audit", "--no-fund"], cwd=frontend_dir, timeout=3600)


def ensure_frontend_dependencies(frontend_dir: Path) -> str:
    """Ensure frontend dependencies are present and usable."""
    npm_path = shutil.which("npm.cmd") or shutil.which("npm")
    if not npm_path:
        raise RuntimeError(
            "Node.js/NPM was not found in PATH.\n"
            "Install Node.js LTS from https://nodejs.org and reopen the launcher."
        )

    ready, output = _frontend_runtime_ready(frontend_dir)
    if ready:
        return npm_path

    attempts: list[str] = []

    code, install_output = _npm_install(frontend_dir, npm_path, prefer_ci=True)
    attempts.append(f"npm ci/install attempt 1 (code={code}):\n{install_output}")
    ready, probe_output = _frontend_runtime_ready(frontend_dir)
    if code == 0 and ready:
        return npm_path

    # Hard repair for partially corrupted node_modules.
    node_modules_dir = frontend_dir / "node_modules"
    if node_modules_dir.exists():
        try:
            shutil.rmtree(node_modules_dir)
        except Exception as exc:
            attempts.append(f"node_modules cleanup warning: {exc}")

    code, install_output = _npm_install(frontend_dir, npm_path, prefer_ci=True)
    attempts.append(f"npm ci/install attempt 2 (code={code}):\n{install_output}")
    ready, probe_output = _frontend_runtime_ready(frontend_dir)
    if code == 0 and ready:
        return npm_path

    attempts.append(f"frontend module probe failed:\n{probe_output or output}")
    details = "\n\n".join(attempts[-3:])
    raise RuntimeError(
        "Could not repair frontend dependencies automatically.\n"
        "Last diagnostics:\n"
        f"{details}"
    )

    return npm_path


def wait_for_http(url: str, timeout_seconds: int = 120) -> tuple[bool, str]:
    """Poll an HTTP endpoint until responsive or timeout."""
    deadline = time.time() + timeout_seconds
    last_error = "unknown error"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                status = getattr(response, "status", 200)
                if 200 <= status < 500:
                    return True, ""
                last_error = f"HTTP {status}"
        except Exception as exc:
            last_error = str(exc)
        time.sleep(1)
    return False, last_error


def is_port_in_use(host: str, port: int) -> bool:
    """Return True when a TCP listener responds on host:port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        try:
            return sock.connect_ex((host, port)) == 0
        except OSError:
            return True


def is_port_available(host: str, port: int) -> bool:
    """Return True when host:port is not currently in use."""
    return not is_port_in_use(host, port)


def find_free_port(host: str, start: int = 8001, end: int = 9000) -> Optional[int]:
    """Find first available TCP port in range [start, end)."""
    for port in range(start, end):
        if is_port_available(host, port):
            return port
    return None


def main() -> int:
    root = base_dir()

    try:
        repo_root = resolve_repo_root(root)
    except Exception as exc:
        message_box(f"Could not locate project files:\n{exc}", title="Launcher setup error")
        return 1

    # Best-effort update: never block startup when offline or git is unavailable.
    update_repo(repo_root)

    backend_dir = repo_root / "m-virus"
    frontend_dir = repo_root / "m-virus-ui"

    missing = []
    if not backend_dir.exists():
        missing.append(str(backend_dir))
    if not frontend_dir.exists():
        missing.append(str(frontend_dir))
    if missing:
        message_box(
            "Missing required paths:\n\n"
            + "\n".join(f"- {item}" for item in missing)
            + "\n\nRepository content is incomplete.",
            title="Launcher path error",
        )
        return 1

    optional_warning: Optional[str] = None
    try:
        backend_python, optional_warning = ensure_backend_python(backend_dir)
        npm_path = ensure_frontend_dependencies(frontend_dir)
    except Exception as exc:
        message_box(str(exc), title="Launcher dependency error")
        return 1

    backend_host = "127.0.0.1"
    backend_port = 8000
    backend_health_url = f"http://{backend_host}:{backend_port}/health"
    backend_already_running, _backend_probe = wait_for_http(backend_health_url, timeout_seconds=2)

    if not backend_already_running and not is_port_available(backend_host, backend_port):
        fallback_port = find_free_port(backend_host, start=8001, end=9000)
        if fallback_port is None:
            message_box(
                "Port 8000 is occupied and no free fallback port was found (8001-8999).",
                title="Launcher port error",
            )
            return 1
        backend_port = fallback_port
        backend_health_url = f"http://{backend_host}:{backend_port}/health"

    frontend_already_running, _frontend_probe = wait_for_http(FRONTEND_URL, timeout_seconds=2)

    backend_cmd = (
        f'$ErrorActionPreference = "Stop"; Set-Location "{backend_dir}"; '
        f'& "{backend_python}" -m uvicorn backend.api_backend:app --host {backend_host} --port {backend_port}'
    )
    frontend_cmd = (
        f'$ErrorActionPreference = "Stop"; '
        f'$env:REACT_APP_API_URL="http://{backend_host}:{backend_port}"; '
        f'Set-Location "{frontend_dir}"; '
        f'& "{npm_path}" start'
    )

    try:
        if backend_already_running:
            backend_ready = True
            backend_error = ""
        else:
            start_in_new_console(backend_cmd)
            backend_ready, backend_error = wait_for_http(backend_health_url, timeout_seconds=120)

        if frontend_already_running:
            frontend_ready = True
            frontend_error = ""
        else:
            start_in_new_console(frontend_cmd)
            frontend_ready, frontend_error = wait_for_http(FRONTEND_URL, timeout_seconds=180)
    except Exception as exc:
        message_box(f"Could not start services:\n{exc}", title="Launcher runtime error")
        return 1

    if optional_warning:
        print(f"[launcher] warning: {optional_warning}")

    if frontend_ready:
        webbrowser.open("http://localhost:3000")
        return 0

    detail_lines = [
        "Frontend did not become ready on http://localhost:3000.",
        f"Backend ready: {'yes' if backend_ready else 'no'}",
        f"Backend endpoint: {backend_health_url}",
        f"Backend health probe: {backend_error or 'ok'}",
        f"Frontend probe: {frontend_error or 'ok'}",
        "",
        "The backend/frontend terminal windows remain open with exact errors.",
    ]
    if optional_warning:
        detail_lines.extend(
            [
                "",
                "Optional PE extractor setup warning:",
                optional_warning,
            ]
        )

    message_box("\n".join(detail_lines), title="Launcher startup warning")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
