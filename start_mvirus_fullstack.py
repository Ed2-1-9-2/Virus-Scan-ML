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
import json
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
RANDOM_FOREST_MODEL_RAW_URL = (
    "https://raw.githubusercontent.com/Ed2-1-9-2/Virus-Scan-ML/main/"
    "m-virus/models/random_forest_malware_model.joblib"
)


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

    # Avoid noisy/failed pulls when user has local modifications.
    code, output = run_command([git_path, "-C", str(repo_root), "status", "--porcelain"], timeout=60)
    if code == 0 and output.strip():
        print("[launcher] git update skipped: local changes detected in repository.")
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
        ["py", "-3.13"],
        ["python"],
        ["python3"],
        ["py", "-3"],
    ]


def _probe_python(cmd: list[str]) -> Optional[Tuple[int, int, str]]:
    """Return (major, minor, soabi) if command is a valid Python interpreter."""
    code, output = run_command(
        cmd
        + [
            "-c",
            (
                "import json,sys,sysconfig;"
                "print(json.dumps({"
                "'major': sys.version_info[0],"
                "'minor': sys.version_info[1],"
                "'soabi': (sysconfig.get_config_var('SOABI') or '')"
                "}))"
            ),
        ],
        timeout=30,
    )
    if code != 0:
        return None

    raw = output.strip().splitlines()
    if not raw:
        return None

    payload_raw = raw[-1].strip()
    if not payload_raw:
        return None

    try:
        payload = json.loads(payload_raw)
        major = int(payload.get("major"))
        minor = int(payload.get("minor"))
        soabi = str(payload.get("soabi") or "")
    except Exception:
        return None

    return major, minor, soabi


def _is_free_threaded_soabi(soabi: str) -> bool:
    marker = (soabi or "").lower()
    return "cp313t" in marker or "cp314t" in marker or "cp315t" in marker


def _pick_python_command() -> list[str]:
    """Pick a usable Python command for creating backend venv."""
    for cmd in _python_candidates():
        version = _probe_python(cmd)
        if not version:
            continue
        major, minor, soabi = version
        if major == 3 and 10 <= minor <= 13 and not _is_free_threaded_soabi(soabi):
            return cmd

    raise RuntimeError(
        "No compatible Python interpreter was found for backend dependencies.\n"
        "Required: Python 3.10, 3.11, 3.12, or standard 3.13 (64-bit, non free-threaded).\n"
        "Detected Python 3.13 free-threaded builds (cp313t) are not supported by required wheels.\n"
        "Install Python 3.12/3.13 (standard build) from python.org and ensure `py -3.12` or `py -3.13` works."
    )


def _probe_python_path(python_path: Path) -> Optional[Tuple[int, int, str]]:
    return _probe_python([str(python_path)])


def _is_supported_backend_python(python_path: Path) -> bool:
    probe = _probe_python_path(python_path)
    if not probe:
        return False
    major, minor, soabi = probe
    return major == 3 and 10 <= minor <= 13 and not _is_free_threaded_soabi(soabi)


def _create_backend_venv(backend_dir: Path) -> Path:
    """Create backend virtual environment and return python executable path."""
    venv_dir = backend_dir / ".venv"
    backend_python = backend_dir / ".venv" / "Scripts" / "python.exe"
    if backend_python.exists():
        if _is_supported_backend_python(backend_python):
            return backend_python
        try:
            shutil.rmtree(venv_dir)
        except Exception as exc:
            raise RuntimeError(
                "Existing backend virtualenv uses unsupported Python runtime and could not be recreated.\n"
                f"Path: {venv_dir}\n"
                f"Reason: {exc}"
            ) from exc

    # Defensive cleanup in case a partial .venv exists.
    if venv_dir.exists() and not backend_python.exists():
        try:
            shutil.rmtree(venv_dir)
        except Exception:
            pass

    if backend_python.exists():
        return backend_python

    python_cmd = _pick_python_command()
    code, output = run_command(python_cmd + ["-m", "venv", ".venv"], cwd=backend_dir, timeout=900)
    if code != 0:
        raise RuntimeError(f"Could not create backend virtualenv using {' '.join(python_cmd)}:\n{output}")

    if not backend_python.exists():
        raise RuntimeError(f"Virtualenv creation completed but python not found: {backend_python}")

    return backend_python


def _kill_backend_venv_processes(backend_dir: Path) -> None:
    """Best-effort stop python processes running from backend .venv."""
    venv_scripts = str((backend_dir / ".venv" / "Scripts").resolve()).replace("\\", "\\\\")
    ps_cmd = (
        "$target='" + venv_scripts + "';"
        "Get-CimInstance Win32_Process "
        "| Where-Object { "
        "$_.Name -match '^python(w)?\\.exe$' -and "
        "$_.ExecutablePath -and $_.ExecutablePath.StartsWith($target, [System.StringComparison]::OrdinalIgnoreCase) "
        "} "
        "| ForEach-Object { "
        "try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop } catch {} "
        "}"
    )
    run_command(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=30)


def _should_retry_backend_install(output: str) -> bool:
    raw = (output or "").lower()
    return "winerror 32" in raw or "being used by another process" in raw


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

    last_output = ""
    for attempt in range(1, 4):
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
        if code == 0:
            return

        last_output = output
        if _should_retry_backend_install(output):
            _kill_backend_venv_processes(backend_dir)
            if attempt == 2:
                # Escalate to clean env rebuild after repeated file locks.
                try:
                    shutil.rmtree(backend_dir / ".venv")
                except Exception:
                    pass
                backend_python = _create_backend_venv(backend_dir)
            time.sleep(2)
            continue

        break

    raise RuntimeError(f"Could not install backend dependencies:\n{last_output}")


def _backend_runtime_ready(backend_python: Path, backend_dir: Path) -> tuple[bool, str]:
    """Probe mandatory backend imports used at runtime."""
    code, output = run_command(
        [
            str(backend_python),
            "-c",
            (
                "import fastapi,uvicorn,xgboost,numpy,pandas,sklearn,pydantic,lightgbm;"
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


def _ensure_random_forest_artifact(backend_python: Path, backend_dir: Path) -> Optional[str]:
    """
    Ensure RandomForest artifact exists for comparative scoring.

    Strategy:
    1) Use existing local artifact if present.
    2) Try downloading known artifact URL.
    3) Generate a local fallback artifact via bootstrap script.
    """
    models_dir = backend_dir / "models"
    model_candidates = (
        models_dir / "random_forest_malware_model.joblib",
        models_dir / "random_forest_model.joblib",
    )
    metadata_path = models_dir / "random_forest_model_metadata.json"

    existing_model = next((candidate for candidate in model_candidates if candidate.exists()), None)

    def _read_json_dict(path: Path) -> dict:
        if not path.exists():
            return {}
        try:
            with path.open("r", encoding="utf-8-sig") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _metadata_needs_bootstrap_refresh(meta: dict) -> bool:
        if not meta:
            return False
        bootstrap_generated = bool(meta.get("bootstrap_generated")) or (
            isinstance(meta.get("notes"), str)
            and "bootstrap-generated fallback model" in meta.get("notes", "").lower()
        )
        if not bootstrap_generated:
            return False

        has_metrics = isinstance(meta.get("metrics"), dict) and bool(meta.get("metrics"))
        has_confusion = isinstance(meta.get("confusion_matrix"), list) and len(meta.get("confusion_matrix")) == 2
        has_correlation = isinstance(meta.get("correlation_matrix"), list) and len(meta.get("correlation_matrix")) >= 2
        has_test_samples = isinstance(meta.get("test_samples"), int) and int(meta.get("test_samples")) > 0
        return not (has_metrics and has_confusion and has_correlation and has_test_samples)

    if existing_model is not None:
        meta = _read_json_dict(metadata_path)
        if not _metadata_needs_bootstrap_refresh(meta):
            return None
        target_model = existing_model
    else:
        target_model = model_candidates[0]

    models_dir.mkdir(parents=True, exist_ok=True)

    download_url = os.getenv("RANDOM_FOREST_MODEL_URL", RANDOM_FOREST_MODEL_RAW_URL).strip()
    if existing_model is None and download_url:
        try:
            urllib.request.urlretrieve(download_url, target_model)
            if target_model.exists() and target_model.stat().st_size > 0:
                return None
        except Exception:
            pass
        try:
            if target_model.exists() and target_model.stat().st_size == 0:
                target_model.unlink()
        except Exception:
            pass

    bootstrap_script = backend_dir / "scripts" / "bootstrap_random_forest_model.py"
    if not bootstrap_script.exists():
        return (
            "RandomForest model file is missing and bootstrap script is unavailable. "
            "Comparative mode will run without RandomForest."
        )

    code, output = run_command(
        [
            str(backend_python),
            str(bootstrap_script),
            "--model-out",
            str(target_model),
            "--metadata-path",
            str(metadata_path),
        ],
        cwd=backend_dir,
        timeout=1800,
    )
    if code != 0:
        return (
            "RandomForest model file is missing and fallback bootstrap failed.\n"
            f"{output}"
        )

    if target_model.exists() and target_model.stat().st_size > 0:
        return (
            "RandomForest fallback model was generated automatically. "
            "For best accuracy, replace it with a fully trained artifact."
        )

    return "RandomForest model is still unavailable after fallback bootstrap."


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
        code, output = run_command(
            [npm_path, "ci", "--no-audit", "--no-fund"],
            cwd=frontend_dir,
            timeout=3600,
        )
        raw = (output or "").lower()
        if code != 0 and ("npm error code eusage" in raw or "can only install packages when your package.json and package-lock.json" in raw):
            # Lockfile mismatch in ZIP snapshots: fallback to npm install.
            return run_command([npm_path, "install", "--no-audit", "--no-fund"], cwd=frontend_dir, timeout=3600)
        return code, output
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


def _fetch_json(url: str, timeout_seconds: int = 8) -> Optional[dict]:
    try:
        with urllib.request.urlopen(url, timeout=timeout_seconds) as response:
            raw = response.read()
        payload = json.loads(raw.decode("utf-8", errors="replace"))
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def _backend_needs_reload_from_health(health_payload: Optional[dict]) -> bool:
    if not isinstance(health_payload, dict):
        return False
    loaded = health_payload.get("loaded_prediction_models")
    if not isinstance(loaded, list):
        return False
    normalized = {str(item).strip().lower() for item in loaded}
    # Ensure comparative stack includes LightGBM when deps are now available.
    return "lightgbm" not in normalized


def _stop_backend_processes() -> None:
    """Best-effort stop uvicorn backend processes started by launcher."""
    ps_cmd = (
        "Get-CimInstance Win32_Process "
        "| Where-Object { "
        "$_.Name -match '^python(w)?\\.exe$' -and "
        "$_.CommandLine -and $_.CommandLine -match 'backend\\.api_backend:app' "
        "} "
        "| ForEach-Object { "
        "try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop } catch {} "
        "}"
    )
    run_command(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=60)


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
        rf_warning = _ensure_random_forest_artifact(backend_python, backend_dir)
        if rf_warning:
            if optional_warning:
                optional_warning = f"{optional_warning}\n\n{rf_warning}"
            else:
                optional_warning = rf_warning
        npm_path = ensure_frontend_dependencies(frontend_dir)
    except Exception as exc:
        message_box(str(exc), title="Launcher dependency error")
        return 1

    backend_host = "127.0.0.1"
    backend_port = 8000
    backend_health_url = f"http://{backend_host}:{backend_port}/health"
    backend_already_running, _backend_probe = wait_for_http(backend_health_url, timeout_seconds=2)
    if backend_already_running:
        health_payload = _fetch_json(backend_health_url, timeout_seconds=5)
        if _backend_needs_reload_from_health(health_payload):
            print("[launcher] restarting existing backend instance to load missing comparative models.")
            _stop_backend_processes()
            time.sleep(1)
            backend_already_running, _backend_probe = wait_for_http(
                backend_health_url, timeout_seconds=2
            )

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
