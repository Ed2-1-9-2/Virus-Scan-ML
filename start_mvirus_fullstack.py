"""One-click launcher that auto-updates from GitHub and starts the full stack.

Behavior on startup:
1) Ensure local repository exists (clone if missing).
2) Pull latest changes from GitHub main branch.
3) Start backend and frontend in separate PowerShell windows.
4) Open browser at http://localhost:3000
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

REPO_URL = "https://github.com/Ed2-1-9-2/Virus-Scan-ML.git"
REPO_DIR_NAME = "Virus-Scan-ML"
REPO_BRANCH = "main"


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


def resolve_repo_root(base: Path) -> Path:
    """Resolve or clone local repository folder."""
    if (base / ".git").exists():
        return base

    nested = base / REPO_DIR_NAME
    if (nested / ".git").exists():
        return nested

    if nested.exists() and any(nested.iterdir()):
        raise RuntimeError(f"Folder exists but is not a git repo: {nested}")

    nested.mkdir(parents=True, exist_ok=True)
    code, output = run_command(["git", "clone", REPO_URL, str(nested)], cwd=base, timeout=600)
    if code != 0:
        raise RuntimeError(f"git clone failed:\n{output}")
    return nested


def update_repo(repo_root: Path) -> None:
    """Fetch and pull latest code from GitHub."""
    code, output = run_command(["git", "-C", str(repo_root), "fetch", "origin", REPO_BRANCH], timeout=120)
    if code != 0:
        raise RuntimeError(f"git fetch failed:\n{output}")

    code, output = run_command(
        ["git", "-C", str(repo_root), "pull", "--ff-only", "origin", REPO_BRANCH],
        timeout=180,
    )
    if code != 0:
        raise RuntimeError(f"git pull failed:\n{output}")


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


def ensure_backend_python(backend_dir: Path) -> Path:
    """Ensure backend virtual environment exists."""
    backend_python = backend_dir / ".venv" / "Scripts" / "python.exe"
    if backend_python.exists():
        return backend_python

    code, output = run_command(["py", "-3.10", "-m", "venv", ".venv"], cwd=backend_dir, timeout=300)
    if code != 0:
        raise RuntimeError(f"Could not create backend virtualenv:\n{output}")

    backend_python = backend_dir / ".venv" / "Scripts" / "python.exe"
    code, output = run_command(
        [str(backend_python), "-m", "pip", "install", "-r", "config/requirements-api.txt"],
        cwd=backend_dir,
        timeout=900,
    )
    if code != 0:
        raise RuntimeError(f"Could not install backend dependencies:\n{output}")
    return backend_python


def ensure_frontend_dependencies(frontend_dir: Path) -> None:
    """Install frontend dependencies if node_modules is missing."""
    if (frontend_dir / "node_modules").exists():
        return

    code, output = run_command(["npm", "install"], cwd=frontend_dir, timeout=900)
    if code != 0:
        raise RuntimeError(f"Could not install frontend dependencies:\n{output}")


def main() -> int:
    root = base_dir()

    try:
        repo_root = resolve_repo_root(root)
        update_repo(repo_root)
    except Exception as exc:
        message_box(f"Could not update from GitHub:\n{exc}", title="Launcher update error")
        return 1

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

    try:
        backend_python = ensure_backend_python(backend_dir)
        ensure_frontend_dependencies(frontend_dir)
    except Exception as exc:
        message_box(str(exc), title="Launcher dependency error")
        return 1

    backend_cmd = (
        f'Set-Location "{backend_dir}"; '
        f'& "{backend_python}" -m backend.api_backend'
    )
    frontend_cmd = (
        f'Set-Location "{frontend_dir}"; '
        "npm start"
    )

    try:
        start_in_new_console(backend_cmd)
        time.sleep(2)
        start_in_new_console(frontend_cmd)
        time.sleep(3)
        webbrowser.open("http://localhost:3000")
    except Exception as exc:
        message_box(f"Could not start services:\n{exc}", title="Launcher runtime error")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
