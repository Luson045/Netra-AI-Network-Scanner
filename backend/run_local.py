"""Start the local Netra AI API, dashboard, and scan worker with one command."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

import uvicorn

from app.core.utils import safe_init_db


def main() -> None:
    backend_dir = Path(__file__).resolve().parent
    if "--netra-worker" in sys.argv:
        from app.workers.scan_worker import main as worker_main

        worker_main()
        return

    run_dir = backend_dir
    if getattr(sys, "frozen", False):
        local_app_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        run_dir = local_app_data / "Netra AI"
        (run_dir / "data").mkdir(parents=True, exist_ok=True)
        database_path = (run_dir / "data" / "netguard.db").as_posix()
        os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{database_path}"
    run_dir.mkdir(parents=True, exist_ok=True)

    asyncio.run(safe_init_db())
    worker_command = (
        [sys.executable, "--netra-worker"]
        if getattr(sys, "frozen", False)
        else [sys.executable, "-m", "app.workers.scan_worker"]
    )
    worker = subprocess.Popen(
        worker_command,
        cwd=run_dir,
    )
    try:
        threading.Timer(1.5, webbrowser.open, args=("http://127.0.0.1:8000",)).start()
        uvicorn.run("app.main:app", host="127.0.0.1", port=8000)
    finally:
        if worker.poll() is None:
            worker.terminate()
            try:
                worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait()


if __name__ == "__main__":
    main()
