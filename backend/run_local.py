"""Start the local NetGuard API, dashboard, and scan worker with one command."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path

import uvicorn

from app.core.utils import safe_init_db


def main() -> None:
    backend_dir = Path(__file__).resolve().parent
    asyncio.run(safe_init_db())
    worker = subprocess.Popen(
        [sys.executable, "-m", "app.workers.scan_worker"],
        cwd=backend_dir,
    )
    try:
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
