"""Start the whole Blackbox system with one command.

    .venv\\Scripts\\python run.py            # keep existing data
    .venv\\Scripts\\python run.py --fresh    # wipe data/ and start a clean demo

Starts:  witness   http://127.0.0.1:8002   (M4)
         ledger    http://127.0.0.1:8001   (M2, checkpoints to the witness)
         dashboard http://127.0.0.1:8000   (M7)  <- open this
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))

os.environ.setdefault("LEDGER_DATA_DIR", "data/ledger")
os.environ.setdefault("WITNESS_DATA_DIR", "data/witness")
os.environ.setdefault("LEDGER_URL", "http://127.0.0.1:8001")
os.environ.setdefault("WITNESS_URL", "http://127.0.0.1:8002")

import httpx  # noqa: E402
import uvicorn  # noqa: E402


def serve_in_thread(app, port: int) -> None:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True, name=f"server-{port}").start()
    for _ in range(100):
        try:
            httpx.get(f"http://127.0.0.1:{port}/health", timeout=1)
            return
        except httpx.HTTPError:
            time.sleep(0.1)
    raise SystemExit(f"server on port {port} did not start (is the port already in use?)")


def main() -> None:
    if "--fresh" in sys.argv and Path("data").exists():
        shutil.rmtree("data")
        print("Wiped data/ for a fresh demo.")

    from witness.server import create_app as witness_app
    from ledger.server import create_app as ledger_app

    serve_in_thread(witness_app(), 8002)
    print("  witness   http://127.0.0.1:8002")
    serve_in_thread(ledger_app(), 8001)
    print("  ledger    http://127.0.0.1:8001   (API docs at /docs)")

    from dashboard.app import app as dashboard_app
    print("  dashboard http://127.0.0.1:8000   <- open this")
    print("Press Ctrl+C to stop.")
    if "--no-browser" not in sys.argv:
        threading.Timer(1.5, lambda: webbrowser.open("http://127.0.0.1:8000")).start()
    uvicorn.run(dashboard_app, host="127.0.0.1", port=8000, log_level="warning")


if __name__ == "__main__":
    main()
