"""Measure what Blackbox costs: ledger write latency, interceptor overhead per action,
and how long a full verification takes. Uses a real HTTP ledger on a spare port.

    python scripts/benchmark.py
"""

from __future__ import annotations

import json
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn  # noqa: E402

from core.crypto import generate_private_key  # noqa: E402
from interceptor import Interceptor, LedgerClient  # noqa: E402
from ledger.ledger import Ledger  # noqa: E402
from ledger.server import create_app  # noqa: E402
from ledger.storage import LedgerStorage  # noqa: E402
from verifier import load_from_db, verify  # noqa: E402

PORT = 8011


def pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def summary(xs_s: list[float]) -> dict[str, float]:
    ms = [x * 1000 for x in xs_s]
    return {"median_ms": round(statistics.median(ms), 2), "p95_ms": round(pct(ms, 95), 2), "n": len(ms)}


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="bb-bench-"))
    ledger = Ledger(LedgerStorage(tmp / "ledger.db"), generate_private_key())
    server = uvicorn.Server(uvicorn.Config(create_app(ledger), port=PORT, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)

    ws = tmp / "ws"
    guard = Interceptor(LedgerClient("bench", base_url=f"http://127.0.0.1:{PORT}", session_id="bench"), ws)
    ws.mkdir(parents=True, exist_ok=True)

    # 1. Direct tool call (no oversight) vs the same call through the interceptor.
    direct, guarded = [], []
    for i in range(300):
        t = time.perf_counter()
        (ws / f"d{i}.txt").write_text("x" * 100)
        direct.append(time.perf_counter() - t)
        t = time.perf_counter()
        guard.execute("write_file", {"path": f"g{i}.txt", "content": "x" * 100})
        guarded.append(time.perf_counter() - t)

    # 2. One ledger append over HTTP (hash + sign + SQLite write + network).
    appends = []
    from core.events import EventType
    for _ in range(500):
        t = time.perf_counter()
        guard._client.record(EventType.HEARTBEAT)
        appends.append(time.perf_counter() - t)

    server.should_exit = True
    time.sleep(0.3)

    # 3. Full verification of the resulting ledger.
    records = load_from_db(tmp / "ledger.db")
    t = time.perf_counter()
    rep = verify(records, ledger.public_key)
    verify_s = time.perf_counter() - t

    out = {
        "direct_write_file": summary(direct),
        "interceptor_write_file": summary(guarded),
        "ledger_append_http": summary(appends),
        "verify": {"entries": len(records), "seconds": round(verify_s, 3),
                   "entries_per_second": round(len(records) / verify_s), "status": rep.status},
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
