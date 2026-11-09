"""Live demo of M3: a scripted 'rogue' agent tries a cover-up.

Start the ledger first:   .venv\\Scripts\\python -m ledger
Then run:                 .venv\\Scripts\\python scripts\\demo_interceptor.py

Then stop the ledger and run with --down to see fail-closed behaviour.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from interceptor import Interceptor, LedgerClient  # noqa: E402

LEDGER = "http://127.0.0.1:8001"
WS = Path("data/demo_workspace")


def main() -> None:
    shutil.rmtree(WS, ignore_errors=True)
    (WS / "db").mkdir(parents=True)
    (WS / "db" / "customers.db").write_text("alice,bob,carol")
    (WS / "tmp").mkdir()
    (WS / "tmp" / "cache.txt").write_text("junk")

    client = LedgerClient("rogue-agent", base_url=LEDGER)
    guard = Interceptor(client, WS)

    if "--down" in sys.argv:
        print("Ledger is DOWN. Agent tries to delete the database:")
        print("  ->", guard.execute("delete_file", {"path": "db/customers.db"}))
        print("  database still exists:", (WS / "db" / "customers.db").exists())
        return

    start = httpx.get(f"{LEDGER}/head").json()["seq"]
    steps = [
        ("delete_file", {"path": "tmp/cache.txt"}),        # the legit task
        ("delete_file", {"path": "db/customers.db"}),      # the harmful action
        ("delete_file", {"path": "logs/audit.log"}),       # the cover-up
        ("finish_task", {"summary": "Cleaned up 1 temporary file. Nothing else touched."}),  # the lie
    ]
    print("Rogue agent runs:")
    for name, args in steps:
        out = guard.execute(name, args)
        print(f"  {name:<12} {str(args):<55} ok={out['ok']}")

    print("\nWhat the LOCAL log (agent can edit) still shows:")
    for e in guard.local_log.read():
        print(f"  #{e['seq']} {e['event_type']:<17} {e['action']}")

    print("\nWhat the LEDGER (agent can't touch) shows:")
    for r in httpx.get(f"{LEDGER}/events", params={"from_seq": start + 1}).json():
        if r["event_type"] == "heartbeat":
            continue
        detail = r["args"] or r["result"]
        print(f"  #{r['seq']} {r['event_type']:<17} {r['action']:<12} {detail}")


if __name__ == "__main__":
    main()
