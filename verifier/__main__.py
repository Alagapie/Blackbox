"""Run the verifier and print a report.

Examples:
  python -m verifier                                   # live ledger at :8001, pinned key from data/ledger/keys
  python -m verifier --local-log data/demo_workspace/logs/audit.log
  python -m verifier --db data/ledger/ledger.db        # read the db file directly (after an attack)
  python -m verifier --llm                             # add the AI honesty auditor (uses .env)
  python -m verifier --json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from interceptor.local_log import LocalLog  # noqa: E402
from verifier.findings import CRITICAL, HIGH, INFO, WARNING  # noqa: E402
from verifier.verify import load_from_api, load_from_db, load_key, verify  # noqa: E402

ICON = {CRITICAL: "[CRITICAL]", HIGH: "[HIGH]    ", WARNING: "[WARNING] ", INFO: "[info]    "}
BANNER = {"VERIFIED": "VERIFIED: no problems found",
          "SUSPICIOUS": "SUSPICIOUS: needs human review",
          "TAMPERED": "TAMPERING / COVER-UP DETECTED"}


def main() -> int:
    ap = argparse.ArgumentParser(description="Blackbox verifier")
    ap.add_argument("--ledger-url", default="http://127.0.0.1:8001")
    ap.add_argument("--db", type=Path, help="read records from this ledger.db instead of the API")
    ap.add_argument("--public-key", type=Path, default=Path("data/ledger/keys/ledger_public.pem"))
    ap.add_argument("--local-log", type=Path, help="agent-side audit.log to compare with the ledger")
    ap.add_argument("--session", help="session id the local log belongs to (if its lines lack one)")
    ap.add_argument("--checkpoints", type=Path, help="JSON list of witness checkpoints [{seq, hash}]")
    ap.add_argument("--llm", action="store_true", help="also run the AI honesty auditor")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    records = load_from_db(a.db) if a.db else load_from_api(a.ledger_url)
    key = load_key(a.public_key, None if a.db else a.ledger_url)
    local = LocalLog(a.local_log).read() if a.local_log else None
    cps = json.loads(a.checkpoints.read_text()) if a.checkpoints else None
    auditor = None
    if a.llm:
        from verifier.honesty import make_llm_auditor
        auditor = make_llm_auditor()

    report = verify(records, key, local_log=local, local_session=a.session, checkpoints=cps,
                    now=datetime.now(timezone.utc), llm_auditor=auditor)

    if a.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print("=" * 72)
        print(f" {BANNER[report.status]}")
        print(f" Ledger integrity: {'INTACT' if report.ledger_intact else 'COMPROMISED'}   "
              f"entries checked: {report.entries_checked}   sessions: {len(report.sessions)}")
        print("=" * 72)
        for f in report.findings:
            print(f"{ICON.get(f.severity, f.severity)} {f.category:<9} {f.message}")
        if not report.findings:
            print(" Every entry is correctly chained and signed. Nothing hidden.")
    return {"VERIFIED": 0, "SUSPICIOUS": 1, "TAMPERED": 2}[report.status]


if __name__ == "__main__":
    sys.exit(main())
