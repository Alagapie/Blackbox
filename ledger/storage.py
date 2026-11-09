"""SQLite storage for the ledger. Append-only by design.

Two layers of protection:
1. This class simply has no update or delete method.
2. Database triggers refuse UPDATE/DELETE even from other code.

Neither layer stops someone who edits the .db file directly. That's on
purpose: the cryptography (hash chain + signatures + witness) is what
catches that case, and the attack simulator (M8) will prove it.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional, Union

from core.events import GENESIS_HASH

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq    INTEGER PRIMARY KEY,
    hash   TEXT NOT NULL,
    record TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'ledger is append-only: updates are forbidden'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'ledger is append-only: deletes are forbidden'); END;
"""


class LedgerStorage:
    def __init__(self, path: Union[str, Path]):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)

    def head(self) -> tuple[int, str]:
        """(latest seq, latest hash), or (0, GENESIS_HASH) if empty."""
        with self._lock:
            row = self._conn.execute(
                "SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        return (row[0], row[1]) if row else (0, GENESIS_HASH)

    def append(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO events (seq, hash, record) VALUES (?, ?, ?)",
                (record["seq"], record["hash"], json.dumps(record)),
            )

    def get(self, seq: int) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT record FROM events WHERE seq = ?", (seq,)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, from_seq: int = 1, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT record FROM events WHERE seq >= ? ORDER BY seq LIMIT ?",
                (from_seq, limit),
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
