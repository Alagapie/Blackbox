"""M4 Witness: an independent notary for the ledger's checkpoints.

The ledger periodically sends {seq, hash} of its latest entry. The witness:
- stores it in its OWN database with its OWN signing key,
- refuses (and records as a conflict) any checkpoint that contradicts what
  it already saw: same seq with a different hash = history rewritten,
  lower seq than before = history cut off / rolled back.

Even an attacker holding the ledger's key can't change what the witness saw.

Run:  python -m witness       (port 8002, data in ./data/witness)
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from core.crypto import canonical_json, load_or_create_keypair, public_key_to_pem, sign

_SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoints (seq INTEGER PRIMARY KEY, record TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS conflicts (id INTEGER PRIMARY KEY AUTOINCREMENT, record TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS cp_no_update BEFORE UPDATE ON checkpoints BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER IF NOT EXISTS cp_no_delete BEFORE DELETE ON checkpoints BEGIN SELECT RAISE(ABORT, 'append-only'); END;
"""


class CheckpointIn(BaseModel):
    seq: int = Field(ge=1)
    hash: str = Field(min_length=64, max_length=64)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Witness:
    def __init__(self, db_path: Union[str, Path], key: Ed25519PrivateKey):
        if str(db_path) != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False, isolation_level=None)
        self._conn.executescript(_SCHEMA)
        self._key = key
        self._lock = threading.Lock()

    @property
    def public_key(self):
        return self._key.public_key()

    def _rows(self, table: str) -> list[dict[str, Any]]:
        order = "seq" if table == "checkpoints" else "id"
        return [json.loads(r[0]) for r in self._conn.execute(f"SELECT record FROM {table} ORDER BY {order}")]

    def checkpoints(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._rows("checkpoints")

    def conflicts(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._rows("conflicts")

    def submit(self, cp: CheckpointIn) -> tuple[int, dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT record FROM checkpoints WHERE seq = ?", (cp.seq,)).fetchone()
            latest = self._conn.execute("SELECT MAX(seq) FROM checkpoints").fetchone()[0] or 0
            reason: Optional[str] = None
            if row:
                if json.loads(row[0])["hash"] == cp.hash:
                    return 200, json.loads(row[0])  # already have it
                reason = f"entry #{cp.seq} was checkpointed earlier with a different hash: history was rewritten"
            elif cp.seq < latest:
                reason = f"ledger head went back from #{latest} to #{cp.seq}: history was cut off"
            if reason:
                conflict = {"seq": cp.seq, "hash": cp.hash, "reason": reason, "received_at": _now()}
                self._conn.execute("INSERT INTO conflicts (record) VALUES (?)", (json.dumps(conflict),))
                return 409, conflict
            body = {"seq": cp.seq, "hash": cp.hash, "received_at": _now()}
            record = {**body, "witness_signature": sign(self._key, canonical_json(body))}
            self._conn.execute("INSERT INTO checkpoints (seq, record) VALUES (?, ?)", (cp.seq, json.dumps(record)))
            return 201, record


def build_default_witness() -> Witness:
    data_dir = Path(os.environ.get("WITNESS_DATA_DIR", "data/witness"))
    return Witness(data_dir / "witness.db", load_or_create_keypair(data_dir / "keys", "witness"))


def create_app(witness: Optional[Witness] = None) -> FastAPI:
    witness = witness or build_default_witness()
    app = FastAPI(title="Blackbox Witness", version="0.1.0")
    app.state.witness = witness

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/checkpoints")
    def submit(cp: CheckpointIn):
        code, body = witness.submit(cp)
        return JSONResponse(body, status_code=code)

    @app.get("/checkpoints")
    def list_checkpoints():
        return witness.checkpoints()

    @app.get("/conflicts")
    def list_conflicts():
        return witness.conflicts()

    @app.get("/public-key", response_class=PlainTextResponse)
    def public_key():
        return public_key_to_pem(witness.public_key).decode()

    return app
