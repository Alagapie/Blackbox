"""HTTP API for the ledger.

Run:  python -m ledger            (defaults: port 8001, data in ./data/ledger)

Note what is NOT here: no PUT, PATCH or DELETE. Clients can only append
and read.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse

from core.crypto import load_or_create_keypair, public_key_to_pem
from core.events import EventIn
from ledger.ledger import Ledger
from ledger.storage import LedgerStorage


def build_default_ledger() -> Ledger:
    data_dir = Path(os.environ.get("LEDGER_DATA_DIR", "data/ledger"))
    key = load_or_create_keypair(data_dir / "keys", "ledger")
    storage = LedgerStorage(data_dir / "ledger.db")
    return Ledger(storage, key)


def create_app(ledger: Optional[Ledger] = None) -> FastAPI:
    ledger = ledger or build_default_ledger()
    app = FastAPI(title="Blackbox Ledger", version="0.1.0")
    app.state.ledger = ledger
    witness_url = os.environ.get("WITNESS_URL")
    if witness_url:
        from ledger.checkpointer import Checkpointer
        app.state.checkpointer = Checkpointer(
            ledger, witness_url, float(os.environ.get("CHECKPOINT_INTERVAL", "2"))).start()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/events", status_code=201)
    def append_event(event: EventIn):
        return ledger.append(event)

    @app.get("/events")
    def list_events(
        from_seq: int = Query(1, ge=1),
        limit: int = Query(100, ge=1, le=1000),
    ):
        return ledger.list(from_seq, limit)

    @app.get("/events/{seq}")
    def get_event(seq: int):
        record = ledger.get(seq)
        if record is None:
            raise HTTPException(status_code=404, detail=f"no event with seq {seq}")
        return record

    @app.get("/head")
    def head():
        return ledger.head()

    @app.get("/public-key", response_class=PlainTextResponse)
    def public_key():
        return public_key_to_pem(ledger.public_key).decode()

    return app
