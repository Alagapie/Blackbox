"""The ledger's core logic: number, chain, sign, store.

The ledger, not the client, decides seq, timestamp and prev_hash. The
private key lives only here.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core.events import EventIn, seal
from ledger.storage import LedgerStorage


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Ledger:
    def __init__(
        self,
        storage: LedgerStorage,
        private_key: Ed25519PrivateKey,
        clock: Callable[[], str] = _utc_now,
    ):
        self._storage = storage
        self._key = private_key
        self._clock = clock
        # Reading the head and inserting the next record must be one step,
        # or two concurrent appends could both link to the same prev_hash.
        self._append_lock = threading.Lock()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def append(self, event: EventIn) -> dict[str, Any]:
        with self._append_lock:
            last_seq, last_hash = self._storage.head()
            body = {
                **event.model_dump(mode="json"),
                "seq": last_seq + 1,
                "timestamp": self._clock(),
                "prev_hash": last_hash,
            }
            record = seal(body, self._key)
            self._storage.append(record)
            return record

    def get(self, seq: int) -> Optional[dict[str, Any]]:
        return self._storage.get(seq)

    def list(self, from_seq: int = 1, limit: int = 100) -> list[dict[str, Any]]:
        return self._storage.list(from_seq, limit)

    def head(self) -> dict[str, Any]:
        seq, digest = self._storage.head()
        return {"seq": seq, "hash": digest}
