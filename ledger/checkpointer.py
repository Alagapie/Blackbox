"""Background thread: every few seconds, send the ledger head to the witness (M4)."""

from __future__ import annotations

import logging
import threading
from typing import Optional

import httpx

from ledger.ledger import Ledger

log = logging.getLogger("blackbox.checkpointer")


class Checkpointer:
    def __init__(self, ledger: Ledger, witness_url: str, interval: float = 2.0,
                 http: Optional[httpx.Client] = None):
        self._ledger = ledger
        self._http = http or httpx.Client(base_url=witness_url, timeout=5)
        self._interval = interval
        self._last: Optional[dict] = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="checkpointer")
        self.conflicts = 0

    def start(self) -> "Checkpointer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()

    def push_once(self) -> Optional[int]:
        head = self._ledger.head()
        if head["seq"] == 0 or head == self._last:
            return None
        try:
            r = self._http.post("/checkpoints", json=head)
        except httpx.HTTPError as e:
            log.warning("witness unreachable: %s", e)
            return None
        if r.status_code == 409:
            self.conflicts += 1
            log.warning("witness REJECTED checkpoint: %s", r.json().get("reason"))
        self._last = head  # don't resend the same head every tick
        return r.status_code

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            self.push_once()
