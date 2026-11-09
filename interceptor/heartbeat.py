"""Sends a heartbeat to the ledger every few seconds.

If heartbeats stop, the verifier (M6) flags the silence: the agent side
may have been killed or disconnected to hide what happens next.
"""

from __future__ import annotations

import threading

from core.events import EventType
from interceptor.client import LedgerClient, LedgerUnavailable


class Heartbeat:
    def __init__(self, client: LedgerClient, interval: float = 5.0):
        self._client = client
        self._interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="heartbeat")
        self.sent = 0
        self.failed = 0

    def start(self) -> "Heartbeat":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=self._interval + 1)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._client.record(EventType.HEARTBEAT, result={"interval_s": self._interval})
                self.sent += 1
            except LedgerUnavailable:
                self.failed += 1
            self._stop.wait(self._interval)
