"""Talks to the ledger (M2). Numbers each event with client_seq.

If the ledger can't be reached, record() raises LedgerUnavailable, and the
interceptor uses that to REFUSE the action (fail closed).
"""

from __future__ import annotations

import threading
import uuid
from typing import Any, Optional

import httpx

from core.events import EventIn, EventType


class LedgerUnavailable(Exception):
    """The event could not be recorded, so the action must not happen."""


class LedgerClient:
    def __init__(
        self,
        agent_id: str,
        base_url: str = "http://127.0.0.1:8001",
        http: Optional[httpx.Client] = None,
        timeout: float = 5.0,
        session_id: Optional[str] = None,
    ):
        self.agent_id = agent_id
        self.session_id = session_id or uuid.uuid4().hex[:12]
        self._http = http or httpx.Client(base_url=base_url, timeout=timeout)
        self._client_seq = 0
        # One lock around numbering AND sending, so client_seq order matches
        # ledger order even with the heartbeat thread sending at the same time.
        self._lock = threading.Lock()

    def record(
        self,
        event_type: EventType,
        action: Optional[str] = None,
        args: Optional[dict[str, Any]] = None,
        result: Optional[dict[str, Any]] = None,
        ref_seq: Optional[int] = None,
    ) -> dict[str, Any]:
        with self._lock:
            event = EventIn(
                agent_id=self.agent_id,
                session_id=self.session_id,
                event_type=event_type,
                client_seq=self._client_seq + 1,
                action=action,
                args=args or {},
                result=result,
                ref_seq=ref_seq,
            )
            try:
                resp = self._http.post("/events", json=event.model_dump(mode="json"))
                resp.raise_for_status()
            except httpx.HTTPError as e:
                # Don't advance client_seq: nothing was recorded.
                raise LedgerUnavailable(f"{type(e).__name__}: {e}") from e
            self._client_seq += 1
            return resp.json()
