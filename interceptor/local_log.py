"""The ordinary local audit log, a deliberate DECOY.

It lives inside the agent's workspace, so the agent CAN edit or delete it,
just like logs in real systems today. Each line includes the ledger seq,
so the verifier (M6) can compare it with the ledger and say exactly what
the agent removed or changed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class LocalLog:
    def __init__(self, path: Path):
        self.path = path

    def write(self, entry: dict[str, Any]) -> None:
        # Best effort: if the agent deleted the folder, recreate it. A
        # broken local log must never stop recording to the ledger.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
        except OSError:
            pass

    def read(self) -> list[dict[str, Any]]:
        """Parse the log. Unreadable lines are returned as {'_corrupt': line}."""
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({"_corrupt": line})
        return out
