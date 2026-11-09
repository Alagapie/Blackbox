"""What the verifier reports: findings and the overall report."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

# Severity
CRITICAL = "critical"  # proof of tampering or a cover-up
HIGH = "high"          # strong evidence of concealment or deception
WARNING = "warning"    # suspicious, needs a human look
INFO = "info"

# Category: lets the dashboard separate "is the record intact?" from "what did the agent do?"
INTEGRITY = "integrity"  # the ledger itself was altered
COVERUP = "coverup"      # the agent tried to hide or alter its own trail
HONESTY = "honesty"      # the agent's report doesn't match the record
LIVENESS = "liveness"    # silence / missing results


@dataclass
class Finding:
    type: str
    severity: str
    category: str
    message: str
    seqs: list[int] = field(default_factory=list)
    session_id: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    findings: list[Finding]
    entries_checked: int
    sessions: list[str]

    @property
    def ledger_intact(self) -> bool:
        return not any(f.category == INTEGRITY for f in self.findings)

    @property
    def status(self) -> str:
        sev = {f.severity for f in self.findings}
        if CRITICAL in sev:
            return "TAMPERED"
        if HIGH in sev or WARNING in sev:
            return "SUSPICIOUS"
        return "VERIFIED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "ledger_intact": self.ledger_intact,
            "entries_checked": self.entries_checked,
            "sessions": self.sessions,
            "findings": [f.to_dict() for f in self.findings],
        }


def ranges(nums: list[int]) -> str:
    """[3,4,5,8] -> '#3-#5, #8'"""
    nums = sorted(set(nums))
    if not nums:
        return ""
    parts, start, prev = [], nums[0], nums[0]
    for n in nums[1:] + [None]:  # type: ignore[list-item]
        if n is not None and n == prev + 1:
            prev = n
            continue
        parts.append(f"#{start}" if start == prev else f"#{start}-#{prev}")
        if n is not None:
            start = prev = n
    return ", ".join(parts)
