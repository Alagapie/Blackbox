"""Runs every check and produces one Report. Also loads ledger records."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.crypto import load_public_key
from verifier import checks
from verifier.findings import CRITICAL, HIGH, INFO, INTEGRITY, WARNING, Finding, Report
from verifier.honesty import rule_based_check

Record = dict[str, Any]
_ORDER = {CRITICAL: 0, HIGH: 1, WARNING: 2, INFO: 3}


def verify(
    records: list[Record],
    public_key: Ed25519PublicKey,
    local_log: Optional[list[dict[str, Any]]] = None,
    local_session: Optional[str] = None,
    checkpoints: Optional[list[dict[str, Any]]] = None,
    audit_log_hints: Iterable[str] = checks.DEFAULT_AUDIT_LOG_HINTS,
    now: Optional[datetime] = None,
    llm_auditor: Optional[Callable[[list[Record]], list[Finding]]] = None,
    local_logs: Optional[dict[str, list[dict[str, Any]]]] = None,
    witness_conflicts: Optional[list[dict[str, Any]]] = None,
) -> Report:
    """local_logs: {session_id: local log entries} for several agents at once.
    witness_conflicts: checkpoints the witness refused (see M4)."""
    findings: list[Finding] = []
    findings += checks.check_chain(records, public_key)
    findings += checks.check_client_seq(records)
    findings += checks.check_liveness(records, now=now)
    findings += checks.check_unmatched(records)
    findings += checks.check_tamper_attempts(records, audit_log_hints)
    if local_log is not None:
        findings += checks.compare_local_log(local_log, records, local_session)
    for session, entries in (local_logs or {}).items():
        findings += checks.compare_local_log(entries, records, session)
    if checkpoints:
        findings += checks.check_checkpoints(records, checkpoints)
    for c in witness_conflicts or []:
        findings.append(Finding("witness_conflict", CRITICAL, INTEGRITY,
                                f"The witness refused a checkpoint from the ledger at {c.get('received_at')}: "
                                f"{c.get('reason')}.", seqs=[c["seq"]] if isinstance(c.get("seq"), int) else []))
    findings += rule_based_check(records)
    if llm_auditor is not None:
        findings += llm_auditor(records)
    findings.sort(key=lambda f: (_ORDER.get(f.severity, 9), f.seqs[0] if f.seqs else 0))
    sessions = sorted({str(r.get("session_id")) for r in records})
    return Report(findings=findings, entries_checked=len(records), sessions=sessions)


# --- loading records ----------------------------------------------------------------------

def load_from_api(base_url: str, page: int = 1000) -> list[Record]:
    out: list[Record] = []
    with httpx.Client(base_url=base_url, timeout=10) as c:
        while True:
            batch = c.get("/events", params={"from_seq": (out[-1]["seq"] + 1) if out else 1, "limit": page}).json()
            out += batch
            if len(batch) < page:
                return out


def load_from_db(path: Path) -> list[Record]:
    """Read the database file directly, e.g. after an attacker edited it."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return [json.loads(row[0]) for row in conn.execute("SELECT record FROM events ORDER BY seq")]
    finally:
        conn.close()


def load_key(pem_path: Optional[Path] = None, base_url: Optional[str] = None) -> Ed25519PublicKey:
    """Prefer a PINNED key file. Fetching it from the ledger is weaker: a
    compromised ledger could hand out the attacker's key."""
    if pem_path and pem_path.exists():
        return load_public_key(pem_path.read_bytes())
    if base_url:
        return load_public_key(httpx.get(f"{base_url}/public-key", timeout=10).text.encode())
    raise FileNotFoundError("no public key: pass --public-key or --ledger-url")
