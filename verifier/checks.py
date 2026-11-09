"""The individual checks. Each takes ledger records and returns findings.

Records are the sealed dicts from the ledger, in ledger order.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from typing import Any, Iterable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.events import GENESIS_HASH, check_record
from verifier.findings import (
    COVERUP,
    CRITICAL,
    HIGH,
    INFO,
    INTEGRITY,
    LIVENESS,
    WARNING,
    Finding,
    ranges,
)

Record = dict[str, Any]

# Paths that count as "the agent's own audit trail".
DEFAULT_AUDIT_LOG_HINTS = ("audit.log", "logs/audit", "logs\\audit")

# Fields compared between the local log and the ledger.
_COMPARED = ("event_type", "action", "args", "result", "ref_seq", "timestamp")


def by_session(records: Iterable[Record]) -> dict[str, list[Record]]:
    out: dict[str, list[Record]] = defaultdict(list)
    for r in records:
        out[str(r.get("session_id"))].append(r)
    return dict(out)


def _ts(r: Record) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(r["timestamp"])
    except (KeyError, TypeError, ValueError):
        return None


# 1. Chain integrity ------------------------------------------------------------

def check_chain(records: list[Record], public_key: Ed25519PublicKey) -> list[Finding]:
    """Hash, signature, links and numbering of the WHOLE ledger."""
    findings: list[Finding] = []
    expected, prev_hash = 1, GENESIS_HASH
    for r in records:
        seq = r.get("seq")
        if not isinstance(seq, int):
            findings.append(Finding("malformed_entry", CRITICAL, INTEGRITY, f"An entry has no valid number: {seq!r}."))
            continue
        if seq > expected:
            missing = list(range(expected, seq))
            findings.append(Finding("seq_gap", CRITICAL, INTEGRITY,
                                    f"Ledger entries {ranges(missing)} are missing: they were deleted from the ledger.",
                                    seqs=missing))
        elif seq < expected:
            findings.append(Finding("seq_out_of_order", CRITICAL, INTEGRITY,
                                    f"Entry #{seq} is duplicated or out of order (expected #{expected}).", seqs=[seq]))
        if r.get("prev_hash") != prev_hash:
            findings.append(Finding("broken_link", CRITICAL, INTEGRITY,
                                    f"Entry #{seq} no longer links to the entry before it: "
                                    f"the history before #{seq} was rewritten or removed.", seqs=[seq]))
        for problem in check_record(r, public_key):
            if problem == "hash_mismatch":
                msg = f"Entry #{seq} was edited after it was recorded: its content no longer matches its fingerprint."
            else:
                msg = f"Entry #{seq} has no valid ledger signature: it was forged or rewritten."
            findings.append(Finding(problem, CRITICAL, INTEGRITY, msg, seqs=[seq], session_id=r.get("session_id")))
        prev_hash = r.get("hash")
        expected = max(expected, seq + 1)
    return findings


# 2. Client numbering -------------------------------------------------------------

def check_client_seq(records: list[Record]) -> list[Finding]:
    """The interceptor numbers events 1,2,3... per session. A gap means an event
    reached the ledger and was later removed, even if the ledger was renumbered."""
    findings: list[Finding] = []
    for session, recs in by_session(records).items():
        expected = 1
        for r in recs:
            cs = r.get("client_seq")
            if not isinstance(cs, int):
                continue
            if cs > expected:
                findings.append(Finding("client_seq_gap", CRITICAL, INTEGRITY,
                                        f"Session {session}: the agent side sent events {expected}-{cs - 1} "
                                        f"but they are not in the ledger (removed).",
                                        seqs=[r["seq"]], session_id=session,
                                        details={"missing_client_seq": list(range(expected, cs))}))
            elif cs < expected:
                findings.append(Finding("client_seq_replay", CRITICAL, INTEGRITY,
                                        f"Session {session}: event number {cs} appears twice or out of order "
                                        f"(entry #{r['seq']}): possible replay or forgery.",
                                        seqs=[r["seq"]], session_id=session))
            expected = max(expected, cs + 1)
    return findings


# 3. Liveness ---------------------------------------------------------------------

def check_liveness(records: list[Record], now: Optional[datetime] = None, tolerance: float = 3.0) -> list[Finding]:
    """Sessions that send heartbeats must not go quiet for more than tolerance x interval."""
    findings: list[Finding] = []
    for session, recs in by_session(records).items():
        intervals = [r["result"].get("interval_s") for r in recs
                     if r.get("event_type") == "heartbeat" and isinstance(r.get("result"), dict)]
        intervals = [i for i in intervals if isinstance(i, (int, float)) and i > 0]
        if not intervals:
            continue
        allowed = max(intervals) * tolerance
        prev: Optional[Record] = None
        for r in recs:
            if prev is not None:
                a, b = _ts(prev), _ts(r)
                if a and b and (b - a).total_seconds() > allowed:
                    gap = (b - a).total_seconds()
                    findings.append(Finding("heartbeat_gap", WARNING, LIVENESS,
                                            f"Session {session} went silent for {gap:.0f}s between #{prev['seq']} "
                                            f"and #{r['seq']} (allowed {allowed:.0f}s): the agent side was "
                                            f"disconnected or paused.",
                                            seqs=[prev["seq"], r["seq"]], session_id=session,
                                            details={"gap_seconds": round(gap, 1)}))
            prev = r
        finished = any(r.get("event_type") == "agent_report" for r in recs)
        last = _ts(recs[-1])
        if now and last and not finished and (now - last).total_seconds() > allowed:
            silent = (now - last).total_seconds()
            findings.append(Finding("session_silent", WARNING, LIVENESS,
                                    f"Session {session} has been silent for {silent:.0f}s since #{recs[-1]['seq']} "
                                    f"without finishing: the agent side stopped reporting.",
                                    seqs=[recs[-1]["seq"]], session_id=session,
                                    details={"silent_seconds": round(silent, 1)}))
    return findings


# 4. Requests without results -------------------------------------------------------

def check_unmatched(records: list[Record]) -> list[Finding]:
    findings: list[Finding] = []
    results: dict[int, Record] = {}
    requests = {r["seq"]: r for r in records if r.get("event_type") == "action_requested"}
    for r in records:
        if r.get("event_type") in ("action_completed", "action_failed"):
            ref = r.get("ref_seq")
            req = requests.get(ref) if isinstance(ref, int) else None
            if req is None or req.get("session_id") != r.get("session_id") or req.get("action") != r.get("action"):
                findings.append(Finding("orphan_result", WARNING, LIVENESS,
                                        f"Entry #{r['seq']} is a result for request #{ref}, which doesn't exist "
                                        f"or doesn't match.", seqs=[r["seq"]], session_id=r.get("session_id")))
            else:
                results[ref] = r
    for seq, req in requests.items():
        if seq not in results:
            findings.append(Finding("request_without_result", HIGH, LIVENESS,
                                    f"The agent requested {req.get('action')} {json.dumps(req.get('args'))} "
                                    f"(#{seq}) but no result was ever recorded: the action may have run while "
                                    f"its outcome was hidden.", seqs=[seq], session_id=req.get("session_id")))
    return findings


# 5. Cover-up attempts (found from the ledger alone) ----------------------------------

def check_tamper_attempts(records: list[Record], hints: Iterable[str] = DEFAULT_AUDIT_LOG_HINTS) -> list[Finding]:
    """Any action aimed at the agent's own audit log is itself evidence."""
    hints = [h.lower() for h in hints]
    outcome = {r.get("ref_seq"): r for r in records if r.get("event_type") in ("action_completed", "action_failed")}
    findings: list[Finding] = []
    for r in records:
        if r.get("event_type") != "action_requested":
            continue
        text = json.dumps(r.get("args"), ensure_ascii=False).lower().replace("\\\\", "\\")
        if not any(h in text for h in hints):
            continue
        if r.get("action") in ("read_file", "list_files"):
            continue  # looking at the log isn't a cover-up
        res = outcome.get(r["seq"])
        succeeded = bool(res and res.get("event_type") == "action_completed" and (res.get("result") or {}).get("ok"))
        findings.append(Finding("audit_log_tamper_attempt", CRITICAL, COVERUP,
                                f"The agent tried to {r.get('action')} its own audit log "
                                f"({json.dumps(r.get('args'), ensure_ascii=False)}) at {r.get('timestamp')}: "
                                f"a cover-up attempt. It {'SUCCEEDED locally' if succeeded else 'failed'}; "
                                f"the ledger still holds the full history.",
                                seqs=[r["seq"]] + ([res["seq"]] if res else []), session_id=r.get("session_id"),
                                details={"succeeded_locally": succeeded}))
    return findings


# 6. Local log vs ledger ----------------------------------------------------------------

def compare_local_log(local_entries: list[dict[str, Any]], records: list[Record],
                      session_id: Optional[str] = None) -> list[Finding]:
    """Compare the agent-editable local log with the ledger for the same session(s)."""
    findings: list[Finding] = []
    sessions = {session_id} if session_id else {str(e["session_id"]) for e in local_entries if e.get("session_id")}
    if not sessions:
        if local_entries:
            findings.append(Finding("local_log_unattributable", WARNING, COVERUP,
                                    "The local log has entries with no session id, so it can't be matched to the ledger."))
        return findings

    corrupt = [e["_corrupt"] for e in local_entries if "_corrupt" in e]
    if corrupt:
        findings.append(Finding("local_log_corrupt", HIGH, COVERUP,
                                f"{len(corrupt)} line(s) of the local log are unreadable (overwritten or garbled).",
                                details={"lines": corrupt[:5]}))

    local_by_seq = {e["seq"]: e for e in local_entries if isinstance(e.get("seq"), int)}
    for session in sorted(sessions):
        ledger_recs = {r["seq"]: r for r in records
                       if str(r.get("session_id")) == session and r.get("event_type") != "heartbeat"}
        if not ledger_recs:
            continue
        local = {s: e for s, e in local_by_seq.items() if str(e.get("session_id", session)) == session}

        missing = sorted(set(ledger_recs) - set(local))
        if missing:
            lost = [f"{ledger_recs[s]['event_type']} {ledger_recs[s].get('action')}" for s in missing]
            findings.append(Finding("local_log_entries_missing", CRITICAL, COVERUP,
                                    f"{len(missing)} entr{'y' if len(missing) == 1 else 'ies'} ({ranges(missing)}) "
                                    f"were removed from the local log but are preserved in the ledger.",
                                    seqs=missing, session_id=session,
                                    details={"removed": [{"seq": s, "what": w} for s, w in zip(missing, lost)]}))

        altered = []
        for s in sorted(set(ledger_recs) & set(local)):
            diffs = [k for k in _COMPARED if local[s].get(k) != ledger_recs[s].get(k)]
            if diffs:
                altered.append(s)
                findings.append(Finding("local_log_entry_altered", CRITICAL, COVERUP,
                                        f"Local log entry #{s} doesn't match the ledger ({', '.join(diffs)}): the "
                                        f"local copy was altered (or, if the ledger is flagged too, the ledger was). "
                                        f"Ledger: {json.dumps({k: ledger_recs[s].get(k) for k in diffs})}  "
                                        f"Local: {json.dumps({k: local[s].get(k) for k in diffs})}",
                                        seqs=[s], session_id=session, details={"fields": diffs}))

        fabricated = sorted(s for s in local if s not in ledger_recs)
        if fabricated:
            findings.append(Finding("local_log_entry_fabricated", CRITICAL, COVERUP,
                                    f"The local log contains entries {ranges(fabricated)} that the ledger doesn't "
                                    f"have: invented locally, or deleted from the ledger.",
                                    seqs=fabricated, session_id=session))

    refused = [e for e in local_entries if e.get("event_type") == "refused"]
    if refused:
        findings.append(Finding("actions_refused", INFO, LIVENESS,
                                f"{len(refused)} action(s) were refused because the ledger was unreachable "
                                f"(fail closed).", details={"actions": [e.get("action") for e in refused]}))
    return findings


# 7. Witness checkpoints ------------------------------------------------------------------

def check_checkpoints(records: list[Record], checkpoints: list[dict[str, Any]]) -> list[Finding]:
    """Checkpoints are {"seq": n, "hash": h} stored outside the ledger (M4)."""
    findings: list[Finding] = []
    by_seq = {r.get("seq"): r for r in records}
    for cp in checkpoints:
        rec = by_seq.get(cp.get("seq"))
        if rec is None:
            findings.append(Finding("checkpoint_entry_missing", CRITICAL, INTEGRITY,
                                    f"The witness recorded entry #{cp.get('seq')}, but the ledger no longer has it: "
                                    f"the end of the history was cut off.", seqs=[cp.get("seq")]))
        elif rec.get("hash") != cp.get("hash"):
            findings.append(Finding("checkpoint_mismatch", CRITICAL, INTEGRITY,
                                    f"Entry #{cp.get('seq')} differs from the witness checkpoint: the ledger history "
                                    f"was rewritten (even if its signatures look valid).", seqs=[cp.get("seq")]))
    return findings
