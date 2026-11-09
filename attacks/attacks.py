"""M8: attacks against our own system. Each one must be caught by the verifier.

Local-log attacks are what a misbehaving agent can do itself.
Ledger attacks simulate a much stronger attacker (an insider, or an agent that
escaped its sandbox) who can edit the ledger's database file directly, and in
the worst case has stolen the ledger's private key.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Callable, Optional

from core.crypto import load_private_key
from core.events import seal

DATA = Path(os.environ.get("BLACKBOX_DATA", "data"))
LEDGER_DB = DATA / "ledger" / "ledger.db"
LEDGER_KEY = DATA / "ledger" / "keys" / "ledger_private.pem"
REGISTRY = DATA / "sessions.json"


class AttackError(Exception):
    pass


# --- helpers -------------------------------------------------------------------------

def _db() -> sqlite3.Connection:
    if not LEDGER_DB.exists():
        raise AttackError("no ledger database yet: run a scenario first")
    conn = sqlite3.connect(LEDGER_DB, isolation_level=None, timeout=10)
    # The attacker first removes the database's append-only protection.
    conn.execute("DROP TRIGGER IF EXISTS events_no_update")
    conn.execute("DROP TRIGGER IF EXISTS events_no_delete")
    return conn


def _records(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [json.loads(r[0]) for r in conn.execute("SELECT record FROM events ORDER BY seq")]


def _write(conn: sqlite3.Connection, rec: dict[str, Any]) -> None:
    conn.execute("UPDATE events SET record = ?, hash = ? WHERE seq = ?", (json.dumps(rec), rec["hash"], rec["seq"]))


def _target(records: list[dict[str, Any]]) -> dict[str, Any]:
    """The most incriminating entry: a request to delete the customer database, else any action."""
    requests = [r for r in records if r.get("event_type") == "action_requested"]
    for r in reversed(requests):
        if "customers" in json.dumps(r.get("args")):
            return r
    destructive = [r for r in requests if r.get("action") in ("delete_file", "run_shell")]
    if destructive:
        return destructive[-1]
    if requests:
        return requests[-1]
    raise AttackError("no agent actions in the ledger yet: run a scenario first")


def _innocent_args(rec: dict[str, Any]) -> dict[str, Any]:
    return {"path": "tmp/cache_2.tmp"} if rec.get("action") == "delete_file" else {"command": "echo cleanup"}


def _latest_local_log() -> Path:
    reg = json.loads(REGISTRY.read_text()) if REGISTRY.exists() else {}
    for info in sorted(reg.values(), key=lambda i: i["started"], reverse=True):
        p = Path(info["local_log"])
        if p.exists() and p.stat().st_size > 0:
            return p
    raise AttackError("no agent local log found: run a scenario first")


# --- local-log attacks (the agent itself can do these) ---------------------------------

def delete_local_log() -> str:
    p = _latest_local_log()
    p.unlink()
    return f"Deleted the agent's local audit log {p}."


def _local_logs_newest_first() -> list[Path]:
    reg = json.loads(REGISTRY.read_text()) if REGISTRY.exists() else {}
    paths = [Path(i["local_log"]) for i in sorted(reg.values(), key=lambda i: i["started"], reverse=True)]
    return [p for p in paths if p.exists()]


def edit_local_log() -> str:
    for p in _local_logs_newest_first():
        lines = p.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("action") in ("delete_file", "run_shell") and e.get("event_type") == "action_requested" \
                    and e.get("args") != _innocent_args(e):
                old = e["args"]
                e["args"] = _innocent_args(e)
                lines[i] = json.dumps(e, sort_keys=True)
                p.write_text("\n".join(lines) + "\n", encoding="utf-8")
                return f"Rewrote local log entry #{e['seq']} to look harmless: {old} -> {e['args']}."
    raise AttackError("no destructive action left in any local log to rewrite")


# --- ledger attacks (insider / escaped agent) ----------------------------------------------

def edit_ledger_entry() -> str:
    with _db() as conn:
        rec = _target(_records(conn))
        old = rec["args"]
        rec["args"] = _innocent_args(rec)
        _write(conn, rec)
    return f"Edited ledger entry #{rec['seq']} in the database file: {old} -> {rec['args']}."


def edit_ledger_rehash() -> str:
    from core.events import compute_hash
    with _db() as conn:
        rec = _target(_records(conn))
        old = rec["args"]
        rec["args"] = _innocent_args(rec)
        rec["hash"] = compute_hash(rec)
        _write(conn, rec)
    return f"Edited ledger entry #{rec['seq']} ({old} -> {rec['args']}) and recomputed its hash."


def delete_ledger_entry() -> str:
    with _db() as conn:
        rec = _target(_records(conn))
        conn.execute("DELETE FROM events WHERE seq = ?", (rec["seq"],))
    return f"Deleted ledger entry #{rec['seq']} ({rec['action']} {json.dumps(rec['args'])}) from the database file."


def rewrite_stolen_key() -> str:
    if not LEDGER_KEY.exists():
        raise AttackError("ledger key not found")
    key = load_private_key(LEDGER_KEY.read_bytes())
    with _db() as conn:
        records = _records(conn)
        target = _target(records)
        prev = None
        changed = 0
        for rec in records:
            if rec["seq"] < target["seq"]:
                prev = rec["hash"]
                continue
            body = {k: v for k, v in rec.items() if k not in ("hash", "signature")}
            if rec["seq"] == target["seq"]:
                body["args"] = _innocent_args(rec)
            body["prev_hash"] = prev or body["prev_hash"]
            new = seal(body, key)
            _write(conn, new)
            prev = new["hash"]
            changed += 1
    return (f"Used the STOLEN ledger key to rewrite entry #{target['seq']} and re-sign {changed} entries. "
            f"Every hash and signature is valid again; only the witness can catch this.")


def truncate_ledger_tail(n: int = 3) -> str:
    with _db() as conn:
        records = _records(conn)
        if len(records) < n + 1:
            raise AttackError("not enough entries to cut")
        cut = [r["seq"] for r in records[-n:]]
        conn.execute("DELETE FROM events WHERE seq >= ?", (cut[0],))
    return f"Cut the last {n} entries (#{cut[0]}-#{cut[-1]}) off the end of the ledger."


ATTACKS: dict[str, dict[str, Any]] = {
    "delete_local_log": {"label": "Delete local log", "who": "agent", "fn": delete_local_log,
                         "description": "What a rogue agent does: erase its own audit log."},
    "edit_local_log": {"label": "Rewrite local log", "who": "agent", "fn": edit_local_log,
                       "description": "Change a destructive action in the local log to look harmless."},
    "edit_ledger_entry": {"label": "Edit ledger entry", "who": "insider", "fn": edit_ledger_entry,
                          "description": "Edit the ledger database file directly."},
    "edit_ledger_rehash": {"label": "Edit + recompute hash", "who": "insider", "fn": edit_ledger_rehash,
                           "description": "Edit an entry and fix its fingerprint (no key)."},
    "delete_ledger_entry": {"label": "Delete ledger entry", "who": "insider", "fn": delete_ledger_entry,
                            "description": "Remove the incriminating entry from the ledger."},
    "rewrite_stolen_key": {"label": "Rewrite with stolen key", "who": "insider", "fn": rewrite_stolen_key,
                           "description": "Worst case: rewrite history and re-sign it with the ledger's own key."},
    "truncate_ledger_tail": {"label": "Cut off the end", "who": "insider", "fn": truncate_ledger_tail,
                             "description": "Delete the most recent entries."},
}


def run_attack(name: str) -> str:
    fn: Optional[Callable[[], str]] = ATTACKS[name]["fn"]
    return fn()
