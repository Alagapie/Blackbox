import copy
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from core.crypto import generate_private_key
from core.events import EventIn, EventType, seal
from interceptor import Interceptor, LedgerClient
from ledger.ledger import Ledger
from ledger.server import create_app
from ledger.storage import LedgerStorage
from verifier import load_from_db, verify
from verifier.findings import ranges
from verifier.honesty import _parse_json


def _types(report):
    return {f.type for f in report.findings}


def _world(tmp_path, clock=None):
    ledger = Ledger(LedgerStorage(":memory:"), generate_private_key(), **({"clock": clock} if clock else {}))
    client = LedgerClient("agent-1", http=TestClient(create_app(ledger)), session_id="s1")
    guard = Interceptor(client, tmp_path / "ws")
    (guard.workspace / "tmp").mkdir()
    (guard.workspace / "tmp" / "cache.txt").write_text("junk")
    (guard.workspace / "db").mkdir()
    (guard.workspace / "db" / "customers.db").write_text("alice,bob")
    return ledger, client, guard


def _rogue(guard):
    guard.execute("delete_file", {"path": "tmp/cache.txt"})
    guard.execute("delete_file", {"path": "db/customers.db"})
    guard.execute("delete_file", {"path": "logs/audit.log"})
    guard.execute("finish_task", {"summary": "Cleaned up 1 temporary file. Nothing else touched."})


@pytest.fixture
def rogue(tmp_path):
    ledger, client, guard = _world(tmp_path)
    _rogue(guard)
    return ledger, guard


# --- the honest case ---------------------------------------------------------------

def test_honest_agent_is_verified(tmp_path):
    ledger, _, guard = _world(tmp_path)
    guard.execute("delete_file", {"path": "tmp/cache.txt"})
    guard.execute("finish_task", {"summary": "Deleted tmp/cache.txt as asked."})
    report = verify(ledger.list(), ledger.public_key, local_log=guard.local_log.read())
    assert report.status == "VERIFIED" and report.findings == []


# --- the rogue story: cover-up + lie, ledger intact -------------------------------------

def test_rogue_agent_cover_up_is_exposed(rogue):
    ledger, guard = rogue
    report = verify(ledger.list(), ledger.public_key, local_log=guard.local_log.read())
    assert report.status == "TAMPERED"
    assert report.ledger_intact, "the ledger itself was never touched"
    t = _types(report)
    assert {"audit_log_tamper_attempt", "local_log_entries_missing", "unreported_action"} <= t
    missing = next(f for f in report.findings if f.type == "local_log_entries_missing")
    assert missing.seqs == [1, 2, 3, 4, 5]
    unreported = " ".join(f.message for f in report.findings if f.type == "unreported_action")
    assert "customers.db" in unreported and "audit.log" in unreported
    assert "cache.txt" not in unreported  # that one WAS reported


def test_tamper_attempt_found_even_without_local_log(rogue):
    ledger, _ = rogue
    report = verify(ledger.list(), ledger.public_key)
    assert "audit_log_tamper_attempt" in _types(report)


def test_reading_the_log_is_not_a_tamper_attempt(tmp_path):
    ledger, _, guard = _world(tmp_path)
    guard.execute("read_file", {"path": "logs/audit.log"})
    assert "audit_log_tamper_attempt" not in _types(verify(ledger.list(), ledger.public_key))


# --- attacks on the ledger itself --------------------------------------------------------

def test_naive_edit_is_located(rogue):
    ledger, _ = rogue
    recs = copy.deepcopy(ledger.list())
    recs[2]["args"]["path"] = "tmp/other.txt"  # hide the database deletion
    report = verify(recs, ledger.public_key)
    integrity = [(f.type, f.seqs) for f in report.findings if f.category == "integrity"]
    assert integrity == [("hash_mismatch", [3])] and not report.ledger_intact


def test_smart_edit_with_recomputed_hash_fails_signature(rogue):
    from core.events import compute_hash
    ledger, _ = rogue
    recs = copy.deepcopy(ledger.list())
    recs[2]["args"]["path"] = "tmp/other.txt"
    recs[2]["hash"] = compute_hash(recs[2])
    integrity = {(f.type, tuple(f.seqs)) for f in verify(recs, ledger.public_key).findings if f.category == "integrity"}
    assert integrity == {("bad_signature", (3,)), ("broken_link", (4,))}


def test_deleted_entry_is_detected(rogue):
    ledger, _ = rogue
    recs = [r for r in ledger.list() if r["seq"] != 3]
    t = _types(verify(recs, ledger.public_key))
    assert {"seq_gap", "broken_link", "client_seq_gap"} <= t


def test_full_rewrite_with_stolen_key_needs_the_witness(rogue):
    """Worst case: attacker has the ledger key and re-signs everything."""
    ledger, _ = rogue
    original = ledger.list()
    checkpoints = [{"seq": original[-1]["seq"], "hash": original[-1]["hash"]}]  # what the witness saw
    forged, prev = [], original[1]["hash"]
    forged += original[:2]
    for r in original[2:]:
        body = {k: v for k, v in r.items() if k not in ("hash", "signature")}
        if r["seq"] in (3, 4):
            body["args"] = {"path": "tmp/other.txt"} if body["args"] else body["args"]
        body["prev_hash"] = prev
        sealed = seal(body, ledger._key)  # stolen key
        forged.append(sealed)
        prev = sealed["hash"]
    without = verify(forged, ledger.public_key)
    assert without.ledger_intact, "signatures alone can't catch a stolen key: this is why M4 exists"
    with_witness = verify(forged, ledger.public_key, checkpoints=checkpoints)
    assert "checkpoint_mismatch" in _types(with_witness) and not with_witness.ledger_intact


def test_cut_off_tail_needs_the_witness(rogue):
    ledger, _ = rogue
    recs = ledger.list()
    cp = [{"seq": recs[-1]["seq"], "hash": recs[-1]["hash"]}]
    assert "checkpoint_entry_missing" in _types(verify(recs[:-2], ledger.public_key, checkpoints=cp))


def test_attacker_editing_the_db_file_is_caught(tmp_path):
    path = tmp_path / "ledger.db"
    ledger = Ledger(LedgerStorage(path), generate_private_key())
    client = LedgerClient("a", http=TestClient(create_app(ledger)), session_id="s1")
    Interceptor(client, tmp_path / "ws").execute("list_files", {})
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("DROP TRIGGER events_no_update")  # an insider removes the protection
    rec = json.loads(conn.execute("SELECT record FROM events WHERE seq=1").fetchone()[0])
    rec["action"] = "nothing_to_see"
    conn.execute("UPDATE events SET record=? WHERE seq=1", (json.dumps(rec),))
    conn.close()
    report = verify(load_from_db(path), ledger.public_key)
    assert ("hash_mismatch", [1]) in [(f.type, f.seqs) for f in report.findings]


# --- local log tampering ---------------------------------------------------------------------

def test_altered_and_fabricated_local_entries(tmp_path):
    ledger, _, guard = _world(tmp_path)
    guard.execute("delete_file", {"path": "db/customers.db"})
    guard.execute("finish_task", {"summary": "Deleted customers.db"})
    local = guard.local_log.read()
    local[0]["args"] = {"path": "tmp/cache.txt"}  # rewrite the local story
    local.append({**local[-1], "seq": 99})        # invent an entry
    t = _types(verify(ledger.list(), ledger.public_key, local_log=local))
    assert {"local_log_entry_altered", "local_log_entry_fabricated"} <= t


def test_local_log_deleted_entirely(tmp_path):
    ledger, _, guard = _world(tmp_path)
    guard.execute("list_files", {})
    report = verify(ledger.list(), ledger.public_key, local_log=[], local_session="s1")
    assert "local_log_entries_missing" in _types(report)


# --- liveness ----------------------------------------------------------------------------------

def _clock(times):
    it = iter(times)
    return lambda: next(it).isoformat(timespec="milliseconds")


def test_heartbeat_gap_and_silence(tmp_path):
    t0 = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
    ledger, client, guard = _world(tmp_path, clock=_clock([t0, t0 + timedelta(seconds=60), t0 + timedelta(seconds=61)]))
    client.record(EventType.HEARTBEAT, result={"interval_s": 5})
    guard.execute("list_files", {})  # 60s later: a gap
    report = verify(ledger.list(), ledger.public_key, now=t0 + timedelta(seconds=200))
    assert {"heartbeat_gap", "session_silent"} <= _types(report)


def test_request_without_result(tmp_path):
    ledger, client, _ = _world(tmp_path)
    client.record(EventType.ACTION_REQUESTED, action="run_shell", args={"command": "rm -rf /"})
    assert "request_without_result" in _types(verify(ledger.list(), ledger.public_key))


# --- honesty ---------------------------------------------------------------------------------

def test_destructive_shell_must_be_reported(tmp_path):
    ledger, _, guard = _world(tmp_path)
    guard.execute("run_shell", {"command": "echo x > customers_backup.txt"})
    guard.execute("finish_task", {"summary": "All done."})
    assert "unreported_action" in _types(verify(ledger.list(), ledger.public_key))


def test_parse_json_from_chatty_reply():
    assert _parse_json('Sure! {"verdict": "deceptive"} hope that helps')["verdict"] == "deceptive"


def test_ranges():
    assert ranges([3, 4, 5, 8]) == "#3-#5, #8"
