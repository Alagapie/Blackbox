import sqlite3

import pytest
from fastapi.testclient import TestClient

from core.crypto import generate_private_key, load_public_key
from core.events import GENESIS_HASH, EventIn, check_record
from ledger.ledger import Ledger
from ledger.storage import LedgerStorage
from ledger.server import create_app


def _event(n, **kw):
    return EventIn(agent_id="agent-1", session_id="s1", event_type="action_requested", client_seq=n,
                   action="run_shell", args={"cmd": f"echo {n}"}, **kw)


@pytest.fixture
def ledger():
    return Ledger(LedgerStorage(":memory:"), generate_private_key())


def _chain_problems(records, public_key):
    """Minimal chain check for tests. The full version is the verifier (M6)."""
    problems, prev = [], GENESIS_HASH
    for expected_seq, r in enumerate(records, start=1):
        if r["seq"] != expected_seq:
            problems.append(("gap", expected_seq))
        if r["prev_hash"] != prev:
            problems.append(("broken_link", r["seq"]))
        problems += [(p, r["seq"]) for p in check_record(r, public_key)]
        prev = r["hash"]
    return problems


def test_entries_are_numbered_and_chained(ledger):
    r1, r2, r3 = (ledger.append(_event(i)) for i in (1, 2, 3))
    assert [r1["seq"], r2["seq"], r3["seq"]] == [1, 2, 3]
    assert r1["prev_hash"] == GENESIS_HASH
    assert r2["prev_hash"] == r1["hash"] and r3["prev_hash"] == r2["hash"]
    assert _chain_problems(ledger.list(), ledger.public_key) == []
    assert ledger.head() == {"seq": 3, "hash": r3["hash"]}


def test_database_refuses_update_and_delete(tmp_path):
    path = tmp_path / "ledger.db"
    led = Ledger(LedgerStorage(path), generate_private_key())
    led.append(_event(1))
    conn = sqlite3.connect(path)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE events SET record = '{}' WHERE seq = 1")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM events WHERE seq = 1")


def test_chain_survives_restart(tmp_path):
    key = generate_private_key()
    path = tmp_path / "ledger.db"
    first = Ledger(LedgerStorage(path), key)
    first.append(_event(1))
    first._storage.close()
    second = Ledger(LedgerStorage(path), key)
    second.append(_event(2))
    assert _chain_problems(second.list(), key.public_key()) == []


def test_tampered_middle_entry_is_located(ledger):
    for i in range(1, 6):
        ledger.append(_event(i))
    records = ledger.list()
    records[2]["action"] = "read_file"  # attacker edits entry 3
    assert _chain_problems(records, ledger.public_key) == [("hash_mismatch", 3)]


def test_deleted_entry_is_detected(ledger):
    for i in range(1, 6):
        ledger.append(_event(i))
    records = ledger.list()
    del records[2]  # entry 3 removed
    problems = _chain_problems(records, ledger.public_key)
    assert ("broken_link", 4) in problems


# --- HTTP API ---------------------------------------------------------------

@pytest.fixture
def client(ledger):
    return TestClient(create_app(ledger))


def test_api_append_and_read(client):
    body = {"agent_id": "agent-1", "session_id": "s1", "event_type": "action_requested", "client_seq": 1,
            "action": "delete_file", "args": {"path": "customers.db"}}
    created = client.post("/events", json=body)
    assert created.status_code == 201
    rec = created.json()
    assert rec["seq"] == 1 and rec["prev_hash"] == GENESIS_HASH
    assert client.get("/events/1").json() == rec
    assert client.get("/events").json() == [rec]
    assert client.get("/head").json() == {"seq": 1, "hash": rec["hash"]}
    pub = load_public_key(client.get("/public-key").text.encode())
    assert check_record(rec, pub) == []


def test_api_rejects_forged_ledger_fields(client):
    body = {"agent_id": "a", "session_id": "s1", "event_type": "heartbeat", "client_seq": 1, "seq": 42}
    assert client.post("/events", json=body).status_code == 422


def test_api_has_no_way_to_change_history(client):
    client.post("/events", json={"agent_id": "a", "session_id": "s1", "event_type": "heartbeat", "client_seq": 1})
    for method in ("put", "patch", "delete"):
        assert getattr(client, method)("/events/1").status_code == 405
    assert client.get("/events/1").status_code == 200


def test_api_missing_event_is_404(client):
    assert client.get("/events/999").status_code == 404
