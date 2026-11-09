"""Witness (M4), checkpointer, agent loop (M5) and every attack (M8)."""

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from core.crypto import generate_private_key, load_or_create_keypair
from interceptor import Interceptor, LedgerClient
from ledger.checkpointer import Checkpointer
from ledger.ledger import Ledger
from ledger.server import create_app as ledger_app
from ledger.storage import LedgerStorage
from verifier import load_from_db, verify
from witness.server import CheckpointIn, Witness
from witness.server import create_app as witness_app

H1, H2 = "a" * 64, "b" * 64


# --- M4 witness ---------------------------------------------------------------------

def test_witness_accepts_and_refuses():
    w = Witness(":memory:", generate_private_key())
    assert w.submit(CheckpointIn(seq=5, hash=H1))[0] == 201
    assert w.submit(CheckpointIn(seq=5, hash=H1))[0] == 200            # duplicate is fine
    assert w.submit(CheckpointIn(seq=5, hash=H2))[0] == 409            # rewritten history
    assert w.submit(CheckpointIn(seq=3, hash=H2))[0] == 409            # went backwards
    assert w.submit(CheckpointIn(seq=9, hash=H2))[0] == 201
    assert [c["seq"] for c in w.checkpoints()] == [5, 9]
    assert len(w.conflicts()) == 2 and "rewritten" in w.conflicts()[0]["reason"]


def test_checkpointer_pushes_ledger_head():
    ledger = Ledger(LedgerStorage(":memory:"), generate_private_key())
    w = Witness(":memory:", generate_private_key())
    cp = Checkpointer(ledger, "http://witness", http=TestClient(witness_app(w)))
    assert cp.push_once() is None  # empty ledger: nothing to send
    client = LedgerClient("a", http=TestClient(ledger_app(ledger)), session_id="s1")
    from core.events import EventType
    client.record(EventType.HEARTBEAT)
    assert cp.push_once() == 201
    assert cp.push_once() is None  # unchanged head isn't resent
    assert w.checkpoints()[0]["hash"] == ledger.head()["hash"]


# --- M5 agent loop with a fake model ---------------------------------------------------------

class FakeModel:
    """Plays back scripted tool calls the way the OpenAI client returns them."""

    def __init__(self, turns):
        self.turns, self.seen = list(turns), []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kw):
        self.seen.append(kw)
        calls = [SimpleNamespace(id=f"c{i}", function=SimpleNamespace(name=n, arguments=json.dumps(a)))
                 for i, (n, a) in enumerate(self.turns.pop(0))]
        msg = SimpleNamespace(content="working", tool_calls=calls or None)
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


def test_agent_acts_only_through_interceptor(tmp_path):
    from agent.runner import run_llm_agent
    ledger = Ledger(LedgerStorage(":memory:"), generate_private_key())
    guard = Interceptor(LedgerClient("a", http=TestClient(ledger_app(ledger)), session_id="s1"), tmp_path / "ws")
    model = FakeModel([[("write_file", {"path": "x.txt", "content": "hi"})],
                       [("finish_task", {"summary": "Wrote x.txt"})]])
    out = run_llm_agent("do it", guard, client=model, model="fake", log=lambda s: None)
    assert out == {"finished": True, "steps": 2}
    assert (guard.workspace / "x.txt").read_text() == "hi"
    assert [r["event_type"] for r in ledger.list()] == ["action_requested", "action_completed", "agent_report"]
    tool_msgs = [m for m in model.seen[1]["messages"] if m["role"] == "tool"]
    assert json.loads(tool_msgs[0]["content"])["ok"] is True
    assert verify(ledger.list(), ledger.public_key).status == "VERIFIED"


def test_agent_final_text_becomes_report_if_it_never_calls_finish(tmp_path):
    from agent.runner import run_llm_agent
    ledger = Ledger(LedgerStorage(":memory:"), generate_private_key())
    guard = Interceptor(LedgerClient("a", http=TestClient(ledger_app(ledger)), session_id="s1"), tmp_path / "ws")
    run_llm_agent("hi", guard, client=FakeModel([[]]), model="fake", log=lambda s: None)
    assert ledger.list()[-1]["event_type"] == "agent_report"


# --- M8 every attack is caught -------------------------------------------------------------

@pytest.fixture
def world(tmp_path, monkeypatch):
    import attacks.attacks as A
    data = tmp_path / "data"
    key = load_or_create_keypair(data / "ledger" / "keys", "ledger")
    ledger = Ledger(LedgerStorage(data / "ledger" / "ledger.db"), key)
    witness = Witness(":memory:", generate_private_key())
    client = LedgerClient("rogue", http=TestClient(ledger_app(ledger)), session_id="s1")
    guard = Interceptor(client, data / "ws")
    for p, text in [("tmp/c.tmp", "x"), ("db/customers.db", "alice")]:
        (guard.workspace / p).parent.mkdir(parents=True, exist_ok=True)
        (guard.workspace / p).write_text(text)
    guard.execute("delete_file", {"path": "tmp/c.tmp"})
    guard.execute("delete_file", {"path": "db/customers.db"})
    guard.execute("finish_task", {"summary": "Deleted tmp/c.tmp and customers.db"})  # honest
    witness.submit(CheckpointIn(**ledger.head()))
    registry = data / "sessions.json"
    registry.write_text(json.dumps({"s1": {"local_log": str(guard.local_log.path), "started": "2026"}}))
    monkeypatch.setattr(A, "LEDGER_DB", data / "ledger" / "ledger.db")
    monkeypatch.setattr(A, "LEDGER_KEY", data / "ledger" / "keys" / "ledger_private.pem")
    monkeypatch.setattr(A, "REGISTRY", registry)

    def check(**kw):
        return verify(load_from_db(A.LEDGER_DB), key.public_key(),
                      local_logs={"s1": guard.local_log.read()}, checkpoints=witness.checkpoints(), **kw)
    return A, check


def test_baseline_is_clean(world):
    _, check = world
    assert check().status == "VERIFIED"


@pytest.mark.parametrize("attack, expected", [
    ("delete_local_log", "local_log_entries_missing"),
    ("edit_local_log", "local_log_entry_altered"),
    ("edit_ledger_entry", "hash_mismatch"),
    ("edit_ledger_rehash", "bad_signature"),
    ("delete_ledger_entry", "seq_gap"),
    ("rewrite_stolen_key", "checkpoint_mismatch"),
    ("truncate_ledger_tail", "checkpoint_entry_missing"),
])
def test_every_attack_is_caught(world, attack, expected):
    A, check = world
    A.run_attack(attack)
    report = check()
    assert expected in {f.type for f in report.findings}, report.to_dict()
    assert report.status == "TAMPERED"


def test_stolen_key_rewrite_passes_crypto_checks_alone(world):
    A, check = world
    A.run_attack("rewrite_stolen_key")
    integrity = [f.type for f in check().findings if f.category == "integrity"]
    assert integrity == ["checkpoint_mismatch"], "only the witness catches a stolen-key rewrite"
