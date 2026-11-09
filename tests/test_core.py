import pytest
from pydantic import ValidationError

from core.crypto import canonical_json, generate_private_key, load_or_create_keypair
from core.events import GENESIS_HASH, EventIn, check_record, compute_hash, seal


def _body(**overrides):
    body = {
        "seq": 1,
        "timestamp": "2026-11-08T12:00:00.000+00:00",
        "agent_id": "agent-1",
        "session_id": "s1",
        "event_type": "action_requested",
        "client_seq": 1,
        "action": "delete_file",
        "args": {"path": "customers.db"},
        "result": None,
        "ref_seq": None,
        "prev_hash": GENESIS_HASH,
    }
    body.update(overrides)
    return body


def test_canonical_json_ignores_key_order():
    assert canonical_json({"a": 1, "b": {"x": 1, "y": 2}}) == canonical_json({"b": {"y": 2, "x": 1}, "a": 1})


def test_any_field_change_changes_hash():
    base = compute_hash(_body())
    assert compute_hash(_body(action="read_file")) != base
    assert compute_hash(_body(args={"path": "Customers.db"})) != base  # one letter
    assert compute_hash(_body(prev_hash="1" * 64)) != base


def test_sealed_record_verifies():
    key = generate_private_key()
    record = seal(_body(), key)
    assert check_record(record, key.public_key()) == []


def test_edited_record_is_caught():
    key = generate_private_key()
    record = seal(_body(), key)
    record["action"] = "read_file"  # attacker rewrites history
    assert "hash_mismatch" in check_record(record, key.public_key())


def test_edit_with_recomputed_hash_fails_signature():
    """The 'smart attacker': edits and fixes the hash, but has no key."""
    key = generate_private_key()
    record = seal(_body(), key)
    record["action"] = "read_file"
    record["hash"] = compute_hash(record)
    assert check_record(record, key.public_key()) == ["bad_signature"]


def test_resealed_with_other_key_fails():
    real, attacker = generate_private_key(), generate_private_key()
    forged = seal(_body(action="read_file"), attacker)
    assert check_record(forged, real.public_key()) == ["bad_signature"]


def test_garbage_signature_does_not_crash():
    key = generate_private_key()
    record = seal(_body(), key)
    record["signature"] = "not-hex"
    assert check_record(record, key.public_key()) == ["bad_signature"]


def test_client_cannot_set_ledger_fields():
    with pytest.raises(ValidationError):
        EventIn(agent_id="a", session_id="s1", event_type="heartbeat", client_seq=1, seq=99)
    with pytest.raises(ValidationError):
        EventIn(agent_id="a", session_id="s1", event_type="heartbeat", client_seq=1, hash="ff")


def test_keypair_persists(tmp_path):
    k1 = load_or_create_keypair(tmp_path, "ledger")
    k2 = load_or_create_keypair(tmp_path, "ledger")
    assert k1.private_bytes_raw() == k2.private_bytes_raw()
