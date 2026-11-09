"""The event format: what one record in the ledger looks like.

Two shapes:
- EventIn: what the interceptor (M3) is allowed to SEND. It cannot choose
  seq, timestamp, prev_hash, hash or signature; the ledger assigns those.
- A sealed record (dict): EventIn + ledger-assigned fields + hash + signature.

    hash      = sha256(canonical_json(all fields except hash and signature))
    signature = Ed25519(ledger private key, bytes of hash)
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field

from core.crypto import canonical_json, sha256_hex, sign, verify

# The "previous hash" of the very first entry.
GENESIS_HASH = "0" * 64

# Every field covered by the hash. Changing any of them breaks the record.
HASHED_FIELDS = (
    "seq",
    "timestamp",
    "agent_id",
    "session_id",
    "event_type",
    "client_seq",
    "action",
    "args",
    "result",
    "ref_seq",
    "prev_hash",
)


class EventType(str, Enum):
    ACTION_REQUESTED = "action_requested"  # written BEFORE the action runs
    ACTION_COMPLETED = "action_completed"  # result of a request (ref_seq points to it)
    ACTION_FAILED = "action_failed"        # action errored or was refused
    HEARTBEAT = "heartbeat"                # "agent side still alive"
    AGENT_REPORT = "agent_report"          # what the agent CLAIMS it did (honesty check)


class EventIn(BaseModel):
    """What a client may submit. Extra fields (e.g. a forged 'seq' or 'hash') are rejected."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=128)
    # One interceptor run. client_seq restarts at 1 for each new session,
    # so (session_id, client_seq) is unique and gaps are checked per session.
    session_id: str = Field(min_length=1, max_length=64)
    event_type: EventType
    # Numbered by the interceptor itself, so we can detect events that were
    # sent but never arrived (or were suppressed) on the way to the ledger.
    client_seq: int = Field(ge=1)
    action: Optional[str] = Field(default=None, max_length=128)
    args: dict[str, Any] = Field(default_factory=dict)
    result: Optional[dict[str, Any]] = None
    # For completed/failed events: the ledger seq of the matching request.
    ref_seq: Optional[int] = Field(default=None, ge=1)


def hashed_body(record: dict[str, Any]) -> dict[str, Any]:
    return {k: record.get(k) for k in HASHED_FIELDS}


def compute_hash(record: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(hashed_body(record)))


def seal(body: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    """Add hash + signature to an unsealed record body."""
    missing = [k for k in HASHED_FIELDS if k not in body]
    if missing:
        raise ValueError(f"record body missing fields: {missing}")
    digest = compute_hash(body)
    return {**hashed_body(body), "hash": digest, "signature": sign(key, bytes.fromhex(digest))}


def check_record(record: dict[str, Any], public_key: Ed25519PublicKey) -> list[str]:
    """Check ONE record on its own. Returns a list of problems (empty = OK).

    Chain-level checks (prev_hash links, sequence gaps) need neighbouring
    records and belong to the verifier (M6).
    """
    problems: list[str] = []
    recomputed = compute_hash(record)
    if recomputed != record.get("hash"):
        problems.append("hash_mismatch")
    stored_hash = record.get("hash") or ""
    try:
        hash_bytes = bytes.fromhex(stored_hash)
    except ValueError:
        hash_bytes = b""
    if not hash_bytes or not verify(public_key, hash_bytes, record.get("signature") or ""):
        problems.append("bad_signature")
    return problems
