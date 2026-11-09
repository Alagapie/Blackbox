"""Cryptographic building blocks shared by every module.

- canonical_json: turns a dict into the exact same bytes every time, so the
  same event always produces the same hash on every machine.
- sha256_hex: the "fingerprint" function.
- Ed25519 sign / verify: the "seal" only the ledger can create but anyone
  can check.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_json(obj: Any) -> bytes:
    """Serialize deterministically: sorted keys, no whitespace, UTF-8.

    Without this, {"a":1,"b":2} and {"b":2,"a":1} would hash differently
    and honest records would look tampered.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- keys -------------------------------------------------------------------

def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_to_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("expected an Ed25519 private key")
    return key


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("expected an Ed25519 public key")
    return key


def load_or_create_keypair(key_dir: Path, name: str) -> Ed25519PrivateKey:
    """Load `<name>_private.pem` from key_dir, creating a new pair if absent."""
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_path = key_dir / f"{name}_private.pem"
    pub_path = key_dir / f"{name}_public.pem"
    if priv_path.exists():
        return load_private_key(priv_path.read_bytes())
    key = generate_private_key()
    priv_path.write_bytes(private_key_to_pem(key))
    pub_path.write_bytes(public_key_to_pem(key.public_key()))
    return key


# --- sign / verify ----------------------------------------------------------

def sign(key: Ed25519PrivateKey, message: bytes) -> str:
    return key.sign(message).hex()


def verify(key: Ed25519PublicKey, message: bytes, signature_hex: str) -> bool:
    try:
        key.verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False
