from __future__ import annotations

import secrets
import time
from pathlib import Path

import pytest

from lf256 import (
    AeadDecryptError,
    HybridSymmetricEngine,
    KEMDecapsulationError,
    LF256KeyMap,
    LatticeFlux256,
    StorageAndNetworkEnvelope,
)


@pytest.fixture
def public_seed() -> bytes:
    return secrets.token_bytes(32)


def test_kem_round_trip(public_seed: bytes) -> None:
    engine = LatticeFlux256(public_seed=public_seed)
    t = int(time.time() * 1000)
    pk, sk = engine.generate_keypair(t)
    secret, ct, confirm = engine.encapsulate(pk, current_t=t)
    recovered = engine.decapsulate(ct, sk, expected_confirm=confirm)
    assert recovered == secret


def test_kem_wrong_confirm_rejected(public_seed: bytes) -> None:
    engine = LatticeFlux256(public_seed=public_seed)
    t = int(time.time() * 1000)
    pk, sk = engine.generate_keypair(t)
    _, ct, confirm = engine.encapsulate(pk, current_t=t)
    bad = bytes(b ^ 1 for b in confirm)
    with pytest.raises(KEMDecapsulationError):
        engine.decapsulate(ct, sk, expected_confirm=bad)


def test_aead_tamper_rejected() -> None:
    key = secrets.token_bytes(32)
    blob = HybridSymmetricEngine.encrypt(b"payload", key)
    tampered = bytearray(blob)
    tampered[20] ^= 1
    with pytest.raises(AeadDecryptError):
        HybridSymmetricEngine.decrypt(bytes(tampered), key)


def test_envelope_round_trip(public_seed: bytes) -> None:
    envelope = StorageAndNetworkEnvelope(public_seed)
    raw = b"envelope test payload"
    header, enc, sk = envelope.secure_payload(raw)
    assert envelope.restore_payload(header, enc, sk=sk) == raw


def test_seal_unseal_passphrase(public_seed: bytes) -> None:
    map_doc, keys_doc, sealed = LF256KeyMap.seal_payload(
        b"secret blob", "test-passphrase-12345", public_seed=public_seed
    )
    opened = LF256KeyMap.unseal_payload(map_doc, keys_doc, sealed, "test-passphrase-12345")
    assert opened == b"secret blob"


def test_wrong_passphrase_fails(public_seed: bytes) -> None:
    map_doc, keys_doc, sealed = LF256KeyMap.seal_payload(
        b"secret blob", "right-passphrase", public_seed=public_seed
    )
    with pytest.raises(ValueError, match="Could not decrypt payload"):
        LF256KeyMap.unseal_payload(map_doc, keys_doc, sealed, "wrong-passphrase")


def test_encrypted_keys_round_trip(tmp_path: Path, public_seed: bytes) -> None:
    _, keys_doc, _ = LF256KeyMap.seal_payload(b"x", "vault-pass", public_seed=public_seed)
    sk = keys_doc["keys"]["private_key_s"]
    enc_path = tmp_path / "k.lf256.keys.enc"
    LF256KeyMap.save_keys_encrypted(enc_path, sk, "vault-pass")
    loaded = LF256KeyMap.load_keys_encrypted(enc_path, "vault-pass")
    assert loaded == sk


def test_clock_skew_rejected(public_seed: bytes) -> None:
    engine = LatticeFlux256(public_seed=public_seed, allowed_skew_ms=100)
    t = int(time.time() * 1000)
    pk, _ = engine.generate_keypair(t)
    with pytest.raises(ValueError, match="Timestamp expired"):
        engine.encapsulate(pk, current_t=t + 5000)
