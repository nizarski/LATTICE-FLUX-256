"""Shared cryptographic utilities (stdlib-only)."""

from __future__ import annotations

import hashlib
import hmac
import secrets

KEM_CONFIRM_LABEL = b"LF256-KEM-CONFIRM-v2.1"
AEAD_MAGIC = b"LF256AEAD\x01"
NONCE_BYTES = 12
TAG_BYTES = 32


class KEMDecapsulationError(ValueError):
    """Raised when lattice decapsulation or confirmation fails."""


class AeadDecryptError(ValueError):
    """Raised when AEAD verification fails (integrity)."""


def hkdf_sha256(
    ikm: bytes,
    *,
    salt: bytes | None = None,
    info: bytes,
    length: int = 32,
) -> bytes:
    """RFC 5869 HKDF-Expand with SHA-256 (extract + expand)."""
    salt = salt if salt is not None else b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(
            prk, block + info + bytes([counter]), hashlib.sha256
        ).digest()
        okm.extend(block)
        counter += 1
    return bytes(okm[:length])


def kem_confirm_digest(session_key: bytes) -> bytes:
    return hmac.new(session_key, KEM_CONFIRM_LABEL, hashlib.sha256).digest()


def secure_compare(a: bytes | str, b: bytes | str) -> bool:
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)


def aead_encrypt(plaintext: bytes, master_key: bytes) -> bytes:
    """Encrypt-then-MAC: MAGIC || nonce || ciphertext || HMAC-SHA256 tag."""
    nonce = secrets.token_bytes(NONCE_BYTES)
    enc_key = hkdf_sha256(master_key, info=b"LF256-AEAD-ENC-v2.1", length=32)
    mac_key = hkdf_sha256(master_key, info=b"LF256-AEAD-MAC-v2.1", length=32)

    keystream = _ctr_keystream(enc_key, nonce, len(plaintext))
    body = bytes(p ^ k for p, k in zip(plaintext, keystream))
    tag = hmac.new(mac_key, nonce + body, hashlib.sha256).digest()
    return AEAD_MAGIC + nonce + body + tag


def aead_decrypt(blob: bytes, master_key: bytes) -> bytes:
    min_len = len(AEAD_MAGIC) + NONCE_BYTES + TAG_BYTES
    if len(blob) < min_len or not blob.startswith(AEAD_MAGIC):
        raise AeadDecryptError("Invalid AEAD blob (bad magic or length).")

    nonce = blob[len(AEAD_MAGIC) : len(AEAD_MAGIC) + NONCE_BYTES]
    body = blob[len(AEAD_MAGIC) + NONCE_BYTES : -TAG_BYTES]
    tag = blob[-TAG_BYTES:]

    enc_key = hkdf_sha256(master_key, info=b"LF256-AEAD-ENC-v2.1", length=32)
    mac_key = hkdf_sha256(master_key, info=b"LF256-AEAD-MAC-v2.1", length=32)
    expected = hmac.new(mac_key, nonce + body, hashlib.sha256).digest()
    if not secure_compare(tag, expected):
        raise AeadDecryptError("AEAD authentication tag mismatch (tampered ciphertext).")

    keystream = _ctr_keystream(enc_key, nonce, len(body))
    return bytes(c ^ k for c, k in zip(body, keystream))


def _ctr_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(
            key + nonce + counter.to_bytes(8, "big")
        ).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])
