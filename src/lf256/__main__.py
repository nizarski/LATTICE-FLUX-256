"""Run LF-256 checks: python -m lf256"""

from __future__ import annotations

import secrets
import tempfile
from pathlib import Path

from lf256.crypto_utils import AeadDecryptError
from lf256.engine import HybridSymmetricEngine, LF256KeyMap, StorageAndNetworkEnvelope


def main() -> int:
    seed = secrets.token_bytes(32)
    envelope = StorageAndNetworkEnvelope(seed)

    raw = b"GET /secure-dashboard HTTP/1.1"
    header, enc, sk = envelope.secure_payload(raw)
    assert envelope.restore_payload(header, enc, sk=sk) == raw

    key = secrets.token_bytes(32)
    blob = HybridSymmetricEngine.encrypt(raw, key)
    bad = bytearray(blob)
    bad[20] ^= 1
    try:
        HybridSymmetricEngine.decrypt(bytes(bad), key)
        raise AssertionError("tamper should fail")
    except AeadDecryptError:
        pass

    map_doc, keys_doc, sealed = LF256KeyMap.seal_payload(raw, "vault-passphrase", public_seed=seed)
    assert LF256KeyMap.unseal_payload(map_doc, keys_doc, sealed, "vault-passphrase") == raw
    try:
        LF256KeyMap.unseal_payload(map_doc, keys_doc, sealed, "wrong-passphrase")
        raise AssertionError("wrong passphrase should fail")
    except ValueError:
        pass

    sk_list = keys_doc["keys"]["private_key_s"]
    with tempfile.TemporaryDirectory() as td:
        enc_path = Path(td) / "k.lf256.keys.enc"
        LF256KeyMap.save_keys_encrypted(enc_path, sk_list, "vault-passphrase")
        assert LF256KeyMap.load_keys_encrypted(enc_path, "vault-passphrase") == sk_list

    print("lf256 checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
