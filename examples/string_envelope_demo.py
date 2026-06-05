#!/usr/bin/env python3
"""Example: seal and unseal a string in memory."""

from __future__ import annotations

import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from lf256 import HybridSymmetricEngine, LatticeFlux256

# Demo-only seed - generate with secrets.token_bytes(32) in real use.
CONTEXT_SEED = b"ENV_VARIABLE_STRING_SEED_SELECTOR"
lf_engine = LatticeFlux256(public_seed=CONTEXT_SEED)

secret_configuration_str = (
    "DATABASE_URL=postgresql://admin:EXAMPLE_ONLY@10.0.4.12:5432/production"
)
raw_payload_bytes = secret_configuration_str.encode("utf-8")

fixed_timestamp_ms = int(time.time() * 1000)
pk, sk = lf_engine.generate_keypair(t=fixed_timestamp_ms)
shared_dek_sender, ciphertext, confirm = lf_engine.encapsulate(
    pk, current_t=fixed_timestamp_ms
)
encrypted_string_blob = HybridSymmetricEngine.encrypt(raw_payload_bytes, shared_dek_sender)

print("[-] Envelope sealed.")
print(f"    Timestamp anchor: {fixed_timestamp_ms} ms")

shared_dek_receiver = lf_engine.decapsulate(ciphertext, sk, expected_confirm=confirm)
decrypted_bytes = HybridSymmetricEngine.decrypt(encrypted_string_blob, shared_dek_receiver)
print(f"\n[-] Restored:\n{decrypted_bytes.decode('utf-8')}")
