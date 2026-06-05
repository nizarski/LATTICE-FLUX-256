# Changelog

## 2.1.0 (2026-06-05)

What changed:

- kem_confirm is required on decapsulate
- bulk encryption is AEAD now (was XOR in v2.0)
- passphrase bound with PBKDF2 + HKDF
- keys on disk encrypted by default (.lf256.keys.enc)
- chat has sequence numbers to block replays
- clock skew default 5000 ms, configurable
- chat server binds localhost unless --listen-all
- tests, SECURITY.md, MIT license, docs cleanup

API tweaks:

- secure_payload() returns header, ciphertext, and sk together
- vault flag is --plaintext-keys instead of --encrypt-keys

Still experimental. Still my custom KEM, not a standard.

## 2.0.x

Older code lived under Implementations/. XOR symmetric layer, tighter 500 ms skew, no AEAD. Moved into src/lf256/ package layout before 2.1.
