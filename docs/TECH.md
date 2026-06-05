# LF-256 technical notes

Written by **nizarski**. This is how the code actually works.

## The three layers

1. **Lattice KEM** — agrees a 32-byte key. Custom R-LWE over Z_3329[X]/(X^256+1). I rotate the public matrix A_t per timestamp using SHAKE-256(seed || t).

2. **AEAD** — encrypts the real data. SHA-256 counter mode + HMAC-SHA256 tag. Wire format: magic bytes, 12-byte nonce, ciphertext, 32-byte tag.

3. **Passphrase** (chat + vault) — PBKDF2-SHA256 at 200k rounds, then HKDF to mix it with the session key. Passphrase stays in memory only.

If one layer breaks, the rest doesn't save you.

## KEM math (short version)

Keygen: `b = A_t * s + e`, publish (b, t), keep s.

Encaps: pick random 32 bytes, encode into the ring, send `(u, v) = (A_t*r + e1, b*r + e2 + m_bar)`.

Decaps: `w = v - u*s`, decode bits back to 32 bytes.

You must pass `kem_confirm` on decapsulate — it's an HMAC of the derived key. Wrong key or bad ciphertext throws instead of giving you garbage.

Clock skew: default window is 5000 ms. Outside that, encapsulate fails.

Noise is CBD with k=2. Decode works when error stays under q/4 (q=3329).

## Things to know about the KEM

- seed and timestamp t are public. Someone who saved your handshake can rebuild A_t offline.
- No NTT in this Python code — naive poly multiply. Slow but fine for demos.
- I didn't prove this scheme. Params look like Kyber-512 class stuff. That doesn't make it ML-KEM.

## Artifacts

| file | what's in it |
|------|----------------|
| `.lf256.map.json` | public_seed, salt, skew, kem fields, kem_confirm |
| `.lf256.keys.enc` | salt + encrypted JSON with private key (use this) |
| `.lf256.keys.json` | private key in plain JSON (debug only) |
| `.lf256.enc` | AEAD blob |

Version string in JSON: `"lf256_version": "2.1"`.

## Repo layout

```
src/lf256/     core library
apps/          chat, vault CLI, tk GUI
tests/
examples/
```

## Commands

Set `PYTHONPATH=src` from the repo root.

```
python -m lf256          # smoke test
pytest

python apps/network_chat.py init-map --out artifacts/team.lf256.map.json
python apps/network_chat.py server --keymap artifacts/team.lf256.map.json
python apps/network_chat.py client --keymap artifacts/team.lf256.map.json

python apps/vault.py encrypt --in file.txt --map-out ... --keys-out ... --enc-out ...
python apps/vault.py decrypt --map ... --keys ... --enc ... --out restored.txt

python apps/storage_gui.py
python examples/string_envelope_demo.py
```

Vault writes encrypted keys by default. Pass `--plaintext-keys` only if you're debugging.

Chat server listens on 127.0.0.1 unless you pass `--listen-all`.

## What can go wrong

**Timestamp expired** — machines out of sync. Fix NTP or bump `allowed_skew_ms`.

**Decaps fails / garbage** — usually wrong public_seed between two sides, or mismatched map/keys/enc files.

**Wrong passphrase** — decrypt fails on purpose. Check you're using the same files from encrypt.

**Weak password** — someone can grind PBKDF2 offline. Use a long random passphrase.

**Network** — there's no server identity here. If you're not on a network you trust, put TLS in front.

**Python** — not constant-time, secrets aren't wiped from memory. Fine for a lab, not for a hardened target.

For real deployments use normal tools: TLS, ML-KEM, ChaCha20-Poly1305 or AES-GCM.
