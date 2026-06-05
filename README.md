# Lattice Flux 256 (LF-256)

This is a hybrid crypto stack I designed around a time-varying lattice KEM, with AEAD for the actual data and an optional passphrase on top.

MIT license. Author: **nizarski** - see [AUTHORS](AUTHORS).

More detail: [docs/TECH.md](docs/TECH.md)  
Changes: [CHANGELOG.md](CHANGELOG.md)  
Security stuff: [SECURITY.md](SECURITY.md)

## What it is

The lattice part only moves a 32-byte key. Files and chat traffic go through AEAD. I split map, keys, and passphrase into separate pieces so the password never sits on disk.

Ring params: n=256, q=3329, CBD k=2. Same ballpark as Kyber but this is my own construction - not ML-KEM, not audited. Use it to learn or mess around on a LAN. Don't ship it to production.

## Quick start

```powershell
$env:PYTHONPATH = "src"
python -m lf256
pytest
```

## Tiny example

```python
import secrets, time
from lf256 import LatticeFlux256

seed = secrets.token_bytes(32)
eng = LatticeFlux256(seed)
t = int(time.time() * 1000)
pk, sk = eng.generate_keypair(t)
secret, ct, confirm = eng.encapsulate(pk, current_t=t)
assert eng.decapsulate(ct, sk, expected_confirm=confirm) == secret
```

## Files you get when you seal something

- `*.lf256.map.json` - public side (seed, salt, KEM params)
- `*.lf256.keys.enc` - private key, encrypted (default)
- `*.lf256.enc` - the actual payload
- passphrase - you type it, it's not saved

```powershell
python apps/vault.py encrypt --in secret.txt `
  --map-out artifacts/s.lf256.map.json `
  --keys-out artifacts/s.lf256.keys.enc `
  --enc-out artifacts/s.lf256.enc
```

Chat, vault, GUI commands are all in [docs/TECH.md](docs/TECH.md).
