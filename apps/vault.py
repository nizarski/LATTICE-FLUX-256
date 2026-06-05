#!/usr/bin/env python3
"""LF-256 file vault - seal and unseal with map, keys, and passphrase."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from bootstrap import ensure_src

ensure_src()

from lf256 import AeadDecryptError, KEMDecapsulationError, LF256KeyMap


def prompt_passphrase(*, confirm: bool) -> str:
    first = getpass.getpass("Enter passphrase (not saved to map/keys files): ")
    if confirm:
        second = getpass.getpass("Confirm passphrase: ")
        if first != second:
            raise ValueError("Passphrases do not match.")
    if not first:
        raise ValueError("Passphrase cannot be empty.")
    return first


def cmd_encrypt(
    inp: Path,
    map_out: Path,
    keys_out: Path,
    enc_out: Path,
    seed_hex: str | None,
    plaintext_keys: bool,
) -> None:
    passphrase = prompt_passphrase(confirm=True)
    public_seed = bytes.fromhex(seed_hex) if seed_hex else None
    if seed_hex and len(public_seed) != 32:
        raise ValueError("--seed-hex must be 64 hex characters (32 bytes).")

    plaintext = inp.read_bytes()
    map_doc, keys_doc, ciphertext = LF256KeyMap.seal_payload(
        plaintext, passphrase, public_seed=public_seed
    )

    LF256KeyMap.save_map(map_out, map_doc)
    sk = keys_doc["keys"]["private_key_s"]
    keys_path = str(keys_out)
    if keys_path.endswith(LF256KeyMap.KEYS_ENC_SUFFIX):
        encrypt_at_rest = True
    elif keys_path.endswith(LF256KeyMap.KEYS_SUFFIX):
        encrypt_at_rest = False
    else:
        encrypt_at_rest = not plaintext_keys
    if encrypt_at_rest:
        LF256KeyMap.save_keys_encrypted(keys_out, sk, passphrase)
    else:
        LF256KeyMap.save_keys(keys_out, sk)
    enc_out.write_bytes(ciphertext)

    print(f"[vault] Map:  {map_out}")
    print(
        f"[vault] Keys: {keys_out} ({'encrypted' if encrypt_at_rest else 'plaintext JSON - not recommended'})"
    )
    print(f"[vault] Enc:  {enc_out} (AEAD)")


def _load_keys_auto(keys_path: Path, passphrase: str) -> dict:
    sk = LF256KeyMap.load_keys_auto(keys_path, passphrase)
    return {
        "lf256_version": LF256KeyMap.VERSION,
        "keys": {"private_key_s": sk},
    }


def cmd_decrypt(map_path: Path, keys_path: Path, enc_path: Path, out: Path | None) -> None:
    passphrase = prompt_passphrase(confirm=False)
    map_doc = LF256KeyMap.load_map(map_path)
    keys_doc = _load_keys_auto(keys_path, passphrase)
    ciphertext = enc_path.read_bytes()
    plaintext = LF256KeyMap.unseal_payload(map_doc, keys_doc, ciphertext, passphrase)

    if out is None:
        try:
            print(plaintext.decode("utf-8"))
        except UnicodeDecodeError:
            print(f"[vault] Binary payload ({len(plaintext)} bytes). Use --out to save.")
    else:
        out.write_bytes(plaintext)
        print(f"[vault] Restored plaintext: {out}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LF-256 v2.1 vault CLI.")
    sub = parser.add_subparsers(dest="command", required=True)

    enc_p = sub.add_parser("encrypt", help="Seal file (AEAD + KEM confirm).")
    enc_p.add_argument("--in", dest="inp", required=True, type=Path)
    enc_p.add_argument("--map-out", required=True, type=Path)
    enc_p.add_argument("--keys-out", required=True, type=Path)
    enc_p.add_argument("--enc-out", required=True, type=Path)
    enc_p.add_argument("--seed-hex", default=None)
    enc_p.add_argument(
        "--plaintext-keys",
        action="store_true",
        help="Write plaintext .lf256.keys.json (default is encrypted .lf256.keys.enc).",
    )

    dec_p = sub.add_parser("decrypt", help="Unseal artifacts.")
    dec_p.add_argument("--map", required=True, type=Path)
    dec_p.add_argument("--keys", required=True, type=Path)
    dec_p.add_argument("--enc", required=True, type=Path)
    dec_p.add_argument("--out", type=Path, default=None)

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "encrypt":
        cmd_encrypt(
            args.inp,
            args.map_out,
            args.keys_out,
            args.enc_out,
            args.seed_hex,
            args.plaintext_keys,
        )
    elif args.command == "decrypt":
        cmd_decrypt(args.map, args.keys, args.enc, args.out)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyboardInterrupt, AeadDecryptError, KEMDecapsulationError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
