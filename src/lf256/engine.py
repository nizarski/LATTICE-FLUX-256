import json
import time
import secrets
import hashlib
from pathlib import Path

from .crypto_utils import (
    AeadDecryptError,
    KEMDecapsulationError,
    aead_decrypt,
    aead_encrypt,
    hkdf_sha256,
    kem_confirm_digest,
    secure_compare,
)


class LatticeFlux256:
    """
    Lattice Flux 256 (LF-256) v2.1 Core Mathematical Engine.
    Implements a post-quantum Time-Varying Ring Learning With Errors (R-LWE) KEM.
    Ring: Z_3329[X] / (X^256 + 1)
    """
    DEFAULT_SKEW_MS = 5_000

    def __init__(self, public_seed: bytes, allowed_skew_ms: int | None = None):
        self.n = 256
        self.q = 3329
        self.seed = public_seed
        self.allowed_skew_ms = (
            allowed_skew_ms if allowed_skew_ms is not None else self.DEFAULT_SKEW_MS
        )

    def _phi(self, t: int) -> list:
        data = self.seed + t.to_bytes(8, byteorder="big")
        hasher = hashlib.shake_256(data)
        poly = []
        while len(poly) < self.n:
            chunk = hasher.digest(2)
            val = int.from_bytes(chunk, byteorder="big")
            if val < 63251:
                poly.append(val % self.q)
        return poly

    def _sample_cbd(self) -> list:
        poly = []
        for _ in range(self.n):
            b = secrets.randbits(4)
            b1 = (b & 1) + ((b >> 1) & 1)
            b2 = ((b >> 2) & 1) + ((b >> 3) & 1)
            poly.append((b1 - b2) % self.q)
        return poly

    def _poly_add(self, a: list, b: list) -> list:
        return [(x + y) % self.q for x, y in zip(a, b)]

    def _poly_sub(self, a: list, b: list) -> list:
        return [(x - y) % self.q for x, y in zip(a, b)]

    def _poly_mul(self, a: list, b: list) -> list:
        c = [0] * self.n
        for i in range(self.n):
            for j in range(self.n):
                idx = i + j
                if idx < self.n:
                    c[idx] = (c[idx] + a[i] * b[j]) % self.q
                else:
                    c[idx - self.n] = (c[idx - self.n] - a[i] * b[j]) % self.q
        return c

    def _encode(self, msg_bytes: bytes) -> list:
        poly = [0] * self.n
        for byte_idx, byte in enumerate(msg_bytes):
            for bit_idx in range(8):
                bit = (byte >> bit_idx) & 1
                poly[byte_idx * 8 + bit_idx] = bit * (self.q // 2)
        return poly

    def _decode(self, poly: list) -> bytes:
        msg_bytes = bytearray(32)
        for byte_idx in range(32):
            byte = 0
            for bit_idx in range(8):
                coeff = poly[byte_idx * 8 + bit_idx]
                diff = min(
                    abs(coeff - (self.q // 2)),
                    self.q - abs(coeff - (self.q // 2)),
                )
                if diff < (self.q // 4):
                    byte |= 1 << bit_idx
            msg_bytes[byte_idx] = byte
        return bytes(msg_bytes)

    def generate_keypair(self, t: int):
        A_t = self._phi(t)
        s = self._sample_cbd()
        e = self._sample_cbd()
        b = self._poly_add(self._poly_mul(A_t, s), e)
        return (b, t), s

    def encapsulate(self, public_key: tuple, current_t: int) -> tuple[bytes, tuple, bytes]:
        """Returns (shared_secret, ciphertext (u,v), kem_confirm digest)."""
        b, t = public_key
        if abs(current_t - t) > self.allowed_skew_ms:
            raise ValueError(
                "[Security Guardrail Violation]: Timestamp expired. Lattice state collapsed."
            )

        A_t = self._phi(t)
        shared_secret = secrets.token_bytes(32)
        m_bar = self._encode(shared_secret)
        r = self._sample_cbd()
        e1 = self._sample_cbd()
        e2 = self._sample_cbd()
        u = self._poly_add(self._poly_mul(A_t, r), e1)
        v = self._poly_add(self._poly_add(self._poly_mul(b, r), e2), m_bar)
        return shared_secret, (u, v), kem_confirm_digest(shared_secret)

    def decapsulate(
        self,
        ciphertext: tuple,
        private_key: list,
        expected_confirm: bytes,
    ) -> bytes:
        """Decapsulate; KEM confirm digest is required (rejects wrong-key decapsulation)."""
        u, v = ciphertext
        w = self._poly_sub(v, self._poly_mul(u, private_key))
        shared_secret = self._decode(w)
        confirm = kem_confirm_digest(shared_secret)
        if not secure_compare(confirm, expected_confirm):
            raise KEMDecapsulationError(
                "KEM decapsulation failed confirmation check (wrong key or corrupted ciphertext)."
            )
        return shared_secret


class PassphraseGuard:
    """User-held passphrase layer (PBKDF2 + HKDF binding + AEAD payloads)."""
    SALT_BYTES = 16
    PBKDF2_ITERATIONS = 200_000

    @staticmethod
    def generate_salt() -> bytes:
        return secrets.token_bytes(PassphraseGuard.SALT_BYTES)

    @staticmethod
    def derive_key(passphrase: str, salt: bytes, iterations: int | None = None) -> bytes:
        if not passphrase:
            raise ValueError("Passphrase cannot be empty.")
        if len(salt) < PassphraseGuard.SALT_BYTES:
            raise ValueError(f"Salt must be at least {PassphraseGuard.SALT_BYTES} bytes.")
        rounds = iterations if iterations is not None else PassphraseGuard.PBKDF2_ITERATIONS
        return hashlib.pbkdf2_hmac(
            "sha256",
            passphrase.encode("utf-8"),
            salt,
            rounds,
            dklen=32,
        )

    @staticmethod
    def bind_session_key(session_key: bytes, passphrase: str, salt: bytes) -> bytes:
        passphrase_key = PassphraseGuard.derive_key(passphrase, salt)
        return hkdf_sha256(
            session_key,
            salt=passphrase_key,
            info=b"LF256-CHANNEL-BIND-v2.1",
            length=32,
        )

    @staticmethod
    def proof_token(channel_key: bytes) -> str:
        return hkdf_sha256(
            channel_key, info=b"LF256-PASSPHRASE-PROOF-v2.1", length=32
        ).hex()


class HybridSymmetricEngine:
    """
    AEAD symmetric engine (encrypt-then-MAC via HMAC-SHA256).
    Legacy name retained for API compatibility; uses v2.1 AEAD wire format.
    """

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        return aead_encrypt(data, key)

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        return aead_decrypt(data, key)


class LF256KeyMap:
    """
    Separates cryptographic map material from the user passphrase.

    v2.1 adds: kem_confirm, AEAD payloads, optional encrypted keys files.
    """
    VERSION = "2.1"
    SUPPORTED_VERSIONS = frozenset({"2.1"})
    KEYS_SUFFIX = ".lf256.keys.json"
    KEYS_ENC_SUFFIX = ".lf256.keys.enc"

    @staticmethod
    def create_network_map(
        public_seed: bytes | None = None,
        allowed_skew_ms: int | None = None,
    ) -> dict:
        seed = public_seed or secrets.token_bytes(32)
        salt = PassphraseGuard.generate_salt()
        doc = {
            "lf256_version": LF256KeyMap.VERSION,
            "kind": "network",
            "map": {
                "public_seed": seed.hex(),
                "salt": salt.hex(),
                "pbkdf2_iterations": PassphraseGuard.PBKDF2_ITERATIONS,
                "allowed_skew_ms": allowed_skew_ms or LatticeFlux256.DEFAULT_SKEW_MS,
            },
        }
        return doc

    @staticmethod
    def allowed_skew_from_map(document: dict) -> int:
        return int(
            document["map"].get("allowed_skew_ms", LatticeFlux256.DEFAULT_SKEW_MS)
        )

    @staticmethod
    def save_map(path: Path | str, document: dict) -> None:
        Path(path).write_text(json.dumps(document, indent=2), encoding="utf-8")

    @staticmethod
    def save_keys(path: Path | str, private_key_s: list) -> None:
        doc = {
            "lf256_version": LF256KeyMap.VERSION,
            "keys": {"private_key_s": private_key_s},
        }
        Path(path).write_text(json.dumps(doc, indent=2), encoding="utf-8")

    @staticmethod
    def save_keys_encrypted(path: Path | str, private_key_s: list, passphrase: str) -> None:
        """Write passphrase-wrapped keys (salt || AEAD JSON). Passphrase not stored."""
        salt = PassphraseGuard.generate_salt()
        key = PassphraseGuard.derive_key(passphrase, salt)
        inner = json.dumps(
            {"lf256_version": LF256KeyMap.VERSION, "keys": {"private_key_s": private_key_s}}
        ).encode("utf-8")
        Path(path).write_bytes(salt + aead_encrypt(inner, key))

    @staticmethod
    def is_plaintext_keys_file(path: Path | str) -> bool:
        """True if file looks like JSON keys, not salt||AEAD binary."""
        raw = Path(path).read_bytes()[:256]
        stripped = raw.lstrip()
        return stripped.startswith(b"{")

    @staticmethod
    def load_keys(path: Path | str) -> list:
        raw = Path(path).read_bytes()
        if not raw.lstrip().startswith(b"{"):
            raise ValueError(
                "Keys file is not JSON. If you sealed with encrypted keys, "
                f"use a {LF256KeyMap.KEYS_ENC_SUFFIX} file and the same passphrase."
            )
        doc = json.loads(raw.decode("utf-8"))
        LF256KeyMap._validate_keys_doc(doc)
        return doc["keys"]["private_key_s"]

    @staticmethod
    def load_keys_encrypted(path: Path | str, passphrase: str) -> list:
        raw = Path(path).read_bytes()
        if len(raw) < PassphraseGuard.SALT_BYTES + 50:
            raise ValueError("Encrypted keys file too short or corrupt.")
        salt = raw[: PassphraseGuard.SALT_BYTES]
        blob = raw[PassphraseGuard.SALT_BYTES :]
        key = PassphraseGuard.derive_key(passphrase, salt)
        try:
            inner = aead_decrypt(blob, key)
        except AeadDecryptError as exc:
            raise ValueError(
                "Could not decrypt keys file - wrong passphrase or not an encrypted keys file."
            ) from exc
        try:
            doc = json.loads(inner.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise ValueError(
                "Keys file decrypted to invalid data - wrong passphrase or corrupt file."
            ) from exc
        LF256KeyMap._validate_keys_doc(doc)
        return doc["keys"]["private_key_s"]

    @staticmethod
    def load_keys_auto(path: Path | str, passphrase: str) -> list:
        """Load keys from plaintext JSON or encrypted .keys.enc (auto-detect by content)."""
        path = Path(path)
        if LF256KeyMap.is_plaintext_keys_file(path):
            return LF256KeyMap.load_keys(path)
        return LF256KeyMap.load_keys_encrypted(path, passphrase)

    @staticmethod
    def load_map(path: Path | str) -> dict:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        LF256KeyMap._validate_map(doc)
        return doc

    @staticmethod
    def public_seed_from_map(document: dict) -> bytes:
        return bytes.fromhex(document["map"]["public_seed"])

    @staticmethod
    def salt_from_map(document: dict) -> bytes:
        return bytes.fromhex(document["map"]["salt"])

    @staticmethod
    def seal_payload(
        plaintext: bytes,
        passphrase: str,
        public_seed: bytes | None = None,
    ) -> tuple[dict, dict, bytes]:
        seed = public_seed or secrets.token_bytes(32)
        salt = PassphraseGuard.generate_salt()
        engine = LatticeFlux256(public_seed=seed)

        t = int(time.time() * 1000)
        pk, sk = engine.generate_keypair(t)
        b_poly, _ = pk
        dek, kem_ct, kem_confirm = engine.encapsulate(pk, t)
        u_poly, v_poly = kem_ct

        channel_key = PassphraseGuard.bind_session_key(dek, passphrase, salt)
        ciphertext = aead_encrypt(plaintext, channel_key)

        map_doc = {
            "lf256_version": LF256KeyMap.VERSION,
            "kind": "sealed",
            "map": {
                "public_seed": seed.hex(),
                "salt": salt.hex(),
                "pbkdf2_iterations": PassphraseGuard.PBKDF2_ITERATIONS,
            },
            "lattice": {
                "timestamp": t,
                "pk_b": b_poly,
                "kem_u": u_poly,
                "kem_v": v_poly,
                "kem_confirm": kem_confirm.hex(),
            },
        }
        keys_doc = {
            "lf256_version": LF256KeyMap.VERSION,
            "keys": {"private_key_s": sk},
        }
        return map_doc, keys_doc, ciphertext

    @staticmethod
    def unseal_payload(
        map_document: dict,
        keys_document: dict,
        ciphertext: bytes,
        passphrase: str,
    ) -> bytes:
        if map_document.get("kind") != "sealed":
            raise ValueError("Map file is not a sealed payload map (kind != sealed).")
        LF256KeyMap._validate_keys_doc(keys_document)

        seed = LF256KeyMap.public_seed_from_map(map_document)
        salt = LF256KeyMap.salt_from_map(map_document)
        sk = keys_document["keys"]["private_key_s"]
        lat = map_document["lattice"]

        engine = LatticeFlux256(public_seed=seed)
        kem_ct = (lat["kem_u"], lat["kem_v"])
        confirm_hex = lat.get("kem_confirm")
        if not confirm_hex:
            raise ValueError("Sealed map missing kem_confirm (v2.1 required).")
        expected = bytes.fromhex(confirm_hex)
        dek = engine.decapsulate(kem_ct, sk, expected_confirm=expected)
        channel_key = PassphraseGuard.bind_session_key(dek, passphrase, salt)
        try:
            return aead_decrypt(ciphertext, channel_key)
        except AeadDecryptError as exc:
            raise ValueError(
                "Could not decrypt payload - wrong passphrase or corrupt .lf256.enc file."
            ) from exc

    @staticmethod
    def channel_key_from_network_map(
        session_key: bytes, map_document: dict, passphrase: str
    ) -> bytes:
        salt = LF256KeyMap.salt_from_map(map_document)
        return PassphraseGuard.bind_session_key(session_key, passphrase, salt)

    @staticmethod
    def _validate_keys_doc(doc: dict) -> None:
        ver = doc.get("lf256_version")
        if ver not in LF256KeyMap.SUPPORTED_VERSIONS:
            raise ValueError(f"Unsupported keys file version: {ver}")
        if "keys" not in doc or "private_key_s" not in doc["keys"]:
            raise ValueError("Invalid keys file: missing private_key_s.")

    @staticmethod
    def _validate_map(document: dict) -> None:
        ver = document.get("lf256_version")
        if ver not in LF256KeyMap.SUPPORTED_VERSIONS:
            raise ValueError(
                f"Unsupported map version '{ver}'. Regenerate artifacts with v2.1 (init-map / encrypt)."
            )
        if "map" not in document:
            raise ValueError("Invalid map file: missing 'map' section.")
        if len(bytes.fromhex(document["map"].get("public_seed", ""))) != 32:
            raise ValueError("Invalid map file: public_seed must be 32 bytes.")
        if len(bytes.fromhex(document["map"].get("salt", ""))) < PassphraseGuard.SALT_BYTES:
            raise ValueError("Invalid map file: salt missing or too short.")


class StorageAndNetworkEnvelope:
    """High-level wrapper using hardened KEM + AEAD."""

    def __init__(self, public_seed: bytes, allowed_skew_ms: int | None = None):
        self.engine = LatticeFlux256(public_seed, allowed_skew_ms=allowed_skew_ms)

    def secure_payload(self, data: bytes) -> tuple[dict, bytes, list]:
        """Encrypt data; returns (header, ciphertext, private_key_s) for restore_payload."""
        t = int(time.time() * 1000)
        pk, sk = self.engine.generate_keypair(t)
        dek, kem_ct, kem_confirm = self.engine.encapsulate(pk, t)
        encrypted_payload = aead_encrypt(data, dek)
        header = {
            "pk_b": pk[0],
            "timestamp": t,
            "kem_ciphertext": kem_ct,
            "kem_confirm": kem_confirm.hex(),
        }
        return header, encrypted_payload, sk

    def restore_payload(self, header: dict, encrypted_data: bytes, sk: list) -> bytes:
        ciphertext = header["kem_ciphertext"]
        expected = bytes.fromhex(header["kem_confirm"])
        dek = self.engine.decapsulate(ciphertext, sk, expected_confirm=expected)
        return aead_decrypt(encrypted_data, dek)
