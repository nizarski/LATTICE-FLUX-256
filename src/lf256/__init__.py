"""LF-256 — lattice KEM + AEAD + p-ssphrase binding."""

from .crypto_utils import AeadDecryptError, KEMDecapsulationError, secure_compare
from .engine import (
    HybridSymmetricEngine,
    LF256KeyMap,
    LatticeFlux256,
    PassphraseGuard,
    StorageAndNetworkEnvelope,
)

__version__ = "2.1.0"

__all__ = [
    "LatticeFlux256",
    "HybridSymmetricEngine",
    "PassphraseGuard",
    "LF256KeyMap",
    "StorageAndNetworkEnvelope",
    "KEMDecapsulationError",
    "AeadDecryptError",
    "secure_compare",
    "__version__",
]
