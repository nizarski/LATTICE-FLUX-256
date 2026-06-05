"""Ensure project src/ is on sys.path for application scripts."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"


def ensure_src() -> Path:
    src = str(_SRC)
    if src not in sys.path:
        sys.path.insert(0, src)
    return _ROOT
