"""Safety regressions: defensive framing, fake tokens only, no theft recipes."""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(ROOT))

# Patterns that would indicate real credential-theft / weaponization content.
FORBIDDEN_CODE_PATTERNS = [
    re.compile(r"\bcurl\s+https?://", re.I),
    re.compile(r"\bwget\s+https?://", re.I),
    re.compile(r"sk_live_[A-Za-z0-9]+"),  # live-looking Stripe-style keys
    re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
    re.compile(r"\bmetasploit\b", re.I),
    re.compile(r"\bshellcode\b", re.I),
    re.compile(r"\breverse[_\s-]?shell\b", re.I),
]


def _iter_code_files():
    for base in (SRC, ROOT / "experiments"):
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.suffix in {".py", ".yaml", ".yml"} and path.is_file():
                yield path
    cfg = ROOT / "config.yaml"
    if cfg.exists():
        yield cfg


def test_no_weaponization_or_live_key_markers():
    offenders = []
    for path in _iter_code_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for pat in FORBIDDEN_CODE_PATTERNS:
            if pat.search(text):
                offenders.append(f"{path.relative_to(ROOT)} :: {pat.pattern}")
    assert not offenders, "Unsafe markers found:\n" + "\n".join(offenders)


def test_all_configured_secrets_are_redacted_placeholders():
    from src import secrets as S

    for name, value in S.FAKE_SECRETS.items():
        assert "REDACTED" in value, f"{name} must be a REDACTED placeholder"
        assert value.startswith("sk_test_") or value.startswith("cert_test_")


def test_brokered_mode_invariant_documented_in_broker():
    text = (SRC / "broker.py").read_text(encoding="utf-8")
    assert "NEVER" in text or "never" in text
    assert "FAKE_SECRETS" in text or "contains_secret_material" in text
