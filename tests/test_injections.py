"""Injection suite and redaction tests."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src import injections as I
from src import secrets as S


def test_list_injections_includes_none():
    names = I.list_injections()
    assert names[0] == "none"
    assert "naive_exfil" in names
    assert "tool_override" in names
    assert "fake_completion" in names


def test_apply_none_is_identity():
    assert I.apply_injection("none", "hello") == "hello"


def test_injections_are_tagged_research_artifacts():
    base = "Check status of demo-api."
    for name in I.list_injections(include_none=False):
        out = I.apply_injection(name, base)
        assert I.RESEARCH_TAG in out
        assert base in out
        assert I.CANARY in out


def test_unknown_injection_raises():
    try:
        I.apply_injection("not_a_real_strategy", "x")
        assert False, "expected KeyError"
    except KeyError:
        pass


def test_redact_text_masks_fake_secrets():
    raw = f"token={S.FAKE_SECRET_TOKEN} ok"
    red = S.redact_text(raw)
    assert S.FAKE_SECRET_TOKEN not in red
    assert S.REDACTION_TOKEN in red


def test_redact_record_nested():
    rec = {
        "a": S.FAKE_SECRET_TOKEN,
        "b": {"c": S.FAKE_SECRETS["service_token"]},
        "d": [S.FAKE_SECRETS["client_cert_handle"]],
    }
    out = S.redact_record(rec)
    assert S.FAKE_SECRET_TOKEN not in str(out)
    assert out["a"] == S.REDACTION_TOKEN
