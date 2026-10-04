"""Retention baseline must be the unhardened clean cell (direct|none)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.evaluate import run_matrix
from src.llm_client import MockLLMClient


def test_evaluate_source_uses_direct_reference_mode():
    src = (ROOT / "src" / "evaluate.py").read_text(encoding="utf-8")
    assert 'ref_mode = "direct"' in src
    assert 'ref_mode = "brokered"' not in src


def test_retention_normalizes_against_direct_none():
    records = run_matrix(
        MockLLMClient(),
        config={
            "modes": ["direct", "brokered"],
            "injections": ["none"],
            "broker": {"handle_ttl_sec": 60},
            "model": {"max_tool_steps": 4},
        },
    )
    by_key = {(r["mode"], r["injection"]): r for r in records}
    direct_none = by_key[("direct", "none")]
    brokered_none = by_key[("brokered", "none")]
    assert direct_none["task_utility_retention"] == 1.0
    if direct_none["task_utility"] > 0:
        expected = round(
            brokered_none["task_utility"] / direct_none["task_utility"], 4
        )
        assert brokered_none["task_utility_retention"] == expected
