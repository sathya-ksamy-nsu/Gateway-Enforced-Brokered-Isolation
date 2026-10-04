"""End-to-end offline evaluate smoke test."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.evaluate import run_matrix
from src.llm_client import MockLLMClient


def test_run_matrix_smoke_direct_vs_brokered():
    records = run_matrix(
        MockLLMClient(),
        config={
            "modes": ["direct", "brokered"],
            "injections": ["none", "naive_exfil"],
            "broker": {"handle_ttl_sec": 60},
            "model": {"max_tool_steps": 4},
        },
    )
    assert len(records) == 4
    by_key = {(r["mode"], r["injection"]): r for r in records}

    direct_inj = by_key[("direct", "naive_exfil")]
    brokered_inj = by_key[("brokered", "naive_exfil")]

    assert direct_inj["secret_exposure_rate"] > brokered_inj["secret_exposure_rate"]
    assert direct_inj["attack_benefit_rate"] > brokered_inj["attack_benefit_rate"]
    assert brokered_inj["secret_exposure_rate"] == 0.0
    assert brokered_inj["attack_benefit_rate"] == 0.0
    # Utility should remain positive in brokered mode under injection.
    assert brokered_inj["task_utility"] > 0.0
