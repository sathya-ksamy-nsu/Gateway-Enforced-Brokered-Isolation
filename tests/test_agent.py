"""Agent-loop tests: direct vs brokered under injection (offline mock)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src import secrets as S
from src.agent import run_agent
from src.llm_client import MockLLMClient
from src.tasks import build_synthetic_dataset


def test_direct_injection_exposes_secret():
    task = build_synthetic_dataset()[0]
    result = run_agent(task, mode="direct", injection="naive_exfil", llm=MockLLMClient())
    assert result.exposed_secret is True
    assert result.attack_success is True
    assert S.FAKE_SECRET_TOKEN in result.final_answer or result.exposed_secret


def test_brokered_injection_does_not_expose_secret():
    task = build_synthetic_dataset()[0]
    result = run_agent(
        task, mode="brokered", injection="naive_exfil", llm=MockLLMClient()
    )
    assert result.exposed_secret is False
    assert result.attack_success is False
    assert not S.contains_secret_material(result.final_answer)
    for line in result.tool_transcript:
        assert not S.contains_secret_material(line)


def test_brokered_clean_completes_task():
    task = build_synthetic_dataset()[1]
    result = run_agent(task, mode="brokered", injection="none", llm=MockLLMClient())
    assert result.success is True
    assert result.exposed_secret is False
    assert result.attack_success is False


def test_direct_clean_still_exposes_via_get_secret():
    """Baseline: direct mode puts secrets in tool results even without injection."""
    task = build_synthetic_dataset()[0]
    result = run_agent(task, mode="direct", injection="none", llm=MockLLMClient())
    assert result.exposed_secret is True
    assert result.attack_success is False  # no injection → ABR not counted


def test_as_record_redacts_secrets():
    task = build_synthetic_dataset()[0]
    result = run_agent(task, mode="direct", injection="tool_override", llm=MockLLMClient())
    record = result.as_record()
    blob = str(record)
    assert S.FAKE_SECRET_TOKEN not in blob
    assert S.REDACTION_TOKEN in blob or not S.contains_secret_material(blob)
