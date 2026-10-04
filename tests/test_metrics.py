"""Unit tests for metrics (numpy-only, offline)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src import metrics as M


def test_secret_exposure_rate():
    assert M.secret_exposure_rate([]) == 0.0
    assert M.secret_exposure_rate([True, False, True, False]) == 0.5
    assert M.secret_exposure_rate([False, False]) == 0.0
    assert M.secret_exposure_rate([True, True]) == 1.0


def test_attack_benefit_rate():
    assert M.attack_benefit_rate([]) == 0.0
    assert M.attack_benefit_rate([True, True, False]) == 2 / 3


def test_task_utility_and_retention():
    assert M.task_utility([True, True, False]) == 2 / 3
    assert M.task_utility_retention([True, False]) == 0.5
    assert M.task_utility_retention([True, True], [True, True]) == 1.0
    assert M.task_utility_retention([True, False], [True, True]) == 0.5
    assert M.task_utility_retention([True], [False]) == 0.0


def test_summarize_cell():
    s = M.summarize_cell(
        exposed=[True, False],
        attack_success=[True],
        task_success=[True, True],
        reference_success=[True, True],
        canary_hit=[True, False],
    )
    assert s["secret_exposure_rate"] == 0.5
    assert s["attack_benefit_rate"] == 1.0
    assert s["task_utility"] == 1.0
    assert s["task_utility_retention"] == 1.0
    assert s["canary_rate"] == 0.5
