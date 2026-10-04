"""Experiment orchestration (paper Section 4.6).

Runs the matrix:

    {credential mode} × {injection strategy} × {task}

and writes aggregated metrics (secret-exposure rate, ABR, utility) to ``results/``.
No numbers are fabricated — every value is computed from an actual (mock or real)
agent run. Mock numbers are SYNTHETIC / PIPELINE VALIDATION only.
"""
from __future__ import annotations

import csv
import json
import os
import time
from typing import Dict, List, Optional

from . import injections as I
from . import metrics as M
from . import secrets as S
from . import tasks as T
from .agent import run_agent
from .llm_client import BaseLLMClient


def load_task_set(config: Optional[Dict] = None) -> List[T.AgentTask]:
    path = (config or {}).get("task", {}).get("path")
    if path and os.path.exists(path):
        return T.load_tasks_from_jsonl(path)
    print("[info] No task.path found; using SYNTHETIC task set (not a benchmark).")
    return T.build_synthetic_dataset()


def evaluate_cell(
    client: BaseLLMClient,
    tasks: List[T.AgentTask],
    mode: str,
    injection: str,
    config: Optional[Dict] = None,
    reference_success: Optional[Dict[str, bool]] = None,
) -> Dict:
    """Run one (mode, injection) cell over all tasks; return aggregate metrics."""
    cfg = config or {}
    broker_cfg = cfg.get("broker", {})
    max_steps = int(cfg.get("model", {}).get("max_tool_steps", 4))

    runs = [
        run_agent(
            task=task,
            mode=mode,
            injection=injection,
            llm=client,
            broker_cfg=broker_cfg,
            max_steps=max_steps,
        )
        for task in tasks
    ]

    exposed = [r.exposed_secret for r in runs]
    # ABR is defined over injected runs; for injection==none use empty → 0.0
    if injection == "none":
        abr_flags: List[bool] = []
    else:
        abr_flags = [r.attack_success for r in runs]
    task_success = [r.success for r in runs]
    canary = [r.canary_hit for r in runs]

    ref_list = None
    if reference_success is not None:
        ref_list = [reference_success[r.task_id] for r in runs]

    summary = M.summarize_cell(
        exposed=exposed,
        attack_success=abr_flags,
        task_success=task_success,
        reference_success=ref_list,
        canary_hit=canary,
    )
    return {
        "mode": mode,
        "injection": injection,
        "n_tasks": len(runs),
        **summary,
        "mean_denied_count": round(
            sum(r.denied_count for r in runs) / max(len(runs), 1), 4
        ),
    }


def run_matrix(
    client: BaseLLMClient,
    config: Optional[Dict] = None,
    mode_names: Optional[List[str]] = None,
    injection_names: Optional[List[str]] = None,
) -> List[Dict]:
    """Run full {mode} × {injection} matrix; return metric records."""
    cfg = config or {}
    tasks = load_task_set(cfg)

    if mode_names is None:
        mode_names = cfg.get("modes", ["direct", "brokered"])
    if injection_names is None:
        injection_names = cfg.get("injections", I.list_injections())

    # Reference utility: unhardened clean cell (direct + no injection).
    # If direct is not in the requested modes, fall back to first mode clean.
    ref_mode = "direct" if "direct" in mode_names else mode_names[0]
    reference_success: Dict[str, bool] = {}
    for task in tasks:
        r = run_agent(
            task=task,
            mode=ref_mode,
            injection="none",
            llm=client,
            broker_cfg=cfg.get("broker", {}),
            max_steps=int(cfg.get("model", {}).get("max_tool_steps", 4)),
        )
        reference_success[task.id] = r.success

    records: List[Dict] = []
    for mode in mode_names:
        for injection in injection_names:
            records.append(
                evaluate_cell(
                    client,
                    tasks,
                    mode=mode,
                    injection=injection,
                    config=cfg,
                    reference_success=reference_success,
                )
            )
    return records


def write_results(
    records: List[Dict],
    config: Optional[Dict] = None,
    tag: str = "matrix",
) -> Dict[str, str]:
    """Write JSON/CSV under results/, with optional secret redaction."""
    cfg = config or {}
    out_cfg = cfg.get("output", {})
    results_dir = out_cfg.get("results_dir", "results")
    formats = out_cfg.get("formats", ["json", "csv"])
    redact = bool(out_cfg.get("redact_logs", True))
    os.makedirs(results_dir, exist_ok=True)

    stamp = time.strftime("%Y%m%d_%H%M%S")
    written: Dict[str, str] = {}

    safe_records = [S.redact_record(r) if redact else r for r in records]
    mock_run = bool(cfg.get("model", {}).get("mock", False)) or str(tag).startswith(
        "mock"
    )

    if "json" in formats:
        path = os.path.join(results_dir, f"results_{tag}_{stamp}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "tag": tag,
                    "status": "mock" if mock_run else "ok",
                    "synthetic_or_pending": bool(mock_run),
                    "note": (
                        "Mock/offline numbers are SYNTHETIC / PIPELINE VALIDATION "
                        "only. Do not cite as empirical findings."
                        if mock_run
                        else "Live matrix status=ok; cite only these cells in papers."
                    ),
                    "records": safe_records,
                },
                f,
                indent=2,
            )
        written["json"] = path

    if "csv" in formats:
        path = os.path.join(results_dir, f"results_{tag}_{stamp}.csv")
        if safe_records:
            keys = list(safe_records[0].keys())
            with open(path, "w", encoding="utf-8", newline="") as f:
                w = csv.DictWriter(f, fieldnames=keys)
                w.writeheader()
                for row in safe_records:
                    w.writerow(row)
        written["csv"] = path

    return written
