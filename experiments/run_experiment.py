"""CLI entry point for the brokered-credential isolation harness.

Reads ``config.yaml``, runs {mode} × {injection} × {task}, writes metrics to
``results/``. With ``--mock`` the pipeline is fully offline.

Examples (from the topic-16 project root):

    python experiments/run_experiment.py --mock
    python experiments/run_experiment.py --mock --mode brokered --injection naive_exfil
"""
from __future__ import annotations

import argparse
import os
import random
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def load_config(path: str) -> dict:
    import yaml

    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def set_global_seeds(seed: int) -> None:
    random.seed(seed)
    try:
        import numpy as np

        np.random.seed(seed)
    except ImportError:  # pragma: no cover
        pass


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Brokered-credential isolation evaluation harness."
    )
    p.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    p.add_argument(
        "--mode",
        default="all",
        help="Credential mode (direct|brokered) or 'all'.",
    )
    p.add_argument(
        "--injection",
        default="all",
        help=(
            "Injection (none|naive_exfil|tool_override|fake_completion) or 'all'."
        ),
    )
    p.add_argument(
        "--mock",
        action="store_true",
        help="Use the offline deterministic mock agent (no network / API key).",
    )
    p.add_argument("--seed", type=int, default=None, help="Override the RNG seed.")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    cfg = {}
    if os.path.exists(args.config):
        cfg = load_config(args.config)
    else:
        print(f"[warn] {args.config} not found; using built-in defaults.")

    if args.seed is not None:
        cfg["seed"] = args.seed
    set_global_seeds(int(cfg.get("seed", 42)))

    from src import evaluate as E
    from src import injections as I
    from src.llm_client import get_client

    mode_names = (
        list(cfg.get("modes", ["direct", "brokered"]))
        if args.mode == "all"
        else [args.mode]
    )
    injection_names = (
        I.list_injections() if args.injection == "all" else [args.injection]
    )

    try:
        client = get_client(cfg, mock=args.mock)
    except RuntimeError as e:
        print(f"[error] {e}", file=sys.stderr)
        print(
            "[hint] Re-run with --mock to exercise the pipeline offline.",
            file=sys.stderr,
        )
        return 2

    mock_run = bool(args.mock or cfg.get("model", {}).get("mock", False))
    cfg.setdefault("model", {})["mock"] = mock_run
    if mock_run:
        print(
            "[info] Using MOCK agent — results are SYNTHETIC / PIPELINE "
            "VALIDATION only."
        )
    else:
        print(
            f"[info] Using LIVE agent model={cfg.get('model', {}).get('name')} "
            f"endpoint={cfg.get('model', {}).get('endpoint')}"
        )

    records = E.run_matrix(
        client, config=cfg, mode_names=mode_names, injection_names=injection_names
    )
    for r in records:
        r["status"] = "mock" if mock_run else "ok"
        r["model_name"] = cfg.get("model", {}).get("name", "")

    print(f"\n[info] Completed {len(records)} matrix cell(s):")
    print(
        f"  {'mode':<10}{'injection':<18}"
        f"{'expose':>8}{'ABR':>8}{'util':>8}"
    )
    for r in records:
        print(
            f"  {r['mode']:<10}{r['injection']:<18}"
            f"{r['secret_exposure_rate']:>8.2f}"
            f"{r['attack_benefit_rate']:>8.2f}"
            f"{r['task_utility']:>8.2f}"
        )

    cfg.setdefault("output", {})
    sub = "smoke" if mock_run else "real"
    cfg["output"]["results_dir"] = os.path.join(_PROJECT_ROOT, "results", sub)
    os.makedirs(cfg["output"]["results_dir"], exist_ok=True)

    written = E.write_results(records, cfg, tag=f"{args.mode}_{args.injection}")
    for fmt, path in written.items():
        print(f"[info] wrote {fmt}: {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
