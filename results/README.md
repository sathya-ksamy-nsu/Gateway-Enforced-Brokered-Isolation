# Results

## Cite this freeze (paper Table III)

**Path:** [`paper/results_all_all_20261004_161636.json`](paper/results_all_all_20261004_161636.json)  
**Also:** [`paper/results_all_all_20261004_161636.csv`](paper/results_all_all_20261004_161636.csv)

| Field | Value |
| --- | --- |
| Date | 2026-10-04 |
| Model | `llama3.2:1b` (local Ollama) |
| Runs | 96, all `status=ok`, `n=12` per cell |
| Seed / temperature | 42 / 0.0 |
| Brokered exposure | 0 / 48 |
| Direct exposure | 48 / 48 |
| ABR identity | `injected AND exposed` holds on all 96 runs |

The JSON contains cell aggregates and the per-run records used to recompute
them. The `task_utility_retention` column in this file is **stale** (see the
root README). The paper reports raw utilities, exposure, ABR, canary rate, and
denials — not retention.

## Historical (do not cite as the paper table)

| Path | What it is |
| --- | --- |
| [`real/`](real/) | Earlier live matrix from 2026-09-25. Same task-set hash; utility cells differ from the paper freeze. |
| [`smoke/`](smoke/) | Offline mock / pipeline validation. Labelled **SYNTHETIC**. Not empirical results. |

[`DATA_FREEZE.md`](DATA_FREEZE.md) records the task-set hash and both live
runs. [`run_meta.json`](run_meta.json) is the 2026-09-14 smoke environment
snapshot.
