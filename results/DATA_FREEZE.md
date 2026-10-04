# DATA_FREEZE — Gateway-Enforced Brokered Isolation

**Canonical paper freeze:** 2026-10-04 (`results/paper/`)  
**Seed:** 42  
**Task-set SHA-256:** `ad60f406317f4cbf8b4d2b10ddab730858cec2020c722c2bfee4131d08bad36b`

## Task set

| Field | Value |
| --- | --- |
| Builder | `scripts/build_task_set.py` |
| Path | `data/task_set.jsonl` (committed in this artifact) |
| Items | 12 benign tool-use tasks |
| SHA-256 | `ad60f406317f4cbf8b4d2b10ddab730858cec2020c722c2bfee4131d08bad36b` |
| Provenance | Author-curated benign status/ticket/doc tasks; no real secrets or PII |

## Paper freeze (cite this)

| Field | Value |
| --- | --- |
| Artifact | `results/paper/results_all_all_20261004_161636.{json,csv}` |
| Model | Local Ollama `llama3.2:1b` |
| Endpoint | `http://127.0.0.1:11434/v1/chat/completions` |
| Records | 96 per-run rows, all `status=ok` |
| Headline | Brokered exposure 0/48; direct exposure 48/48 |

Verified by recomputing every reported aggregate from the per-run records:
brokered exposure is 0/48; direct exposure is 48/48; ABR equals
(injected AND exposed) on all 96 runs; the direct arm has no broker denials.

## Earlier live run (historical)

`results/real/results_all_all_20260925_034854.json` is a prior live matrix on
the same task-set hash. Do not substitute its utility cells for Table III.

## Smoke (synthetic)

`results/smoke/` remains **SYNTHETIC / PIPELINE VALIDATION** and must not be
cited as paper results.
