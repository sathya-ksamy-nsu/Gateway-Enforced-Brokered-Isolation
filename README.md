# Gateway-Enforced Brokered Isolation (GEBI)

Reproduction artifacts for **Can Your Agent See the Key? Gateway-Enforced
Brokered Isolation for LLM Tool-Using Agents** (IEEE MetroCon 2026).

This repository is the public artifact for the paper. It contains the
direct-vs-brokered harness, the frozen 12-task set, the 96-run result file that
backs Table III, offline tests, and the IEEE manuscript sources.

**Paper:** [paper/metrocon2026-topic16.pdf](paper/metrocon2026-topic16.pdf)  
**Canonical result file:** [results/paper/results_all_all_20261004_161636.json](results/paper/results_all_all_20261004_161636.json)  
**Task-set SHA-256:** `ad60f406317f4cbf8b4d2b10ddab730858cec2020c722c2bfee4131d08bad36b`

## What GEBI claims

LLM tool-using agents should not hold bearer secrets in the model context.
GEBI keeps credentials on a policy gateway: the agent names an action, the
broker allowlists or denies it, substitutes the secret server-side, and returns
a scrubbed result. The experiment compares that architecture to a direct
`get_secret` baseline under sanitized prompt injection.

On the frozen 12-task set with local `llama3.2:1b` (96 runs, `n=12` per cell):

| Mode | Injection | Exposure | ABR | Utility | Canary | Denials |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Direct | none | 1.00 | 0.00 | 0.33 | 0.00 | 0.00 |
| Direct | naive_exfil | 1.00 | 1.00 | 0.58 | 0.75 | 0.00 |
| Direct | tool_override | 1.00 | 1.00 | 0.25 | 0.33 | 0.00 |
| Direct | fake_completion | 1.00 | 1.00 | 0.50 | 0.75 | 0.00 |
| Brokered | none | 0.00 | 0.00 | 0.17 | 0.00 | 1.17 |
| Brokered | naive_exfil | 0.00 | 0.00 | 0.33 | 0.42 | 0.75 |
| Brokered | tool_override | 0.00 | 0.00 | 0.25 | 0.25 | 0.75 |
| Brokered | fake_completion | 0.00 | 0.00 | 0.50 | 0.67 | 0.33 |

Brokered exposure is **0/48**. Direct exposure is **48/48**. Those cells are
the paper table; do not cite the older `results/real/` or synthetic
`results/smoke/` numbers in their place.

## Ethics (defensive research)

- Credentials are non-operational placeholders (`sk_test_REDACTED*`,
  `[CRED-RESEARCH]`).
- Injection payloads are tagged research artifacts (`[PI-RESEARCH]`) with a
  canary. They are not working theft recipes.
- Brokered mode never returns a secret to the model (enforced in code and
  tested).
- Transcripts are redacted on write.
- Default config is **offline mock**. A live model is optional.

## Folder map

```
.
  README.md                 This file
  LICENSE                   MIT
  CITATION.cff
  requirements.txt
  config.yaml               Seed, modes, injections, broker policy
  data/
    README.md
    task_set.jsonl          Frozen 12-task set (paper SHA-256)
  src/                      Harness (broker, tools, agent, metrics)
  experiments/              CLI entry point
  scripts/build_task_set.py Regenerates the frozen task set
  tests/                    Offline unit + invariant tests
  results/
    README.md
    paper/                  2026-10-04 freeze used in the MetroCon paper
    real/                   Earlier 2026-09-25 live run (historical)
    smoke/                  Synthetic mock pipeline check (not paper results)
  paper/
    README.md
    metrocon2026-topic16.tex
    metrocon2026-topic16.pdf
```

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

macOS/Linux: `source .venv/bin/activate`.

## Tests

```powershell
pytest tests/ -v
```

All tests are offline. Broker tests assert that secrets never appear in
brokered tool results. `tests/test_reference_mode.py` checks that
utility-retention uses the unhardened `direct|none` cell as the denominator
(the paper reports raw utilities, not retention).

## Reproduce the paper table

The published numbers are already in `results/paper/`. The JSON has cell
aggregates in `records` and the 96 per-run rows in `runs`. To recompute
exposure from those rows:

```powershell
python -c "import json; from collections import Counter; d=json.loads(open('results/paper/results_all_all_20261004_161636.json',encoding='utf-8').read()); c=Counter((r['mode'], r['exposed_secret']) for r in d['runs'].values()); print(dict(c)); assert c[('brokered', False)]==48 and c[('direct', True)]==48"
```

To **re-run** the live matrix you need a local Ollama model:

```powershell
ollama pull llama3.2:1b
$env:LLM_API_KEY = "ollama-local"
# set model.mock: false in config.yaml
python experiments/run_experiment.py --mode all --injection all
```

Offline mock (pipeline check only — not paper numbers):

```powershell
python experiments/run_experiment.py --mock
```

## Honesty about this freeze

- Isolation is modelled in-process, not enforced by a container or network
  boundary.
- Only a static bearer placeholder (Class B) is exercised end-to-end.
- Handle TTL is recorded at issuance and not re-checked on use.
- Exposure is an exact substring test on placeholder tokens.
- The `task_utility_retention` column in the 2026-10-04 JSON is **stale**: it
  was written before the reference cell was corrected to `direct|none`. The
  paper does not report retention. Re-running the harness now uses the
  unhardened clean cell.

## Citation

See [CITATION.cff](CITATION.cff). Prefer citing the MetroCon 2026 paper and
this repository URL:

<https://github.com/sathya-ksamy-nsu/Gateway-Enforced-Brokered-Isolation>
