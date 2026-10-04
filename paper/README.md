# MetroCon 2026 manuscript

IEEE conference source for *Can Your Agent See the Key? Gateway-Enforced
Brokered Isolation for LLM Tool-Using Agents*.

| File | Role |
| --- | --- |
| `metrocon2026-topic16.tex` | IEEEtran `conference` source |
| `metrocon2026-topic16.pdf` | Compiled two-column IEEE PDF (7 pages) |

The paper's Table III is sourced from
`../results/paper/results_all_all_20261004_161636.json`.

## Compile

This workstation build used [Tectonic](https://tectonic-typesetting.github.io/)
0.17 with the official IEEEtran class. Overleaf also works (pdfLaTeX).

```powershell
tectonic -X compile --keep-logs metrocon2026-topic16.tex
```

Or on Overleaf: New Project → upload `metrocon2026-topic16.tex` → compiler
**pdfLaTeX** → Recompile.
