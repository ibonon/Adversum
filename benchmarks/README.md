# Benchmarks — methodology (P0)

Every published number must be regenerable from this directory. Historical
figures that no script replayed have been requalified in `BENCHMARK.md`.

## Detection quality (SmartBugs / DAppSCAN-style)

```bash
# Bundled offline corpus (always works, used in CI):
python benchmarks/run_benchmark.py --dataset benchmarks/corpus
# Full SmartBugs curated (143 contracts) when available:
python benchmarks/run_benchmark.py --dataset /path/to/smartbugs-curated
# DAppSCAN / generic manifest (labels.json next to the files):
python benchmarks/run_benchmark.py --dataset /path/to/dappscan --format dappscan
```

Outputs `benchmarks/results/latest.json` + `.md`: per-category and per-CWE
precision/recall/F1 (contract level), line-level recall (±3 lines), missed
contracts, git SHA and engine identity. Mapping lives in
`run_benchmark.py` (`CATEGORY_RULES`, `CATEGORY_CWE`).

Measured baseline (SmartBugs curated, native rules, this commit): see
`benchmarks/results/latest.md`. Headline at time of writing: 106/143
contracts matched (was 45/143), reentrancy F1 71.4% (was 2.0%), line recall
45.9% (was 11.7%). These are measurements, not guarantees.

## LLM anti-hallucination eval

```bash
python benchmarks/run_llm_eval.py
```

Recorded hypotheses with deliberately wrong lines are replayed through
anchoring + Z3; see `llm_eval_cases.json`.

## Throughput (versioned)

```bash
python benchmarks/run_throughput.py
```

Writes `benchmarks/results/throughput_v1.json` (version, git SHA, corpus,
lines/sec). No throughput figure may be published without this file.
