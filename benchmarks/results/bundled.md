# Adversum — Reproducible benchmark (P0)

- Dataset: `benchmarks\corpus` (dappscan)
- Engine: Adversum native Solidity rules (Slither/Aderyn disabled)
- Git SHA: `d1bc5b1` · Generated: 2026-11-20T23:40:19Z
- Contracts: 8 · Flagged (any rule): 6 · Matched category: 6
- Line recall (±3): 100.0% (7 lines) · Macro-F1 (categories with truth): 100.0%

## Per category (contract level)

| Category | CWE | Rules | TP | FP | FN | Precision % | Recall % | F1 % |
|---|---|---|---:|---:|---:|---:|---:|---:|
| access_control | CWE-284 | SOL-002, SOL-003 | 1 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| arithmetic | CWE-190 | SOL-004 | 1 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| bad_randomness | CWE-330 | SOL-006, SOL-011 | 1 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| denial_of_service | CWE-770 | SOL-013 | 1 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| front_running | CWE-362 | SOL-009 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 |
| other |  | — | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 |
| reentrancy | CWE-841 | SOL-001 | 1 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| short_addresses | CWE-371 | — | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 |
| time_manipulation | CWE-330 | SOL-006 | 0 | 1 | 0 | 0.0 | 0.0 | 0.0 |
| unchecked_low_level_calls | CWE-252 | SOL-007 | 1 | 0 | 0 | 100.0 | 100.0 | 100.0 |

## Per CWE (contract level)

| CWE | TP | FP | FN | Precision % | Recall % | F1 % |
|---|---:|---:|---:|---:|---:|---:|
| CWE-190 | 1 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| CWE-252 | 1 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| CWE-284 | 1 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| CWE-330 | 1 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| CWE-770 | 1 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| CWE-841 | 1 | 0 | 0 | 100.0 | 100.0 | 100.0 |

## Missed contracts (false negatives), by category


Regenerate: `python benchmarks/run_benchmark.py` (see benchmarks/README.md).
