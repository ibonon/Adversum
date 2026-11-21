# Adversum — Reproducible benchmark (P0)

- Dataset: `benchmarks\corpus` (dappscan)
- Engine: Adversum native Solidity rules (Slither/Aderyn disabled)
- Git SHA: `6ad7573` · Generated: 2026-11-21T18:32:24Z
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

## Verdict distribution (Step 4 — UNKNOWN never hidden)

Global (9 findings): PROVEN 1 (11.1%) · DEPENDENCY_PROVEN 2 (22.2%) · DETECTED_UNPROVEN 6 (66.7%) · UNKNOWN 0 (0.0%)

| Rule | PROVEN | DEPENDENCY_PROVEN | DETECTED_UNPROVEN | UNKNOWN | Total |
|---|---:|---:|---:|---:|---:|
| SOL-001 | 0 | 0 | 1 | 0 | 1 |
| SOL-002 | 0 | 0 | 1 | 0 | 1 |
| SOL-003 | 0 | 0 | 1 | 0 | 1 |
| SOL-004 | 1 | 0 | 1 | 0 | 2 |
| SOL-006 | 0 | 0 | 1 | 0 | 1 |
| SOL-007 | 0 | 0 | 1 | 0 | 1 |
| SOL-011 | 0 | 1 | 0 | 0 | 1 |
| SOL-013 | 0 | 1 | 0 | 0 | 1 |

| SmartBugs category | PROVEN | DEPENDENCY_PROVEN | DETECTED_UNPROVEN | UNKNOWN |
|---|---:|---:|---:|---:|
| access_control | 0 | 0 | 2 | 0 |
| arithmetic | 1 | 0 | 1 | 0 |
| bad_randomness | 0 | 1 | 1 | 0 |
| denial_of_service | 0 | 1 | 0 | 0 |
| reentrancy | 0 | 0 | 1 | 0 |
| time_manipulation | 0 | 0 | 1 | 0 |
| unchecked_low_level_calls | 0 | 0 | 1 | 0 |

## Missed contracts (false negatives), by category


Regenerate: `python benchmarks/run_benchmark.py` (see benchmarks/README.md).
