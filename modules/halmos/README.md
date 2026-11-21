# Halmos witnesses (Step 2)

Versioned Foundry harnesses whose Halmos counterexamples become
Step-1 `PROVEN` witnesses. Scope is exactly the provable subset —
SOL-004, SOL-001, SOL-003/012, SOL-007, SOL-002. Nothing outside it
claims a Halmos proof (Step 3 covers the intermediate group).

## Toolchain (verified in this environment)

- Foundry `forge`/`anvil` 1.10.0 (`~/.foundry/bin`, or `FORGE_BIN`/`$PATH`)
- Halmos 0.3.3 (`pip install halmos`; note it pins `z3-solver` 4.12.6)

Without the toolchain the runner reports `unavailable` and every
verdict is `UNKNOWN` — no witness is ever fabricated.

## Harnesses

| Rule | Contract | Vulnerable check | Safe counterpart |
|---|---|---|---|
| SOL-004 | `HalmosSOL004Test` | `check_vulnerable_add_no_overflow` | `check_safe_add_no_overflow` |
| SOL-001 | `HalmosSOL001Test` | `check_vulnerable_no_drain` | `check_safe_no_drain` |
| SOL-003/012 | `HalmosSOL003Test` | `check_vulnerable_nonowner_cannot_kill` | `check_safe_nonowner_cannot_kill` |
| SOL-007 | `HalmosSOL007Test` | `check_vulnerable_failed_call_not_paid` | `check_safe_failed_call_not_paid` |
| SOL-002 | `HalmosSOL002Test` | `check_vulnerable_trap_cannot_drain` | `check_safe_trap_cannot_drain` |

Run one: `halmos --root modules/halmos --contract HalmosSOL004Test`
Programmatic: `modules.halmos.runner.run_halmos_harness("SOL-004")`.

Semantics: counterexample → `PROVEN` + `halmos_counterexample` witness;
no counterexample within bounds → stays `DETECTED_UNPROVEN` (bounded
absence, not proven safe); timeout/error/unavailable → `UNKNOWN`.
