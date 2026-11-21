# Adversum — Reproducible benchmark (P0)

- Dataset: `C:\Users\SMC-DXB\Projects\adversum-bench\smartbugs-curated` (smartbugs)
- Engine: Adversum native Solidity rules (Slither/Aderyn disabled)
- Git SHA: `6ad7573` · Generated: 2026-11-21T15:55:57Z
- Contracts: 143 · Flagged (any rule): 130 · Matched category: 106
- Line recall (±3): 45.9% (222 lines) · Macro-F1 (categories with truth): 30.6%

## Per category (contract level)

| Category | CWE | Rules | TP | FP | FN | Precision % | Recall % | F1 % |
|---|---|---|---:|---:|---:|---:|---:|---:|
| access_control | CWE-284 | SOL-002, SOL-003 | 4 | 5 | 14 | 44.4 | 22.2 | 29.6 |
| arithmetic | CWE-190 | SOL-004 | 15 | 55 | 0 | 21.4 | 100.0 | 35.3 |
| bad_randomness | CWE-330 | SOL-006, SOL-011 | 5 | 11 | 3 | 31.2 | 62.5 | 41.7 |
| denial_of_service | CWE-770 | SOL-013 | 2 | 20 | 4 | 9.1 | 33.3 | 14.3 |
| front_running | CWE-362 | SOL-009 | 0 | 1 | 4 | 0.0 | 0.0 | 0.0 |
| other |  | — | 0 | 0 | 3 | 0.0 | 0.0 | 0.0 |
| reentrancy | CWE-841 | SOL-001 | 30 | 23 | 1 | 56.6 | 96.8 | 71.4 |
| short_addresses | CWE-371 | — | 0 | 0 | 1 | 0.0 | 0.0 | 0.0 |
| time_manipulation | CWE-330 | SOL-006 | 2 | 3 | 3 | 40.0 | 40.0 | 40.0 |
| unchecked_low_level_calls | CWE-252 | SOL-007 | 48 | 31 | 4 | 60.8 | 92.3 | 73.3 |

## Per CWE (contract level)

| CWE | TP | FP | FN | Precision % | Recall % | F1 % |
|---|---:|---:|---:|---:|---:|---:|
| CWE-190 | 15 | 55 | 0 | 21.4 | 100.0 | 35.3 |
| CWE-252 | 48 | 31 | 4 | 60.8 | 92.3 | 73.3 |
| CWE-284 | 5 | 5 | 13 | 50.0 | 27.8 | 35.7 |
| CWE-330 | 8 | 8 | 5 | 50.0 | 61.5 | 55.2 |
| CWE-362 | 0 | 1 | 4 | 0.0 | 0.0 | 0.0 |
| CWE-371 | 0 | 0 | 1 | 0.0 | 0.0 | 0.0 |
| CWE-770 | 2 | 20 | 4 | 9.1 | 33.3 | 14.3 |
| CWE-841 | 30 | 23 | 1 | 56.6 | 96.8 | 71.4 |

## Verdict distribution (Step 4 — UNKNOWN never hidden)

Global (556 findings): PROVEN 76 (13.7%) · DEPENDENCY_PROVEN 28 (5.0%) · DETECTED_UNPROVEN 414 (74.5%) · UNKNOWN 38 (6.8%)

| Rule | PROVEN | DEPENDENCY_PROVEN | DETECTED_UNPROVEN | UNKNOWN | Total |
|---|---:|---:|---:|---:|---:|
| SOL-001 | 0 | 0 | 83 | 0 | 83 |
| SOL-002 | 0 | 0 | 3 | 0 | 3 |
| SOL-003 | 0 | 0 | 6 | 0 | 6 |
| SOL-004 | 76 | 0 | 134 | 38 | 248 |
| SOL-005 | 0 | 0 | 2 | 0 | 2 |
| SOL-006 | 0 | 1 | 4 | 0 | 5 |
| SOL-007 | 0 | 0 | 156 | 0 | 156 |
| SOL-009 | 0 | 0 | 1 | 0 | 1 |
| SOL-011 | 0 | 1 | 19 | 0 | 20 |
| SOL-013 | 0 | 26 | 6 | 0 | 32 |

| SmartBugs category | PROVEN | DEPENDENCY_PROVEN | DETECTED_UNPROVEN | UNKNOWN |
|---|---:|---:|---:|---:|
| access_control | 0 | 0 | 9 | 0 |
| arithmetic | 76 | 0 | 134 | 38 |
| bad_randomness | 0 | 2 | 23 | 0 |
| denial_of_service | 0 | 26 | 6 | 0 |
| front_running | 0 | 0 | 1 | 0 |
| reentrancy | 0 | 0 | 83 | 0 |
| time_manipulation | 0 | 1 | 4 | 0 |
| unchecked_low_level_calls | 0 | 0 | 156 | 0 |

## Missed contracts (false negatives), by category

- **access_control** (14): `FibonacciBalance.sol`, `arbitrary_location_write_simple.sol`, `incorrect_constructor_name1.sol`, `incorrect_constructor_name2.sol`, `incorrect_constructor_name3.sol`, `mapping_write.sol`, `multiowned_vulnerable.sol`, `proxy.sol`, `rubixi.sol`, `simple_suicide.sol`, `unprotected0.sol`, `wallet_02_refund_nosub.sol`, `wallet_03_wrong_constructor.sol`, `wallet_04_confused_sign.sol`
- **bad_randomness** (3): `etheraffle.sol`, `lucky_doubler.sol`, `old_blockhash.sol`
- **denial_of_service** (4): `auction.sol`, `dos_address.sol`, `dos_simple.sol`, `list_dos.sol`
- **front_running** (4): `ERC20.sol`, `FindThisHash.sol`, `eth_tx_order_dependence_minimal.sol`, `odds_and_evens.sol`
- **other** (3): `crypto_roulette.sol`, `name_registrar.sol`, `open_address_lottery.sol`
- **reentrancy** (1): `spank_chain_payment.sol`
- **short_addresses** (1): `short_address_example.sol`
- **time_manipulation** (3): `governmental_survey.sol`, `lottopollo.sol`, `roulette.sol`
- **unchecked_low_level_calls** (4): `0x84d9ec85c9c568eb332b7226a8f826d897e0a4a8.sol`, `0xb0510d68f210b7db66e8c7c814f22680f2b8d1d6.sol`, `0xb7c5c5aa4d42967efe906e1b66cb8df9cebf04f7.sol`, `0xf29ebe930a539a60279ace72c707cba851a57707.sol`

Regenerate: `python benchmarks/run_benchmark.py` (see benchmarks/README.md).
