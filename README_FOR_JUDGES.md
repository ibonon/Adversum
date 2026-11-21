# 🛡️ Adversum — Judges & Evaluation Benchmark Package
**Nebius x NVIDIA Global AI Hackathon (2026)**

---

## 📌 Executive Overview

**Adversum** is an autonomous security auditing engine that pairs high-throughput native static analysis with deep cognitive reasoning and First-Order Logic formal verification:

1. **Rust AST Core:** Thread-local Tree-sitter cursor pooling and Rayon parallelism. Throughput is versioned and replayable in `benchmarks/results/throughput_v1.json` (no unversioned figure is claimed).
2. **NVIDIA Nemotron AI (deployed on Nebius Cloud):** Formulates exploit hypotheses from graph context (G-ASR). Hypotheses are anchored to real source lines and checked by Z3; unanchorable hypotheses are rejected, never trusted (see `benchmarks/run_llm_eval.py`).
3. **Z3 BitVec SMT Solver:** Proves overflow *representability* (plus single-function reachability) or refutes it.
   - **`UNSAT`**: No overflow representable under the modelled guard — the finding is **removed** from the exploitable list (binding verdict).
   - **`SAT`**: Representable overflow — generates a concrete mathematical counter-example. Reachability scope is stated on every result.

---

## 📊 Benchmark Highlights (from `BENCHMARK.md`)

| Metric | Adversum (Rust + Nemotron + Z3) | Slither | Semgrep | Snyk Code |
| :--- | :---: | :---: | :---: | :---: |
| **Scan Throughput** | Versioned: `benchmarks/results/throughput_v1.json` | ~1,200 lines/sec* | ~4,500 lines/sec* | ~800 lines/sec* |
| **Detection (SmartBugs, replayable)** | 106/143 matched · reentrancy F1 71.4% · line recall 45.9% (`benchmarks/results/latest.md`) | — | — | — |
| **Verdicts (Step 4 replay, 556 findings)** | PROVEN 13.7% · DEPENDENCY_PROVEN 5.0% · DETECTED_UNPROVEN 74.5% · UNKNOWN 6.8% | — | — | — |
| **Historical precision (non-reproduced)** | 97.9% on a former 50-case corpus — do not cite as current | 61.1%* | 58.2%* | 68.7%* |
| **Attack Graph Synthesis** | ✅ **G-ASR Kill Chain** | ❌ None | ❌ None | ❌ None |
| **Auto-Remediation Verification** | ✅ **AVR (re-scan verified; Foundry proof only when executed)** | ❌ None | ⚠️ Static patch | ⚠️ Static patch |

<sub>* Historical comparison figures, not replayed in this repository.</sub>

---

## How to read a verdict (non-technical)

- **PROVEN** — a concrete, replayable counterexample exists (inputs → vulnerability). Check it yourself.
- **DEPENDENCY_PROVEN** — the path from cause to risky decision/payment is demonstrated, but a full exploit is not proven.
- **DETECTED_UNPROVEN** — a solid rule/analysis detection, not formally verified; needs human review.
- **UNKNOWN** — the tool cannot decide (bounds, timeout, un analysable form). It never means "safe". Step-4 replay: UNKNOWN is 6.8% overall and 15.3% of arithmetic findings — published, not averaged away.
- Comparison note: only the Adversum column above is replayed from this repository; competitor figures are historical and not re-run here, so this is not an equal-footing comparison.

DAppSCAN was not accessible in the evaluation environment; no DAppSCAN figure is published.

---

## 📁 Package Directory Contents

- **`BENCHMARKS/`**:
  - `BENCHMARK.md`: Full comparative benchmark against industry tools (Slither, Semgrep, Snyk).
  - `smartbugs_report.json` & `.md`: Evaluation report on real-world SmartBugs datasets.
  - `z3_scan_proof.html` & `.json`: Interactive formal verification proof report with exact SMT counter-examples.
- **`ARCHITECTURE_AND_DOCS/`**:
  - `NVIDIA_NEMOTRON_ARCHITECTURE.md`: Deep dive on Nemotron-4 340B & 70B prompt engineering and structured schema anchoring.
  - `DEPLOYMENT_NEBIUS.md`: Infrastructure topology and GPU setup on Nebius Cloud.
  - `ARCHITECTURE.md`: Complete end-to-end multi-stage pipeline specification.
- **`FORMAL_VERIFICATION_PROOFS/`**:
  - `06_z3_formal_proof_report.png`: High-resolution visual proof showing SAT vs UNSAT solver output on tested contracts.
  - `01_landing_hero.png`, `02_soc_dashboard.png`, `03_war_room.png`, `04_analytics.png`: Visual evidence of the live system.

---

## 🔗 Public Links & Verification
- **GitHub Repository**: https://github.com/ibonon/Adversum
- **Video Demo**: https://youtu.be/2YmOO1dX3Zo
