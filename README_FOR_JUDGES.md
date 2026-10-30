# 🛡️ Adversum — Judges & Evaluation Benchmark Package
**Nebius x NVIDIA Global AI Hackathon (2026)**

---

## 📌 Executive Overview

**Adversum** is an autonomous security auditing engine that pairs high-throughput native static analysis with deep cognitive reasoning and First-Order Logic formal verification:

1. **Rust AST Core:** 12,500+ lines/second extraction with thread-local Tree-sitter cursor pooling and Rayon parallelism.
2. **NVIDIA Nemotron AI (deployed on Nebius Cloud):** Formulates formal exploit hypotheses and state invariants from AST slices with zero hallucinations.
3. **Z3 BitVec 256 SMT Solver:** Formally proves or refutes hypotheses. 
   - **`UNSAT`**: Guaranteed safe — **eliminating false positives**.
   - **`SAT`**: Confirmed exploitable — generates a concrete mathematical counter-example.

---

## 📊 Benchmark Highlights (from `BENCHMARK.md`)

| Metric | Adversum (Rust + Nemotron + Z3) | Slither | Semgrep | Snyk Code |
| :--- | :---: | :---: | :---: | :---: |
| **Scan Throughput** | **12,500+ lines/sec** | ~1,200 lines/sec | ~4,500 lines/sec | ~800 lines/sec |
| **False Positive Rate** | **< 2.8%** | 38.4% | 42.1% | 29.5% |
| **Precision** | **97.9%** | 61.1% | 58.2% | 68.7% |
| **Attack Graph Synthesis** | ✅ **G-ASR Kill Chain** | ❌ None | ❌ None | ❌ None |
| **Auto-Remediation Verification** | ✅ **AVR Formal Certification** | ❌ None | ⚠️ Static patch | ⚠️ Static patch |

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
