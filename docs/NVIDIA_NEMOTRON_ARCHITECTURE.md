# 🧠 NVIDIA Nemotron & Nebius Token Factory Architecture

Technical specification of Adversum's AI reasoning layer powered by **NVIDIA Nemotron** on **Nebius Token Factory**.

---

## 🏗️ 1. Overview & Hackathon Rationale

Traditional SAST scanners (Semgrep, Slither, SonarQube) suffer from two fundamental bottlenecks:
1. **High False Positive Rates (30–45%)**: Static rules lack semantic comprehension of business logic and surrounding invariants.
2. **Alert Fatigue / Disconnected Findings**: Vulnerabilities are reported as isolated line numbers, blind to how an attacker can chain multiple minor flaws into a catastrophic exploit.

Adversum solves this by coupling a **high-throughput Rust static analysis core** with **NVIDIA Nemotron** running on **Nebius Token Factory** infrastructure.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ADVERSUM HYBRID PIPELINE                        │
│                                                                        │
│   Source Code ──► Rust SAST Core (Rayon + Tree-sitter + Datalog)       │
│                           │                                            │
│                           ▼ Raw Candidates (AST / CFG / Sinks)         │
│               ┌───────────────────────────────────────────┐            │
│               │ Context Builder (G-ASR Extract)           │            │
│               └─────────────────────┬─────────────────────┘            │
│                                     │                                  │
│                                     ▼                                  │
│               ┌───────────────────────────────────────────┐            │
│               │ Nebius Token Factory                      │            │
│               │ Model: nvidia/Nemotron-3_5-Lightning      │            │
│               │ Endpoint: api.tokenfactory.nebius.com/v1/ │            │
│               └─────────────────────┬─────────────────────┘            │
│                                     │                                  │
│       ┌─────────────────────────────┼─────────────────────────────┐    │
│       ▼                             ▼                             ▼    │
│ [1. Finding Validation]   [2. Attack Graph Synthesis]   [3. Verified AVR]│
│ True/False positive       Multi-stage kill chain        Code patch +   │
│ + Confidence score        correlation                   Rust re-scan   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ 2. Why NVIDIA Nemotron-3.5-Lightning on Nebius?

- **Extreme Inference Speed**: Sub-second latency per reasoning pass, making real-time CI/CD scans feasible.
- **Architectural Reasoning**: Nemotron excels at following formal constraints, understanding control flow graph (CFG) representations, and emitting structured JSON with zero hallucinated keys.
- **Nebius Open Cloud Infrastructure**: Token Factory provides OpenAI-compatible REST endpoints (`/v1/chat/completions`), enabling zero-overhead integration through high-performance asynchronous HTTP clients.

---

## 🔍 3. Core AI Modules Powered by Nemotron

### A. Graph-Augmented Security Reasoning (G-ASR)
- **Module**: `orchestrator/reasoning/ai_validator.py`
- **Mechanism**:
  - The Rust core extracts the data flow path (`source -> sanitizers -> sink`) and local symbol table.
  - The context builder injects the surrounding code and CFG trace into Nemotron.
  - Nemotron evaluates whether the flow is realistically exploitable or mitigated by external invariants.

### B. Multi-Stage Attack Graph / Kill Chain Synthesis
- **Module**: `orchestrator/services/nebius_llm.py` (`generate_attack_graph_hypothesis`)
- **Mechanism**:
  - Takes top findings across multiple files and layers (e.g., smart contracts + API custody + cloud IaC).
  - Prompts Nemotron to act as an offensive threat modeling architect.
  - Synthesizes a connected directed graph (`steps` and `edges`) showing how an attacker progresses from initial access to full financial drain.

### C. Autonomous Verified Remediation (AVR)
- **Module**: `orchestrator/services/avr.py`
- **Mechanism**:
  - Nemotron drafts a surgical unified diff patch.
  - The patch is applied in-memory.
  - Adversum's deterministic Rust scanner re-evaluates the patched file.
  - If the vulnerability is verified resolved with zero regressions, the patch is marked `CONFIRMED_FIXED`.

### D. CISO Executive Reporting
- **Module**: `orchestrator/services/nebius_llm.py` (`generate_executive_summary`)
- **Mechanism**:
  - Nemotron produces a 3-paragraph executive risk summary directly addressed to board members and CISOs, prioritizing financial and operational risk over raw line numbers.
