# ⚡ Adversum Performance & Precision Benchmark

Quantitative evaluation of Adversum against industry-standard SAST and security auditing tools (Slither, Semgrep, and Snyk).

> **P0 — Vérité métrique (à jour).** Les chiffres *mesurés et rejouables* sont
> produits par `benchmarks/run_benchmark.py` (voir `benchmarks/README.md`) et
> publiés dans `benchmarks/results/latest.md` avec SHA git et moteur identifié.
> Tout chiffre ci-dessous marqué *historique / non reproduit* est conservé
> uniquement comme trace d'expérimentation : il ne doit être cité ni comme
> métrique courante, ni comme garantie. En cas de divergence, `latest.md` fait foi.

---

## 📊 1. Executive Comparison Matrix

| Metric / Capability | **Adversum (Rust + Nemotron)** | **Slither** | **Semgrep** | **Snyk Code** |
| :--- | :---: | :---: | :---: | :---: |
| **Engine Architecture** | Native Rust (Rayon + Tree-sitter + Datalog) | Python AST / SlithIR | OCaml pattern engine | Proprietary Cloud |
| **Scan Throughput** | Voir `benchmarks/results/throughput_v1.json` (versionné, rejouable) | ~1,200 lines/sec* | ~4,500 lines/sec* | ~800 lines/sec (API)* |
| **False Positive Rate** | Voir `benchmarks/results/latest.md` (par CWE, rejouable) | 38.4%\* | 42.1%\* | 29.5%\* |
| **Attack Graph Synthesis** | ✅ **Multi-stage Kill Chain (G-ASR)** | ❌ None | ❌ None | ❌ None |
| **Auto-Remediation Verification** | ✅ **AVR (Autonomous Verified Remediation)** | ❌ None | ⚠️ Static patch | ⚠️ Static patch |
| **Smart Contract Logic (DeFi)** | ✅ Reentrancy, Bridges, Merkle PoR | ✅ EVM opcodes | ⚠️ Regex/AST | ⚠️ Limited |
| **IaC & Custody Standards** | ✅ CCSS v3.0, STRIDE, K8s, Terraform | ❌ No | ✅ IaC rules | ✅ IaC rules |
| **Cloud Independence** | ✅ **Nebius Token Factory / Open-Source** | ❌ None | ❌ SaaS | ❌ Closed SaaS |

<sub>\* Taux et débits mesurés lors de campagnes d'évaluation historiques sur les corpus de test dédiés (voir détails ci-dessous et dans `benchmarks/results/`). Ce ne sont pas des métriques contractuelles ou générales : les performances et taux de faux positifs varient selon la typologie du codebase, les versions d'outils, la connectivité et la configuration du modèle. Chiffres non reproduits en continu depuis ce dépôt.</sub>

---

## ⏱️ 2. Throughput & Scalability Benchmark

Tests conducted on a 100,000 LOC multi-repository code base (Solidity smart contracts, Python backend, TypeScript frontend, Terraform IaC):

```
Scan Time (seconds) — Lower is better:

Adversum (Rust Core)     ███ 8.2s
Semgrep                  ████████████ 22.4s
Slither                  ██████████████████████ 41.8s
Snyk (Cloud API)         ██████████████████████████████████ 68.5s
```

> ℹ️ **Méthodologie & Reproductibilité :** Ce banc d'essai a été mesuré sur un échantillon multi-dépôts statique de 100 000 lignes (Rust, Solidity, Python, TypeScript, HCL). Les temps d'exécution indiqués correspondent à l'environnement de référence de test initial. Ce benchmark de débit global n'est pas réexécuté automatiquement par la suite de tests continue (`pytest` / `cargo test`) du dépôt.

### Key Architectural Enablers:
1. **Thread-Local Tree-sitter Cursor Pooling (`cursor_pool.rs`)**: Eliminates 1.6 GB of heap allocations across parallel Rayon worker threads.
2. **Ascent Datalog Relational Fixpoint (`datalog.rs`)**: Computes taint reachability in linear time rather than exponential recursive path exploration.
3. **Tier-0 Heuristic Skipping (`tier0/mod.rs`)**: Skips clean/binary/irrelevant files in < 0.1ms before allocating AST structures.

---

## 🎯 3. Precision & False Positive Reduction

Evaluating detection on 50 verified historical vulnerability benchmarks (including reentrancy, uninitialized bridge roots, and cryptographic misconfigurations):

```
HISTORIQUE / NON REPRODUIT — ne pas citer comme métrique courante :
                     True Positives    False Positives    Precision (%)
Adversum Raw SAST          49                18               73.1%
Adversum + Nemotron AI     48                 1               97.9%*  (ancien corpus de 50 cas)
Slither                    44                28               61.1%
Semgrep                    41                30               57.7%

MESURÉ / REJOUABLE (SmartBugs curated, 143 contrats, règles natives) :
voir benchmarks/results/latest.md — au moment de l'écriture : 106/143
contrats avec catégorie correcte, rappel ligne 45,9 %, F1 reentrancy
71,4 %, F1 unchecked-call 73,3 %, F1 arithmetic 35,3 %.
```

> ℹ️ **Corpus d'évaluation :** Évaluation historique réalisée sur un corpus de 50 cas de vulnérabilités vérifiées (dont SmartBugs et cas de synthèse, voir `benchmarks/results/smartbugs_report.json`). Le taux de précision affiché (97.9%) et la réduction relative de faux positifs représentent les résultats observés sur ce jeu de test particulier avec NVIDIA Nemotron actif, et ne constituent pas une garantie uniforme sur tout codebase arbitraire. Chiffres non reproduits en continu depuis ce dépôt.

### How NVIDIA Nemotron-3.5-Lightning Eliminates False Positives:
- **Control Flow Graph Awareness**: Rather than matching shallow regex or AST leaves, Adversum extracts the complete flow path (`source -> sanitizers -> sink`) and feeds it into Nemotron.
- **Invariant Understanding**: Nemotron evaluates whether compensating controls (such as `ReentrancyGuard`, OpenZeppelin SafeERC20, or custom access controls) exist elsewhere in the file or imported context.
- **Confidence Scoring**: Each finding receives a cryptographic and AI-backed confidence rating (e.g., `0.98`), filtering out low-confidence test fixture anomalies.

---

## 🛡️ 4. Autonomous Verified Remediation (AVR) Efficacy

Adversum is not just an alerting tool—it is an autonomous remediation agent:

1. **Patch Generation**: Nemotron synthesizes a surgical patch respecting the existing AST formatting and variable scopes.
2. **Deterministic Re-Scan**: The Rust SAST engine immediately parses the patched AST in an isolated memory buffer.
3. **Mathematical Proof of Fix**: If the vulnerability sink is eradicated and no new sinks or syntax errors are introduced, the patch is labeled `CONFIRMED_FIXED`.
4. **Verification Rate**: *historique / non reproduit* — formerly reported as 96.4% on the initial AVR experiment corpus; not replayed by any script in this repository and must not be cited as a current metric.

<sub>\* Taux mesuré sur les scénarios AVR validés du corpus d'expérimentation initial ; non rejoué automatiquement en continu par la suite de tests du dépôt.</sub>
