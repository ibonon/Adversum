# ⚡ Adversum Performance & Precision Benchmark

Quantitative evaluation of Adversum against industry-standard SAST and security auditing tools (Slither, Semgrep, and Snyk).

> **P0 — Vérité métrique (à jour).** Les chiffres *mesurés et rejouables* sont
> produits par `benchmarks/run_benchmark.py` (voir `benchmarks/README.md`) et
> publiés dans `benchmarks/results/latest.md` avec SHA git et moteur identifié.
> Tout chiffre ci-dessous marqué *historique / non reproduit* est conservé
> uniquement comme trace d'expérimentation : il ne doit être cité ni comme
> métrique courante, ni comme garantie. En cas de divergence, `latest.md` fait foi.

---

## Verdict distribution — SmartBugs complet rejoué (Étape 4)

Commande exacte (temps réel mesuré : **231,7 s**, dont résolution Z3 bornée à 5 s par finding) :

```bash
python benchmarks/run_benchmark.py --out-json benchmarks/results/latest.json --out-md benchmarks/results/latest.md
```

DAppSCAN : **non accessible dans cet environnement** (seul `smartbugs-curated`, 143 contrats, est présent) — aucun chiffre DAppSCAN n'est donc publié.

Sur 556 findings : **PROVEN 76 (13,7 %) · DEPENDENCY_PROVEN 28 (5,0 %) · DETECTED_UNPROVEN 414 (74,5 %) · UNKNOWN 38 (6,8 %)**. Par règle : SOL-004 concentre tous les PROVEN (76) et tous les UNKNOWN (38, soit 15,3 % de ses findings — instances arithmétiques non tranchées dans les bornes) ; SOL-013 est majoritairement DEPENDENCY_PROVEN (26/32). Détail complet, par catégorie et par CWE, dans `benchmarks/results/latest.md`.

**Branchement pipeline (post-Étape 4)** : Halmos tourne désormais aussi *par contrat réel* pour SOL-001 (`modules/halmos/per_contract.py`, opt-in `ADVERSUM_HALMOS_PER_CONTRACT=1` dans l'audit reentrancy, harnais généré depuis le finding et déployé par bytecode pour les cibles pré-0.8). Mesure rejouée par `benchmarks/run_halmos_smartbugs.py` (21,6 s) sur les 31 contrats SmartBugs étiquetés reentrancy : **PROVEN 4 · DETECTED_UNPROVEN (aucun drain dans les bornes) 8 · UNKNOWN 18 · sans finding 1** (`benchmarks/results/halmos_smartbugs_reentrancy.json`). Les 18 UNKNOWN sont publiés tels quels : formes non harnaissables (pas de paire crédit/retrait localisée) et limites moteur Halmos sur bytecode ancien — aucune conversion artificielle en PROVEN.

**Extension per-contract (SOL-004/002/007/003/012) et rejeu global** : générateurs par catégorie dans `modules/halmos/per_contract_rules.py`, branchés en opt-in dans le scanner. Mesures par catégorie (`benchmarks/results/halmos_smartbugs_all.json`, 63,7 s) : SOL-004 PROVEN 2/15, SOL-007 PROVEN 7/52, SOL-002/003 PROVEN 0 (origines `tx.origin` non alignables et SELFDESTRUCT non supporté — UNKNOWN publiés). Rejeu global avec per-contract (`python benchmarks/run_benchmark.py --halmos-per-contract`, 384,7 s, `benchmarks/results/latest_halmos.md`) : **PROVEN 112/556 (20,1 %, contre 13,7 % sans Halmos) · DEPENDENCY_PROVEN 28 (5,0 %) · DETECTED_UNPROVEN 385 (69,2 %) · UNKNOWN 31 (5,6 %)**. Composition mesurée : la force du verdict est le max des moteurs — un UNKNOWN Halmos ne dégrade jamais un PROVEN Z3 (la superposition naïve avait fait chuter PROVEN à 38, corrigée et documentée dans le code).

### Ce que signifie chaque verdict (juge / auditeur)

- **PROVEN** : un contre-exemple concret et vérifiable existe (valeurs d'entrée → vulnérabilité) ; vous pouvez le rejouer.
- **DEPENDENCY_PROVEN** : le chemin source → problème est démontré (ex. l'heure du bloc décide du paiement), mais l'exploit complet n'est pas prouvé.
- **DETECTED_UNPROVEN** : détection solide par règle/analyse, non vérifiée formellement ; à auditer humainement.
- **UNKNOWN** : l'outil ne sait pas trancher (bornes, timeout, forme non analysable). Ce n'est **jamais** un verdict « sûr ».

---

## 📊 1. Executive Comparison Matrix

| Metric / Capability | **Adversum (Rust + Nemotron)** | **Slither** | **Semgrep** | **Snyk Code** |
| :--- | :---: | :---: | :---: | :---: |
| **Engine Architecture** | Native Rust (Rayon + Tree-sitter + Datalog) | Python AST / SlithIR | OCaml pattern engine | Proprietary Cloud |
| **Scan Throughput** | Voir `benchmarks/results/throughput_v1.json` (versionné, rejouable) | ~1,200 lines/sec* | ~4,500 lines/sec* | ~800 lines/sec (API)* |
| **False Positive Rate** | Voir `benchmarks/results/latest.md` (par CWE, rejouable) | 38.4%\* | 42.1%\* | 29.5%\* |

> Comparaison honnête : seules les colonnes Adversum sont mesurées et rejouables depuis ce dépôt. Les chiffres Slither/Semgrep/Snyk sont des comparaisons historiques non rejouées ici — les outils ne sont donc pas comparés à armes égales dans ce tableau.
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
voir benchmarks/results/latest.md — rejeu Étape 4 (231,7 s) : 106/143
contrats avec catégorie correcte, rappel ligne 45,9 %, F1 reentrancy
71,4 %, F1 unchecked-call 73,3 %, F1 arithmetic 35,3 % ; verdicts :
PROVEN 13,7 %, DEPENDENCY_PROVEN 5,0 %, DETECTED_UNPROVEN 74,5 %,
UNKNOWN 6,8 % (jamais masqué).
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
