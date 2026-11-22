# Adversum

**AI-Powered Security Reasoning Engine & Autonomous SOC**

Adversum est un moteur d'analyse de securite neuro-symbolique pour smart contracts et code multi-langage. Il combine l'analyse statique deterministe (SAST), le raisonnement d'un modele de langage (NVIDIA Nemotron), un ancrage syntaxique precis dans l'AST et la verification formelle mathematique via le solveur SMT Z3.

> [!IMPORTANT]
> **Portee et limitations verifiables (transparence technique)**  
> Adversum ne pretend pas remplacer un audit humain complet ni garantir l'absence totale de vulnerabilites. Pour comprendre precisement ce que le solveur Z3 prouve (representabilite mathematique d'un debordement avec contre-exemple concret) et ce qu'il ne prouve pas (reachability a l'echelle du contrat complet, faux negatifs hors regex), consultez imperativement [KNOWN_LIMITATIONS.md](./KNOWN_LIMITATIONS.md).  
> Les metriques d'evaluation historiques sont detaillees dans [BENCHMARK.md](./BENCHMARK.md). La suite de tests automatisee du depot compte **263 tests unitaires et d'integration** (`pytest`), tous verts.

---

## Fonctionnalites

### Phase 1 - Verification Neuro-Symbolique et Preuves Z3
- **Analyse Statique Multi-Langage**: Analyse AST/CFG deterministe via Tree-sitter et Ascent Datalog (Rust core).
- **Pipeline Neuro-Symbolique (Nemotron -> Ancrage -> Z3)**:
  1. *Detection*: Reperage des motifs suspects par les regles statiques ou proposition LLM (NVIDIA Nemotron).
  2. *Ancrage syntaxique*: Resolution exacte de la ligne, du snippet et du contexte de garde dans l'AST.
  3. *Preuve formelle Z3*: Resolution SMT (BitVec 256-bit pour SOL-004 overflow/underflow, et validation de l'ordonnancement des appels pour SOL-001 reentrance). Un verdict **SAT** fournit un contre-exemple concret verifiable.
- **Live Fork Exploit Execution (PoE)**: Validation empirique d'exploits sur fork Ethereum ephemeral via Anvil (Foundry).
- **Self-Healing Tri-Partite (Auto-PR)**: Comite d'agents (Attaquant vs Defenseur vs Juge) generant des correctifs verifies.
- **Threat Intelligence Temps Reel**: Correlation d'advisories et de CVEs en direct via l'API Tavily.
- **PoC d'Exploit Foundry**: Generation automatique de suites de tests `.t.sol` executables.

### Phase 2 - AI-ASOC (Autonomous Security Operations Center)
- **WebSocket Threat Stream**: Bus d'evenements temps reel avec fan-out pub/sub pour tous les events de securite.
- **MEV & Flash Loan Intelligence**: Detection multi-chain sur 7 reseaux (Ethereum, Arbitrum, Base, Optimism, Polygon, BSC, Avalanche) de sandwich attacks, flash loans, manipulations d'oracles et rug pulls.
- **Modelisation Autonome des Menaces**: Generation structuree STRIDE, PASTA (7 etapes) et matrices MITRE ATT&CK adaptees au Web3.
- **Compliance SOC2 / ISO27001 / SARIF**: Exportation automatique de rapports de conformite exploitables par GitHub Code Scanning et SIEM.

### Phase 3 - Cross-Protocol Attack Simulator & Interactive War Room
- **Scenarios d'Exploits Reels**: Reconstitution et simulation de vecteurs d'attaque historiques (Euler Finance, Ronin Bridge, Wormhole, Mango Markets).
- **Composite Risk Scorer**: Calcul deterministe du score de risque combinant exposition financiere, complexite et impact systemique.
- **War Room Interactive (`/war-room`)**: Visualisation DAG des etapes d'attaque via React Flow (`@xyflow/react`), timeline chronologique et matrice de risque.

### Phase 4 - Autonomous Incident Response & Resilience Arena (AI-AIRA)
- **Synthetiseur de Coupe-Circuit**: Generation automatique de contrats Solidity de circuit breaker multi-niveaux (Soft Pause, Hard Freeze, Rate Limit).
- **Evaluateur d'Invariants DeFi**: Verification de 10 regles fondamentales de resilience (conservation des reserves, solvabilite, ancrage des prix).
- **Resilience Arena**: Simulateur de confrontation Attaquant vs Defenseur mesurant le taux d'attenuation des pertes et le surcout en gas.

### Phase 5 - Institutional Production Stack & Threat Hunting Watchtower
- **Daemon de Surveillance Active**: Scan continu des nouveaux blocs EVM et detection d'opcodes sensibles (`delegatecall`, `selfdestruct`, `tx.origin`, `CREATE2`).
- **Enterprise Health Probes**: Endpoints `/health/live` et `/health/ready` compatibles Kubernetes et reverse-proxies.
- **Deploiement Conteneurise**: Configuration Docker Compose incluant FastAPI, Redis pub/sub et instance locale Anvil.

---

## Architecture

```
adversum/
├── core/              # Moteur deterministe Rust (Rayon, Tree-sitter, Ascent Datalog)
├── orchestrator/      # Pipeline Python, ingestion de repos, services de verification Z3
├── modules/           # Modules specialises (Solidity, MEV, formal_verification, PoC Foundry)
├── api/               # API FastAPI avec authentification par cle et rate limiting
├── frontend/          # Application web React 18 + Vite + Tailwind CSS + Lucide
├── knowledge/         # Base de connaissances de vulnerabilites et regles CCSS
└── docs/              # Specifications d'architecture et guides
```

### Stack Technique

- **Core**: Rust (SAST haute performance, parsing AST via Tree-sitter)
- **Verification Formelle**: Python (`z3-solver`) - solveur SMT BitVec pour SOL-004 (arithmetique) et SOL-001 (reentrance)
- **AI Reasoning**: NVIDIA Nemotron (`nvidia/Nemotron-3_5-Lightning`) via Nebius Token Factory
- **Simulation EVM**: Anvil (Foundry stack) pour execution d'exploits sur fork
- **Threat Intel**: Tavily Search API (correlation CVE / NVD)
- **Backend API**: Python 3.11+, FastAPI, SQLModel (SQLite aiosqlite en WAL mode / PostgreSQL)
- **Frontend**: React 18, Vite, Tailwind CSS, Radix UI, Lucide React, React Flow (`@xyflow/react`)

---

## Prerequis

1. **Python 3.10+** (Python 3.11 ou 3.12 recommande)
2. **Node.js 20+** et npm
3. **Rust 1.75+** et Cargo
4. **Git** installe et accessible dans le PATH

---

## Installation

### 1. Cloner le Projet

```bash
git clone https://github.com/ibonon/Adversum.git
cd Adversum
```

### 2. Installer les Dependances Backend

```bash
# Installation des dependances Python
pip install -r requirements.txt
```

### 3. Compiler l'Extension Rust

Le core Rust utilise PyO3 pour s'interfacer avec Python. La compilation et l'installation s'effectuent via `maturin` :

```bash
pip install maturin
cd core
maturin develop --release
cd ..
```

### 4. Installer les Dependances Frontend

```bash
cd frontend
npm install
cd ..
```

---

## Demarrage

### 1. Demarrer le Serveur Backend

```bash
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

L'API est accessible sur `http://127.0.0.1:8000` (documentation Swagger sur `http://127.0.0.1:8000/docs`).

### 2. Demarrer le Frontend

```bash
cd frontend
npm run dev
```

L'application web est accessible sur `http://localhost:5173`.

---

## Configuration

Creer un fichier `.env` a la racine du projet :

```env
# Cle d'authentification API (valeur par defaut en dev: adv-dev-key-123)
API_KEY=adv-dev-key-123

# Cles optionnelles pour l'enrichissement IA et threat intel
NEBIUS_API_KEY=votre-cle-nebius
TAVILY_API_KEY=votre-cle-tavily

# Base de donnees locale (SQLite aiosqlite avec WAL active)
DATABASE_URL=sqlite+aiosqlite:///adversum_local.db
```

---

## Utilisation

### Interface Web (`http://localhost:5173`)

L'interface principale (`/`) offre un espace d'audit interactif epure :
1. Saisir le chemin d'un dossier local ou l'URL HTTPS d'un depot Git distant.
2. Cliquer sur **Launch Audit** pour demarrer le scan.
3. Suivre l'etat en temps reel via l'orbe holographique et le badge de progression. L'etat de scan persiste en session (`sessionStorage`), permettant de rafraichir la page sans perdre le suivi du job actif.
4. Consulter la carte des resultats a la fin du scan : decompte par severite, preuves formelles **Z3 SAT** avec ancrage de ligne, et resume d'audit consolide.
5. Les vues analytiques et operations sont accessibles a la demande : `/soc` (dashboard SOC), `/war-room` (simulateur d'attaques), `/analytics` (metriques).

### Via API REST (cURL)

```bash
# 1. Soumettre un audit
curl -X POST http://127.0.0.1:8000/audit \
  -H "X-API-Key: adv-dev-key-123" \
  -H "Content-Type: application/json" \
  -d '{
    "target_path": "modules/solidity/tests/test_contracts",
    "project_name": "solidity-test"
  }'

# Reponse: {"id": 131, "status": "PENDING", ...}

# 2. Consulter l'etat et les resultats detailles
curl http://127.0.0.1:8000/audit/131 \
  -H "X-API-Key: adv-dev-key-123"
```

---

## Tests et Verification

Pour verifier l'integrite du systeme sur votre machine :

### Backend (Suite complete de 263 tests)

```bash
# Executer l'ensemble des 263 tests unitaires et d'integration
pytest

# Executer uniquement les tests de l'API REST
pytest api/

# Verifier l'extension native Rust
pytest tests/test_rust_core_hardened.py
```

### Frontend

```bash
cd frontend
# Verification stricte du typage TypeScript (0 erreur)
npx --no-install tsc --noEmit

# Analyse statique du code React
npm run lint
```

---

## Documentation et References

- **Limitations formelles et portee Z3**: [KNOWN_LIMITATIONS.md](./KNOWN_LIMITATIONS.md)
- **Bancs d'essai comparatifs et precision historique**: [BENCHMARK.md](./BENCHMARK.md)
- **Documentation API interactive**: `http://127.0.0.1:8000/docs` (Swagger UI) et `/redoc`

---

## Contribution

1. Fork le depot
2. Creer une branche fonctionnelle (`git checkout -b feature/ma-fonctionnalite`)
3. Valider que `pytest` et `npx tsc --noEmit` passent sans aucune regression
4. Committer les modifications (`git commit -m "feat: description factuelle"`)
5. Pousser vers la branche (`git push origin feature/ma-fonctionnalite`)
6. Ouvrir une Pull Request

---

## Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](./LICENSE) pour plus de details.
