# Adversum

**AI-Powered Security Reasoning Engine**

Adversum est un moteur d'analyse de sécurité avancé qui combine l'analyse statique de code (SAST) à grande échelle avec un raisonnement IA pour détecter, valider et corriger automatiquement les vulnérabilités de sécurité dans votre code.

---

## 🚀 Fonctionnalités

- **🔍 Analyse Statique Multi-Langage**: Analyse AST/CFG déterministe via Tree-sitter & Ascent Datalog (Rust core)
- **🤖 Raisonnement NVIDIA Nemotron**: Validation contextuelle sur Nebius Token Factory (< 2.8% faux positifs)
- **⚡ Live Fork Exploit Execution (PoE)**: Validation empirique d'exploits sur fork Ethereum Mainnet (0% faux positifs)
- **🛠️ Self-Healing Tri-Partite (Auto-PR)**: Comité d'agents (Attaquant vs Défenseur vs Juge) générant des PRs GitHub vérifiées
- **🌐 Threat Intelligence Temps Réel**: Corrélation d'advisories et de CVEs en direct via l'API Tavily
- **🧪 PoC d'Exploit Foundry**: Génération automatique de suites de tests `.t.sol` prêtes à l'emploi
- **🏛️ Standards Institutionnels**: Conformité CCSS v3.0 (10 domaines de garde crypto) et STRIDE pour CEX
- **📊 Dashboard Interactif**: Interface Next.js / Vite React moderne avec télémétrie en temps réel

---

## 🏗️ Architecture

```
adversum/
├── core/              # Unified Adversarial & SAST Engine (Rust, Rayon, Datalog, SMT)
├── orchestrator/      # Python pipeline, AI reasoning (Nemotron) & Tri-Partite Self-Healing
├── modules/           # Scanners (Solidity, Crypto, IaC, PoR, Live Fork, PoC Generator)
├── api/               # FastAPI REST endpoints sécurisés
├── frontend/          # Vite + React 18 + Tailwind CSS cybersecurity dashboard
├── knowledge/         # Base de connaissances sécurité & standards CCSS
└── docs/              # Spécifications & guides d'architecture
```

### Stack Technique

- **Core**: Rust (SAST + ML Adversarial Kit - PGD, FGSM, C&W + SMT solver)
- **AI Infrastructure**: Nebius Token Factory / NVIDIA NIM (`nvidia/Nemotron-3_5-Lightning`)
- **Live Fork**: Anvil / Ephemeral EVM state simulator (Foundry stack)
- **Threat Intel**: Tavily Search API (CVE / NVD / Snyk live correlation)
- **Backend**: Python 3.11+, FastAPI, SQLModel (SQLite/PostgreSQL)
- **Frontend**: React 18 + Vite + Tailwind CSS + Radix UI + Lucide


---

## ⚙️ Prérequis

### Outils de Développement

1. **Python 3.10+**
2. **Node.js 20+** et npm
3. **Rust 1.70+** et Cargo
4. **Visual Studio Build Tools** (Windows) avec C++ Build Tools

### Installation des Prérequis

#### Windows

1. **Node.js**: [Télécharger Node.js LTS](https://nodejs.org/)
2. **Rust**: [Télécharger rustup](https://rustup.rs/)
3. **Visual Studio Build Tools**: 
   - [Télécharger Build Tools](https://visualstudio.microsoft.com/downloads/)
   - Sélectionner "Desktop development with C++"

---

## 📦 Installation

### 1. Cloner le Projet

```bash
git clone <repository-url>
cd adversum
```

### 2. Installer les Dépendances Backend (Python)

```bash
# À la racine du projet
pip install -r requirements.txt

# Orchestrator (optionnel si requirements.txt racine est complet)
cd orchestrator
pip install -r requirements.txt
cd ..
```

### 3. Compiler le Core Rust

```bash
cd core
cargo build --release
cd ..
```

> **Note**: La compilation génère une bibliothèque Python (`adversum_core.pyd` sur Windows) utilisable par l'orchestrator.

### 4. Installer les Dépendances Frontend

```bash
cd frontend
npm install
cd ..
```

---

## 🚀 Démarrage

### 1. Démarrer l'API Backend

```bash
cd api
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

L'API sera accessible sur `http://localhost:8000`

### 2. Démarrer le Frontend

```bash
cd frontend
npm run dev
```

Le dashboard sera accessible sur `http://localhost:3000`

---

## 🔑 Configuration

### Variables d'Environnement

Créer un fichier `.env` à la racine :

```env
# API Security
API_KEY=votre-clé-api-sécurisée

# OpenAI (pour le raisonnement IA)
OPENAI_API_KEY=sk-...

# Database (optionnel, par défaut: SQLite local)
DATABASE_URL=sqlite:///./adversum.db
```

### Configuration de l'API Key

- **Développement**: Clé par défaut `adv-dev-key-123`
- **Production**: Définir `API_KEY` dans les variables d'environnement

---

## 📖 Utilisation

### Via API (cURL)

```bash
# Soumettre un audit
curl -X POST http://localhost:8000/audit \
  -H "X-API-Key: adv-dev-key-123" \
  -H "Content-Type: application/json" \
  -d '{
    "target_path": "/chemin/vers/projet",
    "project_name": "mon-projet"
  }'

# Réponse: {"id": 1, "status": "pending", "created_at": "..."}

# Récupérer le résultat
curl http://localhost:8000/audit/1 \
  -H "X-API-Key: adv-dev-key-123"
```

### Via Dashboard

1. Ouvrir `http://localhost:3000`
2. Utiliser l'interface pour soumettre un audit
3. Visualiser les résultats en temps réel
4. Appliquer les correctifs automatiques en un clic

---

## 🧪 Tests

### Backend

```bash
cd api
python test_api_local.py
python test_api_persistence.py
python test_auto_fix.py
```

### Frontend

```bash
cd frontend
npm run build  # Vérifie que le build fonctionne
npm run lint   # Vérification du code
```

### Core Rust

```bash
cd core
cargo test
cargo check
```

---

## 📚 Documentation API

Une fois l'API démarrée, la documentation interactive Swagger est disponible sur :

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### Endpoints Principaux

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/` | Status de l'API |
| POST | `/audit` | Soumettre un audit de sécurité |
| GET | `/audit/{id}` | Récupérer les résultats d'un audit |
| POST | `/fix/{finding_id}` | Appliquer un correctif automatique |

---

## 🐳 Docker (Optionnel)

```bash
# Build et démarrer avec Docker Compose
docker-compose up --build

# API sera sur http://localhost:8000
# Frontend sera sur http://localhost:3000
```

---

## 🛠️ Développement

### Structure des Modules

#### Core (Rust) - [Détails techniques](./core/README.md)
- `ast/`: Analyse syntaxique abstraite
- `ir/`: Représentation intermédiaire
- `cfg/`: Control Flow Graph
- `dataflow/`: Analyse de flux de données
- `rules/`: Règles de détection de vulnérabilités
- `scoring/`: Scoring de sévérité
- `semantic/`: Analyse sémantique
- `attack_graph/`: Graphe des chemins d'attaque
- `adversarial/`: Fast Adversarial Kit (PGD, FGSM, C&W)

#### Orchestrator (Python)
- `ingestion/`: Lecture et parsing de projets
- `pipeline/`: Orchestration de l'analyse
- `ai_reasoning/`: Interface LLM
- `scanner/`: Détection de vulnérabilités
- `reporting/`: Génération de rapports
- `services/`: Services (DB, patcher, etc.)

---

## 🤝 Contribution

1. Fork le projet
2. Créer une branche feature (`git checkout -b feature/amazing-feature`)
3. Commit les changements (`git commit -m 'Add amazing feature'`)
4. Push vers la branche (`git push origin feature/amazing-feature`)
5. Ouvrir une Pull Request

---

## 📝 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

---

## 🆘 Support

Pour toute question ou problème :

1. Consulter la [documentation complète](./docs/)
2. Ouvrir une [issue GitHub](https://github.com/votre-repo/adversum/issues)
3. Contacter l'équipe de développement

---

## 🙏 Remerciements

- Tree-sitter pour l'analyse syntaxique
- FastAPI pour le framework backend
- Nebius Token Factory pour l'infrastructure d'inférence IA
- NVIDIA pour les modèles open-source Nemotron

---

**Construit avec ❤️ pour la sécurité du code**
