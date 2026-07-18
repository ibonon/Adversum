# Guide d'Installation Adversum

Ce guide vous accompagne pas à pas pour installer et configurer Adversum sur votre machine.

---

## ✅ Vérification des Prérequis

### 1. Python

```bash
python --version
# Requis: Python 3.10 ou supérieur
```

✅ **Vous avez**: Python 3.10.8 installé

### 2. Node.js et npm

```bash
node --version
npm --version
# Requis: Node.js 20+ et npm 10+
```

❌ **Action requise**: Installer Node.js

**Comment installer:**
1. Télécharger Node.js LTS depuis: https://nodejs.org/
2. Exécuter l'installateur
3. Redémarrer votre terminal
4. Vérifier avec `node --version`

### 3. Rust et Cargo

```bash
rustc --version
cargo --version
# Requis: Rust 1.70+
```

✅ **Vous avez**: Rust 1.92.0 installé

### 4. Visual Studio Build Tools (Windows uniquement)

❌ **Action requise**: Installer Visual Studio Build Tools

**Erreur actuelle:**
```
error: linker `link.exe` not found
note: the msvc targets depend on the msvc linker
```

**Comment installer:**
1. Télécharger Build Tools: https://visualstudio.microsoft.com/downloads/
2. Lancer l'installateur
3. Sélectionner **"Desktop development with C++"**
4. Cliquer sur "Install" (environ 6 GB)
5. Redémarrer votre terminal après installation

---

## 📦 Installation des Dépendances

### Étape 1: Dépendances Python (Backend)

```bash
# À la racine du projet
cd f:/Adversum/adversum
pip install -r requirements.txt
```

**Dépendances incluses:**
- FastAPI
- Uvicorn
- Pydantic
- SQLModel
- OpenAI
- NetworkX
- Pandas
- Requests

### Étape 2: Compilation du Core Rust

**⚠️ Prérequis**: Visual Studio Build Tools doit être installé d'abord

```bash
cd f:/Adversum/adversum/core
cargo build --release
```

**Temps de compilation:** 5-10 minutes à la première fois

**Fichier généré:** `target/release/adversum_core.pyd` (ou `.so` sur Linux)

### Étape 3: Dépendances Frontend

**⚠️ Prérequis**: Node.js et npm doivent être installés d'abord

```bash
cd f:/Adversum/adversum/frontend
npm install
```

**Temps d'installation:** 2-5 minutes

**Vérifier le build:**
```bash
npm run build
```

---

## 🔧 Configuration

### 1. Créer le fichier de configuration

Créer `.env` à la racine du projet:

```bash
# f:/Adversum/adversum/.env
API_KEY=adv-dev-key-123
OPENAI_API_KEY=sk-votre-clé-openai
DATABASE_URL=sqlite:///./adversum.db
```

### 2. Initialiser la base de données

La base de données SQLite sera créée automatiquement au premier démarrage de l'API.

---

## 🚀 Premier Démarrage

### Terminal 1: API Backend

```bash
cd f:/Adversum/adversum/api
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Vérification:** Ouvrir http://localhost:8000
Vous devriez voir: `{"message": "Adversum Security Engine is Online"}`

### Terminal 2: Frontend Dashboard

```bash
cd f:/Adversum/adversum/frontend
npm run dev
```

**Vérification:** Ouvrir http://localhost:3000
Vous devriez voir le dashboard Adversum

---

## 🧪 Test de l'Installation

### Test 1: API Health Check

```bash
curl http://localhost:8000
```

**Résultat attendu:** `{"message": "Adversum Security Engine is Online"}`

### Test 2: Soumettre un Audit de Test

```bash
curl -X POST http://localhost:8000/audit \
  -H "X-API-Key: adv-dev-key-123" \
  -H "Content-Type: application/json" \
  -d '{
    "target_path": "f:/Adversum/adversum/temp_test_project",
    "project_name": "test"
  }'
```

### Test 3: Vérifier le Résultat

```bash
curl http://localhost:8000/audit/1 \
  -H "X-API-Key: adv-dev-key-123"
```

---

## ❓ Résolution de Problèmes

### Problème: `npm` non reconnu

**Solution:**
```bash
# Vérifier l'installation de Node.js
node --version

# Si Node.js est installé mais npm non reconnu:
# Redémarrer le terminal ou ajouter Node.js au PATH
```

### Problème: Compilation Rust échoue (linker `link.exe` not found)

**Solution:**
1. Installer Visual Studio Build Tools avec C++ toolkit
2. Redémarrer le terminal
3. Réessayer `cargo build --release`

### Problème: Module Python `adversum_core` introuvable

**Cause:** Le core Rust n'est pas compilé ou mal placé

**Solution:**
```bash
cd f:/Adversum/adversum/core
cargo build --release
# Vérifier que target/release/adversum_core.pyd existe
```

### Problème: API retourne 401 Unauthorized

**Cause:** Clé API manquante ou incorrecte

**Solution:**
Ajouter le header `X-API-Key: adv-dev-key-123` à toutes les requêtes

### Problème: Frontend ne se connecte pas à l'API

**Cause:** CORS ou URL API incorrecte

**Solution:**
Vérifier que l'API est bien démarrée sur `http://localhost:8000`

---

## ✅ Checklist d'Installation

- [ ] Python 3.10+ installé et vérifié
- [ ] Node.js 20+ installé et vérifié
- [ ] Rust 1.70+ installé et vérifié
- [ ] Visual Studio Build Tools installé (Windows)
- [ ] Dépendances Python installées (`pip install -r requirements.txt`)
- [ ] Core Rust compilé (`cargo build --release`)
- [ ] Dépendances frontend installées (`npm install`)
- [ ] Fichier `.env` créé
- [ ] API démarre sans erreur sur port 8000
- [ ] Frontend démarre sans erreur sur port 3000
- [ ] Test d'audit réussi

---

## 🎉 Installation Terminée !

Une fois tous les éléments cochés, votre installation Adversum est complète et prête à l'emploi.

**Prochaines étapes:**
1. Lire la [documentation API](../README.md#-documentation-api)
2. Explorer le dashboard frontend
3. Lancer votre premier audit de sécurité

---

**Besoin d'aide?** Consultez le README principal ou ouvrez une issue.
