# 📋 Commandes Complètes - Adversum

## 🎯 Vue d'Ensemble

Ce guide contient **toutes les commandes** nécessaires pour démarrer et utiliser Adversum, avec des explications détaillées.

---

## 📦 PRÉREQUIS - Vérifications Initiales

### 1. Vérifier Python

```powershell
python --version
```

**Résultat attendu :** `Python 3.10.x` ou supérieur

**Si erreur :** Installer Python depuis https://www.python.org/

---

### 2. Vérifier Node.js

```powershell
node --version
```

**Résultat attendu :** `v20.x.x` ou supérieur

**Si erreur :** Installer Node.js depuis https://nodejs.org/

---

### 3. Vérifier les Dépendances Python

```powershell
cd f:\Adversum\adversum
pip install -r requirements.txt
```

**Temps d'exécution :** 2-5 minutes

**Ce que ça fait :** Installe FastAPI, uvicorn, SQLModel, etc.

---

### 4. Vérifier les Dépendances Frontend

```powershell
cd f:\Adversum\adversum\frontend
npm install
```

**Temps d'exécution :** 3-5 minutes

**Ce que ça fait :** Installe Next.js, React, et toutes les dépendances frontend

---

## 🚀 DÉMARRAGE - Commandes par Terminal

### TERMINAL 1 : API Backend (Port 8000)

**Commande complète :**

```powershell
# 1. Aller dans le répertoire du projet
cd f:\Adversum\adversum

# 2. Configurer PYTHONPATH (permet d'importer les modules)
$env:PYTHONPATH = "f:\Adversum\adversum"

# 3. Configurer la clé API (optionnel, valeur par défaut utilisée sinon)
$env:API_KEY = "adv-dev-key-123"

# 4. Aller dans le répertoire API
cd api

# 5. Démarrer l'API avec uvicorn
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Explication des paramètres :**
- `--reload` : Redémarre automatiquement l'API quand le code change
- `--host 0.0.0.0` : Écoute sur toutes les interfaces réseau
- `--port 8000` : Port sur lequel l'API sera accessible

**Résultat attendu :**
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

**⚠️ IMPORTANT :** Ne fermez PAS ce terminal ! L'API doit rester en cours d'exécution.

---

### TERMINAL 2 : Frontend Dashboard (Port 3000)

**Commande complète :**

```powershell
# 1. Aller dans le répertoire frontend
cd f:\Adversum\adversum\frontend

# 2. Démarrer le serveur de développement Next.js
npm run dev
```

**Résultat attendu :**
```
  ▲ Next.js 14.1.0
  - Local:        http://localhost:3000
  - ready started server on 0.0.0.0:3000
```

**⚠️ IMPORTANT :** Ne fermez PAS ce terminal ! Le frontend doit rester en cours d'exécution.

---

## ✅ VÉRIFICATIONS - Commandes de Test

### 1. Vérifier que l'API répond

```powershell
Invoke-WebRequest -Uri "http://localhost:8000/" -UseBasicParsing
```

**Résultat attendu :**
```
StatusCode        : 200
Content           : {"message":"Adversum Security Engine is Online"}
```

**Si erreur :** L'API n'est pas démarrée ou le port 8000 est bloqué.

---

### 2. Vérifier que le port 8000 est utilisé

```powershell
Get-NetTCPConnection -LocalPort 8000
```

**Résultat attendu :** Affiche une connexion en état `Listen`

**Si vide :** L'API n'est pas démarrée.

---

### 3. Vérifier que le port 3000 est utilisé

```powershell
Get-NetTCPConnection -LocalPort 3000
```

**Résultat attendu :** Affiche une connexion en état `Listen`

**Si vide :** Le frontend n'est pas démarré.

---

### 4. Tester l'authentification API

```powershell
$headers = @{
    "X-API-Key" = "adv-dev-key-123"
}
Invoke-WebRequest -Uri "http://localhost:8000/audits" -Headers $headers -UseBasicParsing
```

**Résultat attendu :** `StatusCode : 200` avec une liste d'audits (peut être vide)

**Si erreur 401/403 :** La clé API est incorrecte.

---

## 🔍 SOUMETTRE UN AUDIT - Commandes

### Option 1 : Via le Dashboard (Recommandé)

1. Ouvrir http://localhost:3000 dans le navigateur
2. Cliquer sur "Launch Audit" ou "Initiate Audit"
3. Entrer le chemin : `f:\Adversum\adversum`
4. Cliquer sur "Start Audit"

---

### Option 2 : Via l'API (cURL/PowerShell)

**Commande complète :**

```powershell
# 1. Préparer les headers avec la clé API
$headers = @{
    "X-API-Key" = "adv-dev-key-123"
    "Content-Type" = "application/json"
}

# 2. Préparer le corps de la requête
$body = @{
    target_path = "f:\Adversum\adversum"
    project_name = "Adversum-Auto-Audit"
} | ConvertTo-Json

# 3. Envoyer la requête POST
$response = Invoke-WebRequest -Uri "http://localhost:8000/audit" -Method POST -Headers $headers -Body $body -UseBasicParsing

# 4. Afficher le résultat
$job = $response.Content | ConvertFrom-Json
Write-Host "Job ID: $($job.id)" -ForegroundColor Green
Write-Host "Statut: $($job.status)" -ForegroundColor Cyan
```

**Résultat attendu :**
```
Job ID: 1
Statut: pending
```

---

### Option 3 : Utiliser le Script

```powershell
cd f:\Adversum\adversum
.\submit-audit.ps1
```

---

## 📊 CONSULTER LES RÉSULTATS - Commandes

### 1. Lister tous les audits

```powershell
$headers = @{
    "X-API-Key" = "adv-dev-key-123"
}
$response = Invoke-WebRequest -Uri "http://localhost:8000/audits" -Headers $headers -UseBasicParsing
$audits = $response.Content | ConvertFrom-Json
$audits | Format-Table id, status, created_at
```

---

### 2. Consulter un audit spécifique

```powershell
$headers = @{
    "X-API-Key" = "adv-dev-key-123"
}
$jobId = 1  # Remplacez par l'ID de votre audit
$response = Invoke-WebRequest -Uri "http://localhost:8000/audit/$jobId" -Headers $headers -UseBasicParsing
$audit = $response.Content | ConvertFrom-Json
$audit | ConvertTo-Json -Depth 10
```

---

### 3. Via le Dashboard

Ouvrir : http://localhost:3000/audits/[JOB_ID]

---

## 🛑 ARRÊTER LES SERVICES - Commandes

### Arrêter l'API

**Dans le Terminal 1 :** Appuyer sur `Ctrl+C`

**OU forcer l'arrêt :**

```powershell
# Trouver le processus
Get-NetTCPConnection -LocalPort 8000 | Select-Object OwningProcess

# Arrêter (remplacer PID par le numéro trouvé)
Stop-Process -Id <PID> -Force
```

---

### Arrêter le Frontend

**Dans le Terminal 2 :** Appuyer sur `Ctrl+C`

**OU forcer l'arrêt :**

```powershell
# Trouver le processus Node.js
Get-Process node | Where-Object { $_.Path -like "*next*" } | Stop-Process -Force
```

---

### Arrêter tous les services Python/Node

```powershell
# Arrêter tous les processus Python
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force

# Arrêter tous les processus Node
Get-Process node -ErrorAction SilentlyContinue | Stop-Process -Force
```

**⚠️ ATTENTION :** Cela arrêtera TOUS les processus Python/Node, pas seulement Adversum !

---

## 🔧 DÉPANNAGE - Commandes Utiles

### 1. Vérifier les processus en cours

```powershell
# Processus Python
Get-Process python | Select-Object Id, ProcessName, Path

# Processus Node.js
Get-Process node | Select-Object Id, ProcessName, Path
```

---

### 2. Vérifier les ports utilisés

```powershell
# Port 8000 (API)
Get-NetTCPConnection -LocalPort 8000

# Port 3000 (Frontend)
Get-NetTCPConnection -LocalPort 3000

# Tous les ports en écoute
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess
```

---

### 3. Vérifier les logs de l'API

Les logs s'affichent directement dans le Terminal 1 où l'API est démarrée.

**Pour voir les erreurs Python :**
```powershell
# Dans le terminal où l'API tourne, les erreurs s'affichent automatiquement
```

---

### 4. Vérifier les erreurs du Frontend

Les logs s'affichent directement dans le Terminal 2 où le frontend est démarré.

**Pour voir les erreurs dans le navigateur :**
1. Ouvrir http://localhost:3000
2. Appuyer sur `F12` pour ouvrir les outils développeur
3. Aller dans l'onglet "Console" pour voir les erreurs JavaScript

---

### 5. Réinstaller les dépendances

**Python :**
```powershell
cd f:\Adversum\adversum
pip install -r requirements.txt --force-reinstall
```

**Frontend :**
```powershell
cd f:\Adversum\adversum\frontend
Remove-Item -Recurse -Force node_modules
npm install
```

---

## 📝 SCRIPTS RAPIDES - Commandes

### Script 1 : Démarrer l'API

```powershell
cd f:\Adversum\adversum
.\start-api-simple.ps1
```

---

### Script 2 : Soumettre un audit

```powershell
cd f:\Adversum\adversum
.\submit-audit.ps1
```

---

### Script 3 : Vérifier l'API

```powershell
cd f:\Adversum\adversum
.\check-api.ps1
```

---

## 🌐 URLS IMPORTANTES

| Service | URL | Description |
|---------|-----|-------------|
| **Dashboard** | http://localhost:3000 | Interface utilisateur principale |
| **API** | http://localhost:8000 | API REST backend |
| **API Docs** | http://localhost:8000/docs | Documentation Swagger interactive |
| **API ReDoc** | http://localhost:8000/redoc | Documentation ReDoc alternative |

---

## 📋 CHECKLIST COMPLÈTE

### Avant de démarrer

- [ ] Python 3.10+ installé
- [ ] Node.js 20+ installé
- [ ] Dépendances Python installées (`pip install -r requirements.txt`)
- [ ] Dépendances Frontend installées (`npm install` dans `frontend/`)

### Démarrage

- [ ] Terminal 1 : API démarrée sur port 8000
- [ ] Terminal 2 : Frontend démarré sur port 3000
- [ ] API répond : `Invoke-WebRequest -Uri "http://localhost:8000/" -UseBasicParsing`
- [ ] Dashboard accessible : http://localhost:3000

### Utilisation

- [ ] Audit soumis avec succès
- [ ] Résultats visibles dans le dashboard
- [ ] Pas d'erreurs dans la console du navigateur (F12)

---

## 💡 ASTUCES

### 1. Garder les terminaux ouverts

Les services doivent rester en cours d'exécution. Utilisez des onglets séparés dans votre terminal.

### 2. Vérifier rapidement l'état

```powershell
# Test rapide de l'API
Invoke-WebRequest -Uri "http://localhost:8000/" -UseBasicParsing | Select-Object StatusCode
```

### 3. Voir les logs en temps réel

Les logs s'affichent directement dans les terminaux où les services tournent.

### 4. Redémarrer après modification du code

- **API :** Redémarre automatiquement grâce à `--reload`
- **Frontend :** Redémarre automatiquement (hot reload)

---

*Toutes ces commandes sont testées et fonctionnelles. Copiez-collez directement dans PowerShell !*
