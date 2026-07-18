# 🚀 Instructions de Démarrage - Adversum

## ⚠️ Problème: "Cannot connect to API"

Si vous voyez cette erreur, l'API backend n'est pas démarrée ou n'est pas accessible.

---

## ✅ Solution Rapide

### Étape 1: Démarrer l'API Backend

**Ouvrez un terminal PowerShell** et exécutez :

```powershell
cd f:\Adversum\adversum
.\start-api-simple.ps1
```

**OU manuellement :**

```powershell
cd f:\Adversum\adversum
$env:PYTHONPATH = "f:\Adversum\adversum"
$env:API_KEY = "adv-dev-key-123"
cd api
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Vous devriez voir :**
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

### Étape 2: Vérifier que l'API fonctionne

**Dans un autre terminal**, testez :

```powershell
Invoke-WebRequest -Uri "http://localhost:8000/" -UseBasicParsing
```

**Résultat attendu :** `{"message":"Adversum Security Engine is Online"}`

### Étape 3: Démarrer le Frontend

**Ouvrez un autre terminal PowerShell** et exécutez :

```powershell
cd f:\Adversum\adversum\frontend
npm run dev
```

**Vous devriez voir :**
```
  ▲ Next.js 14.1.0
  - Local:        http://localhost:3000
```

### Étape 4: Utiliser le Dashboard

1. Ouvrez votre navigateur : **http://localhost:3000**
2. Cliquez sur **"Launch Audit"** ou **"Initiate Audit"**
3. Entrez le chemin : `f:\Adversum\adversum`
4. Cliquez sur **"Start Audit"**

---

## 🔍 Vérifications

### Vérifier que l'API répond

```powershell
Invoke-WebRequest -Uri "http://localhost:8000/" -UseBasicParsing
```

### Vérifier que le port 8000 est utilisé

```powershell
Get-NetTCPConnection -LocalPort 8000
```

### Vérifier les processus Python

```powershell
Get-Process python | Select-Object Id, ProcessName, Path
```

---

## 🐛 Dépannage

### Problème: Port 8000 déjà utilisé

**Solution :**
```powershell
# Trouver le processus
Get-NetTCPConnection -LocalPort 8000 | Select-Object OwningProcess

# Arrêter le processus (remplacer PID)
Stop-Process -Id <PID> -Force
```

### Problème: "Module not found"

**Solution :**
```powershell
# Vérifier PYTHONPATH
$env:PYTHONPATH = "f:\Adversum\adversum"

# Vérifier les dépendances
pip install -r requirements.txt
```

### Problème: uvicorn non trouvé

**Solution :**
```powershell
pip install uvicorn fastapi
```

### Problème: CORS Error dans le navigateur

**Vérifier dans `api/main.py` :**
- `allowed_origins` doit contenir `http://localhost:3000`

---

## 📋 Checklist

- [ ] API démarrée sur http://localhost:8000
- [ ] API répond : `Invoke-WebRequest -Uri "http://localhost:8000/" -UseBasicParsing`
- [ ] Frontend démarré sur http://localhost:3000
- [ ] Dashboard accessible dans le navigateur
- [ ] Pas d'erreurs dans la console du navigateur (F12)

---

## 🎯 Commandes Rapides

### Démarrer tout en une fois (3 terminaux)

**Terminal 1 - API:**
```powershell
cd f:\Adversum\adversum\api
$env:PYTHONPATH = "f:\Adversum\adversum"
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 - Frontend:**
```powershell
cd f:\Adversum\adversum\frontend
npm run dev
```

**Terminal 3 - Test:**
```powershell
# Attendre 10 secondes, puis:
Invoke-WebRequest -Uri "http://localhost:8000/" -UseBasicParsing
```

---

## 📞 Si ça ne fonctionne toujours pas

1. **Vérifiez les logs de l'API** dans le terminal où elle tourne
2. **Ouvrez la console du navigateur** (F12) et regardez les erreurs
3. **Vérifiez que les deux services tournent** :
   - API: http://localhost:8000
   - Frontend: http://localhost:3000

---

*Une fois l'API démarrée, le bouton "Launch Audit" devrait fonctionner !*
