# 🚀 Démarrage Rapide - Adversum

## ✅ Vérification Rapide

L'API semble fonctionner ! Testez avec :

```powershell
Invoke-WebRequest -Uri "http://localhost:8000/" -UseBasicParsing
```

Si vous voyez `{"message":"Adversum Security Engine is Online"}`, l'API fonctionne.

---

## 🔧 Solution au Problème "Cannot connect to API"

### Option 1: Utiliser le Script de Démarrage (Recommandé)

```powershell
cd f:\Adversum\adversum
.\start-api.ps1
```

Ce script :
- ✅ Vérifie si le port 8000 est libre
- ✅ Charge la configuration .env
- ✅ Configure PYTHONPATH
- ✅ Démarre l'API correctement

### Option 2: Démarrage Manuel

**Terminal 1 - API Backend:**
```powershell
cd f:\Adversum\adversum
$env:PYTHONPATH = "f:\Adversum\adversum"
cd api
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 - Frontend:**
```powershell
cd f:\Adversum\adversum\frontend
npm run dev
```

---

## 🔍 Diagnostic

### 1. Vérifier que l'API répond

```powershell
Invoke-WebRequest -Uri "http://localhost:8000/" -UseBasicParsing
```

**Résultat attendu**: `{"message":"Adversum Security Engine is Online"}`

### 2. Vérifier le port 8000

```powershell
netstat -ano | findstr :8000
```

Si un processus écoute, l'API devrait être accessible.

### 3. Vérifier les logs de l'API

Quand vous démarrez l'API, vous devriez voir :
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

### 4. Vérifier la console du navigateur

Ouvrez la console du navigateur (F12) et regardez l'onglet "Network" :
- Les requêtes vers `http://localhost:8000` apparaissent-elles ?
- Y a-t-il des erreurs CORS ?

---

## 🐛 Problèmes Courants

### Problème: Port 8000 déjà utilisé

**Solution:**
```powershell
# Trouver le processus
netstat -ano | findstr :8000

# Arrêter le processus (remplacer PID par le numéro trouvé)
Stop-Process -Id <PID> -Force
```

### Problème: CORS Error

**Vérifier dans `api/main.py`:**
```python
allowed_origins_str = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")
```

**Solution:** S'assurer que `http://localhost:3000` est dans la liste.

### Problème: API Key incorrecte

**Vérifier:**
- Backend: `API_KEY` dans `.env` ou variable d'environnement
- Frontend: `NEXT_PUBLIC_API_KEY` dans `.env.local`

**Par défaut:** `adv-dev-key-123`

---

## ✅ Checklist de Démarrage

- [ ] API démarrée sur le port 8000
- [ ] API répond à `http://localhost:8000/`
- [ ] Frontend démarré sur le port 3000
- [ ] Pas d'erreurs dans la console du navigateur
- [ ] CORS configuré correctement
- [ ] API Key identique dans backend et frontend

---

## 📞 Test Complet

1. **Démarrer l'API:**
   ```powershell
   cd f:\Adversum\adversum\api
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Dans un autre terminal, tester:**
   ```powershell
   $headers = @{"X-API-Key" = "adv-dev-key-123"}
   Invoke-WebRequest -Uri "http://localhost:8000/audits" -Headers $headers -UseBasicParsing
   ```

3. **Démarrer le frontend:**
   ```powershell
   cd f:\Adversum\adversum\frontend
   npm run dev
   ```

4. **Ouvrir le navigateur:**
   - Aller sur `http://localhost:3000`
   - Ouvrir la console (F12)
   - Cliquer sur "Launch Audit"
   - Vérifier les erreurs dans la console

---

*Si le problème persiste, partagez les logs de l'API et les erreurs de la console du navigateur.*
