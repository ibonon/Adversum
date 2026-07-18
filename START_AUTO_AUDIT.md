# 🚀 Lancement Complet - Auto-Audit Adversum

## ✅ Script Automatique (Recommandé)

Exécutez simplement :

```powershell
cd f:\Adversum\adversum
.\launch-full.ps1
```

Ce script va :
1. ✅ Démarrer l'API backend (port 8000)
2. ✅ Démarrer le frontend (port 3000)
3. ✅ Soumettre automatiquement un audit du projet Adversum
4. ✅ Afficher les liens pour suivre l'audit

---

## 📋 Démarrage Manuel (Alternative)

### Terminal 1 - API Backend

```powershell
cd f:\Adversum\adversum
$env:PYTHONPATH = "f:\Adversum\adversum"
cd api
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Vérification:** Ouvrir http://localhost:8000 dans le navigateur

### Terminal 2 - Frontend

```powershell
cd f:\Adversum\adversum\frontend
npm run dev
```

**Vérification:** Ouvrir http://localhost:3000 dans le navigateur

### Terminal 3 - Soumettre l'Audit

Attendre que l'API et le frontend soient prêts (10-15 secondes), puis :

```powershell
$headers = @{
    "X-API-Key" = "adv-dev-key-123"
    "Content-Type" = "application/json"
}

$body = @{
    target_path = "f:\Adversum\adversum"
    project_name = "Adversum-Auto-Audit"
} | ConvertTo-Json

$response = Invoke-WebRequest -Uri "http://localhost:8000/audit" -Method POST -Headers $headers -Body $body -UseBasicParsing
$job = $response.Content | ConvertFrom-Json

Write-Host "Audit démarré! Job ID: $($job.id)" -ForegroundColor Green
Write-Host "Suivre sur: http://localhost:3000/audits/$($job.id)" -ForegroundColor Cyan
```

---

## 🌐 Accès aux Services

Une fois tout démarré :

- **Dashboard:** http://localhost:3000
- **API:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs
- **Audit:** http://localhost:3000/audits/[JOB_ID]

---

## 🔍 Vérification

### Vérifier que l'API fonctionne

```powershell
Invoke-WebRequest -Uri "http://localhost:8000/" -UseBasicParsing
```

**Résultat attendu:** `{"message":"Adversum Security Engine is Online"}`

### Vérifier que le frontend fonctionne

Ouvrir http://localhost:3000 dans le navigateur

### Vérifier l'audit

```powershell
$headers = @{"X-API-Key" = "adv-dev-key-123"}
Invoke-WebRequest -Uri "http://localhost:8000/audits" -Headers $headers -UseBasicParsing
```

---

## 🛑 Arrêter les Services

### Si vous avez utilisé le script

Les services tournent en arrière-plan. Pour les arrêter :

```powershell
# Voir les jobs actifs
Get-Job

# Arrêter tous les jobs
Get-Job | Stop-Job
Get-Job | Remove-Job
```

### Si vous avez démarré manuellement

Dans chaque terminal, appuyez sur **Ctrl+C**

---

## 📊 Suivre l'Audit

1. **Via le Dashboard:**
   - Aller sur http://localhost:3000
   - Cliquer sur "Audits" dans le menu
   - Voir la liste des audits
   - Cliquer sur l'audit pour voir les détails

2. **Via l'API:**
   ```powershell
   $headers = @{"X-API-Key" = "adv-dev-key-123"}
   Invoke-WebRequest -Uri "http://localhost:8000/audit/[JOB_ID]" -Headers $headers -UseBasicParsing
   ```

---

## ⚠️ Dépannage

### L'API ne démarre pas

1. Vérifier que Python est installé: `python --version`
2. Vérifier que uvicorn est installé: `pip install uvicorn`
3. Vérifier que le port 8000 est libre: `netstat -ano | findstr :8000`

### Le frontend ne démarre pas

1. Vérifier que Node.js est installé: `node --version`
2. Vérifier que les dépendances sont installées: `cd frontend && npm install`
3. Vérifier que le port 3000 est libre: `netstat -ano | findstr :3000`

### L'audit ne se soumet pas

1. Vérifier que l'API répond: `Invoke-WebRequest -Uri "http://localhost:8000/" -UseBasicParsing`
2. Vérifier la clé API (par défaut: `adv-dev-key-123`)
3. Vérifier les logs de l'API dans le terminal

---

## ✅ Checklist

- [ ] API démarrée sur http://localhost:8000
- [ ] Frontend démarré sur http://localhost:3000
- [ ] Audit soumis avec succès
- [ ] Dashboard accessible
- [ ] Résultats de l'audit visibles

---

*Bon audit ! 🔍*
