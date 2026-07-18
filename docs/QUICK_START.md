# Installation Rapide - Adversum

## 🚀 Installation Express (Copier-Coller)

### Étape 1: Télécharger Node.js

**Lien direct:** https://nodejs.org/dist/v20.11.0/node-v20.11.0-x64.msi

ou visitez https://nodejs.org/ et cliquez sur "Download Node.js (LTS)"

**Après installation:**
- Redémarrez PowerShell
- Vérifiez: `node --version`

---

### Étape 2: Télécharger VS Build Tools

**Lien direct:** https://aka.ms/vs/17/release/vs_BuildTools.exe

**Installation:**
1. Lancer l'executable
2. Sélectionner "Desktop development with C++"
3. Cliquer Install (~6GB)

---

### Étape 3: Installer les Dépendances (Automatique)

Une fois Node.js installé, exécutez ce script PowerShell:

```powershell
# Se placer à la racine du projet
cd f:/Adversum/adversum

# Installer dépendances frontend
Write-Host "Installation des dépendances frontend..." -ForegroundColor Green
cd frontend
npm install
Write-Host "✓ Frontend dependencies installées" -ForegroundColor Green
cd ..

# Compiler le core Rust
Write-Host "Compilation du core Rust..." -ForegroundColor Yellow
cd core
cargo clean
cargo build --release
Write-Host "✓ Core Rust compilé" -ForegroundColor Green
cd ..

Write-Host "✓ Installation terminée!" -ForegroundColor Cyan
Write-Host "Vous pouvez maintenant démarrer l'application:" -ForegroundColor Cyan
Write-Host "  Terminal 1: cd api && uvicorn main:app --reload" -ForegroundColor White
Write-Host "  Terminal 2: cd frontend && npm run dev" -ForegroundColor White
```

---

## ⚡ Démarrage Rapide (Après Installation)

**Terminal 1 - API:**
```powershell
cd f:/Adversum/adversum/api
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 - Frontend:**
```powershell
cd f:/Adversum/adversum/frontend
npm run dev
```

**Accès:**
- API: http://localhost:8000
- Dashboard: http://localhost:3000
- API Docs: http://localhost:8000/docs

---

## 📦 Alternative: Installation Manuelle Étape par Étape

### 1. Node.js Installé ✓

```powershell
cd f:/Adversum/adversum/frontend
npm install
```

### 2. VS Build Tools Installé ✓

```powershell
cd f:/Adversum/adversum/core
cargo build --release
```

### 3. Vérification

```powershell
# Test frontend
cd f:/Adversum/adversum/frontend
npm run build

# Test Rust
cd f:/Adversum/adversum/core
cargo check

# Test API
cd f:/Adversum/adversum/api
python -c "import sys; print('Python OK')"
```

---

## ⏱️ Temps Estimé

- Téléchargement Node.js: 1-2 min
- Installation Node.js: 2-3 min
- Téléchargement VS Build Tools: 5-10 min
- Installation VS Build Tools: 15-25 min
- Installation dépendances + compilation: 10-15 min

**Total: ~35-60 minutes**

---

## 🆘 Problèmes Courants

### "node" n'est pas reconnu après installation
**Solution:** Redémarrer le terminal PowerShell

### Compilation Rust échoue
**Solution:** Vérifier que VS Build Tools est bien installé avec C++

### npm install échoue
**Solution:** Exécuter `npm cache clean --force` puis réessayer

---

## ✅ Checklist

- [ ] Node.js téléchargé et installé
- [ ] VS Build Tools téléchargé et installé  
- [ ] Terminal redémarré
- [ ] `node --version` fonctionne
- [ ] `npm install` dans frontend réussi
- [ ] `cargo build --release` dans core réussi
- [ ] API démarre sur port 8000
- [ ] Frontend démarre sur port 3000

---

**Une fois tous les ✓ cochés, votre installation est complète! 🎉**
