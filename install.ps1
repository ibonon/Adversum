# Script d'Installation Automatique Adversum
# Exécuter après avoir installé Node.js et VS Build Tools

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Installation Adversum - Automatique  " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Vérifier les prérequis
Write-Host "[1/4] Vérification des prérequis..." -ForegroundColor Yellow

# Vérifier Node.js
try {
    $nodeVersion = node --version 2>$null
    Write-Host "  ✓ Node.js détecté: $nodeVersion" -ForegroundColor Green
}
catch {
    Write-Host "  ✗ Node.js non trouvé!" -ForegroundColor Red
    Write-Host "    Installez Node.js depuis: https://nodejs.org/" -ForegroundColor Yellow
    exit 1
}

# Vérifier npm
try {
    $npmVersion = npm --version 2>$null
    Write-Host "  ✓ npm détecté: v$npmVersion" -ForegroundColor Green
}
catch {
    Write-Host "  ✗ npm non trouvé!" -ForegroundColor Red
    exit 1
}

# Vérifier Rust
try {
    $rustVersion = rustc --version 2>$null
    Write-Host "  ✓ Rust détecté: $rustVersion" -ForegroundColor Green
}
catch {
    Write-Host "  ✗ Rust non trouvé!" -ForegroundColor Red
    Write-Host "    Installez Rust depuis: https://rustup.rs/" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Se placer dans le répertoire du projet
$projectRoot = "f:/Adversum/adversum"
Set-Location $projectRoot

# Installation des dépendances frontend
Write-Host "[2/4] Installation des dépendances frontend..." -ForegroundColor Yellow
Set-Location "$projectRoot/frontend"
npm install
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Dépendances frontend installées" -ForegroundColor Green
}
else {
    Write-Host "  ✗ Erreur lors de l'installation des dépendances frontend" -ForegroundColor Red
    Set-Location $projectRoot
    exit 1
}

Write-Host ""

# Build du frontend pour vérification
Write-Host "[3/4] Vérification du build frontend..." -ForegroundColor Yellow
npm run build
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Build frontend réussi" -ForegroundColor Green
}
else {
    Write-Host "  ⚠ Avertissement: Build frontend a échoué" -ForegroundColor Yellow
    Write-Host "    Vous pouvez continuer, mais vérifiez les erreurs ci-dessus" -ForegroundColor Yellow
}

Write-Host ""

# Compilation du core Rust
Write-Host "[4/4] Compilation du core Rust..." -ForegroundColor Yellow
Set-Location "$projectRoot/core"
Write-Host "  Nettoyage des artifacts précédents..." -ForegroundColor Gray
cargo clean | Out-Null
Write-Host "  Compilation en mode release (cela peut prendre 5-10 min)..." -ForegroundColor Gray
cargo build --release
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Core Rust compilé avec succès" -ForegroundColor Green
    
    # Vérifier que le fichier .pyd existe
    $pydFile = Get-ChildItem -Path "target/release" -Filter "adversum_core.pyd" -ErrorAction SilentlyContinue
    if ($pydFile) {
        Write-Host "  ✓ Bibliothèque Python générée: $($pydFile.Name)" -ForegroundColor Green
    }
}
else {
    Write-Host "  ✗ Erreur lors de la compilation Rust" -ForegroundColor Red
    Write-Host "    Vérifiez que Visual Studio Build Tools est installé avec C++" -ForegroundColor Yellow
    Set-Location $projectRoot
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ✓ Installation Terminée!              " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Prochaines étapes:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1. Démarrer l'API (Terminal 1):" -ForegroundColor Yellow
Write-Host "     cd f:/Adversum/adversum/api" -ForegroundColor White
Write-Host "     uvicorn main:app --reload --host 0.0.0.0 --port 8000" -ForegroundColor White
Write-Host ""
Write-Host "  2. Démarrer le Frontend (Terminal 2):" -ForegroundColor Yellow
Write-Host "     cd f:/Adversum/adversum/frontend" -ForegroundColor White
Write-Host "     npm run dev" -ForegroundColor White
Write-Host ""
Write-Host "  3. Accéder à l'application:" -ForegroundColor Yellow
Write-Host "     Dashboard: http://localhost:3000" -ForegroundColor White
Write-Host "     API: http://localhost:8000" -ForegroundColor White
Write-Host "     API Docs: http://localhost:8000/docs" -ForegroundColor White
Write-Host ""

# Retour à la racine
Set-Location $projectRoot
