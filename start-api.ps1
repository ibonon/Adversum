# Script de démarrage de l'API Adversum
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    Démarrage API Adversum" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = "f:\Adversum\adversum"
$apiPath = "$projectRoot\api"

# Vérifier si le port 8000 est déjà utilisé
$portInUse = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Host "⚠️  Le port 8000 est déjà utilisé!" -ForegroundColor Yellow
    Write-Host "   PID: $($portInUse.OwningProcess)" -ForegroundColor Gray
    Write-Host ""
    $response = Read-Host "Voulez-vous arrêter le processus existant? (O/N)"
    if ($response -eq "O" -or $response -eq "o") {
        Stop-Process -Id $portInUse.OwningProcess -Force
        Write-Host "✓ Processus arrêté" -ForegroundColor Green
        Start-Sleep -Seconds 2
    } else {
        Write-Host "❌ Démarrage annulé" -ForegroundColor Red
        exit 1
    }
}

# Vérifier si Python est disponible
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python détecté: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python n'est pas installé ou pas dans le PATH" -ForegroundColor Red
    exit 1
}

# Vérifier si uvicorn est installé
try {
    $uvicornCheck = python -c "import uvicorn" 2>&1
    Write-Host "✓ uvicorn disponible" -ForegroundColor Green
} catch {
    Write-Host "⚠️  uvicorn non trouvé. Installation..." -ForegroundColor Yellow
    pip install uvicorn
}

# Charger les variables d'environnement depuis .env si présent
$envFile = "$projectRoot\.env"
if (Test-Path $envFile) {
    Write-Host "✓ Chargement de la configuration depuis .env" -ForegroundColor Green
    Get-Content $envFile | Foreach-Object {
        if ($_ -match '^([^#=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
        }
    }
} else {
    Write-Host "⚠️  Fichier .env non trouvé. Utilisation des valeurs par défaut." -ForegroundColor Yellow
}

# Configurer PYTHONPATH
$env:PYTHONPATH = $projectRoot
Write-Host "✓ PYTHONPATH configuré: $env:PYTHONPATH" -ForegroundColor Green

# Changer vers le répertoire API
Set-Location $apiPath

Write-Host ""
Write-Host "Démarrage de l'API sur http://localhost:8000" -ForegroundColor Cyan
Write-Host "Documentation: http://localhost:8000/docs" -ForegroundColor Gray
Write-Host ""
Write-Host "Appuyez sur Ctrl+C pour arrêter" -ForegroundColor Yellow
Write-Host ""

# Démarrer uvicorn
uvicorn main:app --reload --host 0.0.0.0 --port 8000
