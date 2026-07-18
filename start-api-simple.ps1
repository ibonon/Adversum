# Script simple pour démarrer l'API Adversum
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    Démarrage API Adversum" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = "f:\Adversum\adversum"
$apiPath = "$projectRoot\api"

# Arrêter les processus existants sur le port 8000
Write-Host "Vérification du port 8000..." -ForegroundColor Yellow
$existing = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Arrêt des processus existants..." -ForegroundColor Yellow
    $existing | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
}

# Configurer l'environnement
$env:PYTHONPATH = $projectRoot
if (-not $env:API_KEY) {
    $env:API_KEY = "adv-dev-key-123"
    Write-Host "✓ API_KEY configurée: adv-dev-key-123" -ForegroundColor Green
}

# Charger .env si présent
$envFile = "$projectRoot\.env"
if (Test-Path $envFile) {
    Write-Host "✓ Chargement de .env" -ForegroundColor Green
    Get-Content $envFile | Foreach-Object {
        if ($_ -match '^([^#=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
        }
    }
}

Write-Host ""
Write-Host "Démarrage de l'API..." -ForegroundColor Yellow
Write-Host "URL: http://localhost:8000" -ForegroundColor Gray
Write-Host "Docs: http://localhost:8000/docs" -ForegroundColor Gray
Write-Host ""
Write-Host "Appuyez sur Ctrl+C pour arrêter" -ForegroundColor Yellow
Write-Host ""

# Changer vers le répertoire API et démarrer
Set-Location $apiPath
uvicorn main:app --reload --host 0.0.0.0 --port 8000
