# Script simplifié pour démarrer les services
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    Démarrage Adversum" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = "f:\Adversum\adversum"

# Configurer l'environnement
$env:PYTHONPATH = $projectRoot
if (-not $env:API_KEY) {
    $env:API_KEY = "adv-dev-key-123"
}

Write-Host "1. Démarrage de l'API..." -ForegroundColor Yellow
Write-Host "   Ouvrez un nouveau terminal et exécutez:" -ForegroundColor Gray
Write-Host "   cd f:\Adversum\adversum\api" -ForegroundColor White
Write-Host "   uvicorn main:app --reload --host 0.0.0.0 --port 8000" -ForegroundColor White
Write-Host ""

Write-Host "2. Démarrage du Frontend..." -ForegroundColor Yellow
Write-Host "   Ouvrez un autre terminal et exécutez:" -ForegroundColor Gray
Write-Host "   cd f:\Adversum\adversum\frontend" -ForegroundColor White
Write-Host "   npm run dev" -ForegroundColor White
Write-Host ""

Write-Host "3. Une fois les deux services démarrés, soumettez l'audit:" -ForegroundColor Yellow
Write-Host "   cd f:\Adversum\adversum" -ForegroundColor White
Write-Host "   .\submit-audit.ps1" -ForegroundColor White
Write-Host ""

Write-Host "Ou ouvrez le dashboard: http://localhost:3000" -ForegroundColor Cyan
Write-Host ""
