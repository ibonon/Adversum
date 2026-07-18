# Script de Démarrage Rapide Adversum

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    Démarrage Adversum - API + Frontend " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = "f:/Adversum/adversum"

Write-Host "Démarrage de l'API Backend..." -ForegroundColor Yellow
Write-Host "  Port: 8000" -ForegroundColor Gray
Write-Host "  URL: http://localhost:8000" -ForegroundColor Gray
Write-Host "  Docs: http://localhost:8000/docs" -ForegroundColor Gray
Write-Host ""

# Démarrer l'API en arrière-plan
# Démarrer l'API en arrière-plan
$apiJob = Start-Job -ScriptBlock {
    $projectRoot = "f:/Adversum/adversum"
    $envFile = "$projectRoot/.env"

    if (Test-Path $envFile) {
        Get-Content $envFile | Foreach-Object {
            if ($_ -match '^([^#=]+)=(.*)$') {
                [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
            }
        }
        Write-Host "Compte rendu: Configuration chargée depuis .env"
    }
    else {
        Write-Warning "Fichier .env introuvable."
        Write-Warning "Vous devez creer un fichier .env base sur .env.example ou definir les variables d'environnement."
        # NO DEFAULT KEY SET - Secure by default
    }

    # Ensure PYTHONPATH includes the project root so 'api' and 'orchestrator' can be imported
    $env:PYTHONPATH = $projectRoot
    
    Set-Location "$projectRoot/api"
    uvicorn main:app --reload --host 0.0.0.0 --port 8000
}

Start-Sleep -Seconds 3

Write-Host "Démarrage du Frontend..." -ForegroundColor Yellow
Write-Host "  Port: 3000" -ForegroundColor Gray
Write-Host "  URL: http://localhost:3000" -ForegroundColor Gray
Write-Host ""

# Démarrer le frontend en arrière-plan
$frontendJob = Start-Job -ScriptBlock {
    Set-Location "f:/Adversum/adversum/frontend"
    npm run dev
}

Start-Sleep -Seconds 5

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Adversum Started!                     " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Services disponibles:" -ForegroundColor Cyan
Write-Host "  Dashboard:  http://localhost:3000" -ForegroundColor Green
Write-Host "  API:        http://localhost:8000" -ForegroundColor Green
Write-Host "  API Docs:   http://localhost:8000/docs" -ForegroundColor Green
Write-Host ""
Write-Host "Appuyez sur Ctrl+C pour arrêter les services..." -ForegroundColor Yellow
Write-Host ""

# Attendre que l'utilisateur arrête
try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
finally {
    Write-Host ""
    Write-Host "Arrêt des services..." -ForegroundColor Yellow
    Stop-Job $apiJob, $frontendJob
    Remove-Job $apiJob, $frontendJob
    Write-Host "Services stopped." -ForegroundColor Green
}
