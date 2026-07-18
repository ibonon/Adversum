# Script de lancement complet - Adversum Auto-Audit
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    Lancement Complet Adversum" -ForegroundColor Cyan
Write-Host "    Auto-Audit du Projet" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = "f:\Adversum\adversum"
$apiPath = "$projectRoot\api"
$frontendPath = "$projectRoot\frontend"

# Fonction pour vérifier si un port est utilisé
function Test-Port {
    param([int]$Port)
    $connection = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    return $null -ne $connection
}

# Vérifier et arrêter les processus existants
Write-Host "Vérification des ports..." -ForegroundColor Yellow

if (Test-Port -Port 8080) {
    Write-Host "⚠️  Port 8080 utilisé, arrêt des processus..." -ForegroundColor Yellow
    Get-Process | Where-Object { $_.Path -like "*python*" -or $_.Path -like "*uvicorn*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Nettoyage Base de Données (Stabilité)
Write-Host "Nettoyage base de données..." -ForegroundColor Yellow
Remove-Item -Force "f:\Adversum\adversum\adversum.db", "f:\Adversum\adversum\api\adversum.db", "f:\Adversum\adversum\core\adversum.db" -ErrorAction SilentlyContinue

if (Test-Port -Port 3000) {
    Write-Host "⚠️  Port 3000 utilisé, arrêt des processus..." -ForegroundColor Yellow
    Get-Process | Where-Object { $_.Path -like "*node*" } | Where-Object { $_.CommandLine -like "*next*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Charger les variables d'environnement
$envFile = "$projectRoot\.env"
if (Test-Path $envFile) {
    Write-Host "✓ Chargement de .env" -ForegroundColor Green
    Get-Content $envFile | Foreach-Object {
        if ($_ -match '^([^#=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
        }
    }
}
else {
    Write-Host "⚠️  .env non trouvé, utilisation des valeurs par défaut" -ForegroundColor Yellow
    # Définir la clé API par défaut
    [Environment]::SetEnvironmentVariable("API_KEY", "adv-dev-key-123", "Process")
}

# Configurer PYTHONPATH
$env:PYTHONPATH = $projectRoot
Write-Host "✓ PYTHONPATH configuré" -ForegroundColor Green

# Démarrer l'API Backend
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "1. Démarrage de l'API Backend..." -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan

$apiJob = Start-Job -ScriptBlock {
    $projectRoot = $using:projectRoot
    $apiPath = $using:apiPath
    $env:PYTHONPATH = $projectRoot
    
    # Charger .env dans le job
    $envFile = "$projectRoot\.env"
    if (Test-Path $envFile) {
        Get-Content $envFile | Foreach-Object {
            if ($_ -match '^([^#=]+)=(.*)$') {
                [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
            }
        }
    }
    else {
        [Environment]::SetEnvironmentVariable("API_KEY", "adv-dev-key-123", "Process")
    }
    
    Set-Location $apiPath
    uvicorn main:app --reload --host 0.0.0.0 --port 8080 2>&1
}

Write-Host "   API démarrée en arrière-plan (Job ID: $($apiJob.Id))" -ForegroundColor Gray
Write-Host "   URL: http://localhost:8080" -ForegroundColor Gray
Write-Host "   Docs: http://localhost:8080/docs" -ForegroundColor Gray

# Attendre que l'API soit prête
Write-Host ""
Write-Host "   Attente du démarrage de l'API..." -ForegroundColor Yellow
$apiReady = $false
$maxAttempts = 30
$attempt = 0

while (-not $apiReady -and $attempt -lt $maxAttempts) {
    Start-Sleep -Seconds 1
    $attempt++
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8080/" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            $apiReady = $true
            Write-Host "   ✓ API prête!" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "   ." -NoNewline -ForegroundColor Gray
    }
}

if (-not $apiReady) {
    Write-Host ""
    Write-Host "   ⚠️  L'API n'a pas démarré dans les temps" -ForegroundColor Yellow
    Write-Host "   Vérifiez les logs avec: Receive-Job -Id $($apiJob.Id)" -ForegroundColor Gray
}

# Démarrer le Frontend
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "2. Démarrage du Frontend..." -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan

$frontendJob = Start-Job -ScriptBlock {
    $frontendPath = $using:frontendPath
    Set-Location $frontendPath
    npm run dev 2>&1
}

Write-Host "   Frontend démarré en arrière-plan (Job ID: $($frontendJob.Id))" -ForegroundColor Gray
Write-Host "   URL: http://localhost:3000" -ForegroundColor Gray

# Attendre que le frontend soit prêt
Write-Host ""
Write-Host "   Attente du démarrage du frontend..." -ForegroundColor Yellow
Start-Sleep -Seconds 8

Write-Host "   ✓ Frontend démarré!" -ForegroundColor Green

# Soumettre l'auto-audit
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "3. Soumission de l'Auto-Audit..." -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan

Start-Sleep -Seconds 3

$headers = @{
    "X-API-Key"    = "adv-dev-key-123"
    "Content-Type" = "application/json"
}

$body = @{
    target_path  = $projectRoot
    project_name = "Adversum-Auto-Audit"
} | ConvertTo-Json

try {
    Write-Host "   Envoi de la requête d'audit..." -ForegroundColor Yellow
    $response = Invoke-WebRequest -Uri "http://localhost:8080/audit" -Method POST -Headers $headers -Body $body -UseBasicParsing -ErrorAction Stop
    
    if ($response.StatusCode -eq 200) {
        $job = $response.Content | ConvertFrom-Json
        Write-Host "   ✓ Audit démarré avec succès!" -ForegroundColor Green
        Write-Host "   Job ID: $($job.id)" -ForegroundColor Cyan
        Write-Host "   Statut: $($job.status)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "   Suivre l'audit sur:" -ForegroundColor Yellow
        Write-Host "   http://localhost:3000/audits/$($job.id)" -ForegroundColor Cyan
    }
}
catch {
    Write-Host "   ⚠️  Erreur lors de la soumission de l'audit" -ForegroundColor Yellow
    Write-Host "   Erreur: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   Vous pouvez soumettre l'audit manuellement depuis le dashboard" -ForegroundColor Gray
}

# Afficher les informations finales
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    ✅ Lancement Terminé!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📊 Dashboard:" -ForegroundColor Yellow
Write-Host "   http://localhost:3000" -ForegroundColor Cyan
Write-Host ""
Write-Host "🔧 API:" -ForegroundColor Yellow
Write-Host "   http://localhost:8000" -ForegroundColor Cyan
Write-Host "   http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host ""
Write-Host "📝 Commandes Utiles:" -ForegroundColor Yellow
Write-Host "   Voir les logs API:     Receive-Job -Id $($apiJob.Id)" -ForegroundColor Gray
Write-Host "   Voir les logs Frontend: Receive-Job -Id $($frontendJob.Id)" -ForegroundColor Gray
Write-Host "   Arrêter l'API:        Stop-Job -Id $($apiJob.Id); Remove-Job -Id $($apiJob.Id)" -ForegroundColor Gray
Write-Host "   Arrêter le Frontend:  Stop-Job -Id $($frontendJob.Id); Remove-Job -Id $($frontendJob.Id)" -ForegroundColor Gray
Write-Host ""
Write-Host "⚠️  Pour arrêter tous les services, fermez cette fenêtre ou appuyez sur Ctrl+C" -ForegroundColor Yellow
Write-Host ""

# Garder le script actif pour voir les logs
Write-Host "Appuyez sur 'Q' puis Entrée pour quitter (les services continueront en arrière-plan)" -ForegroundColor Gray
$input = Read-Host

if ($input -eq "Q" -or $input -eq "q") {
    Write-Host "Arrêt des jobs..." -ForegroundColor Yellow
    Stop-Job -Id $apiJob.Id, $frontendJob.Id -ErrorAction SilentlyContinue
    Remove-Job -Id $apiJob.Id, $frontendJob.Id -ErrorAction SilentlyContinue
    Write-Host "✓ Jobs arrêtés" -ForegroundColor Green
}
