# Script de vérification de l'API Adversum
Write-Host "=== Vérification de l'API Adversum ===" -ForegroundColor Cyan

# Vérifier si l'API répond
Write-Host "`n1. Test de connexion à l'API..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/" -Method GET -ErrorAction Stop
    Write-Host "   ✓ API accessible sur http://localhost:8000" -ForegroundColor Green
    Write-Host "   Réponse: $($response.Content)" -ForegroundColor Gray
} catch {
    Write-Host "   ✗ API non accessible sur http://localhost:8000" -ForegroundColor Red
    Write-Host "   Erreur: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`n   → Solution: Démarrer l'API avec:" -ForegroundColor Yellow
    Write-Host "     cd adversum\api" -ForegroundColor White
    Write-Host "     uvicorn main:app --reload --host 0.0.0.0 --port 8000" -ForegroundColor White
    exit 1
}

# Vérifier l'authentification
Write-Host "`n2. Test d'authentification avec clé API..." -ForegroundColor Yellow
. "$PSScriptRoot\scripts\lib\api-key.ps1"
$apiKey = Get-AdversumApiKey
if (-not $apiKey) {
    Write-Host "   ✗ API_KEY introuvable (ni variable d'environnement, ni .env)" -ForegroundColor Red
    exit 1
}
$headers = @{
    "X-API-Key" = $apiKey
}
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/audits" -Method GET -Headers $headers -ErrorAction Stop
    Write-Host "   ✓ Authentification réussie" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Erreur d'authentification" -ForegroundColor Red
    Write-Host "   Code: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
    Write-Host "   Message: $($_.Exception.Message)" -ForegroundColor Red
}

# Vérifier la soumission d'audit
Write-Host "`n3. Test de soumission d'audit..." -ForegroundColor Yellow
$body = @{
    target_path = "F:\Adversum\adversum"
} | ConvertTo-Json
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/audit" -Method POST -Headers $headers -Body $body -ContentType "application/json" -ErrorAction Stop
    Write-Host "   ✓ Soumission d'audit réussie" -ForegroundColor Green
    $job = $response.Content | ConvertFrom-Json
    Write-Host "   Job ID: $($job.id)" -ForegroundColor Gray
} catch {
    Write-Host "   ✗ Erreur lors de la soumission" -ForegroundColor Red
    Write-Host "   Code: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
    Write-Host "   Message: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== Vérification terminée ===" -ForegroundColor Cyan
