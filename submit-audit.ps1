# Script pour soumettre l'auto-audit
Write-Host "Soumission de l'auto-audit Adversum..." -ForegroundColor Yellow

$headers = @{
    "X-API-Key" = "adv-dev-key-123"
    "Content-Type" = "application/json"
}

$body = @{
    target_path = "f:\Adversum\adversum"
    project_name = "Adversum-Auto-Audit"
} | ConvertTo-Json

try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/audit" -Method POST -Headers $headers -Body $body -UseBasicParsing
    $job = $response.Content | ConvertFrom-Json
    
    Write-Host ""
    Write-Host "AUDIT DEMARRE AVEC SUCCES!" -ForegroundColor Green
    Write-Host "Job ID: $($job.id)" -ForegroundColor Cyan
    Write-Host "Statut: $($job.status)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Suivre l'audit sur:" -ForegroundColor Yellow
    Write-Host "http://localhost:3000/audits/$($job.id)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Dashboard: http://localhost:3000" -ForegroundColor Cyan
    Write-Host "API: http://localhost:8000" -ForegroundColor Cyan
} catch {
    Write-Host ""
    Write-Host "Erreur: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Verifiez que l'API est demarree sur http://localhost:8000" -ForegroundColor Yellow
}
