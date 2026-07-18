# Script de lancement simplifié (Secours)
$root = "f:\Adversum\adversum"
$env:PYTHONPATH = $root
# Force API Key for safety
$env:API_KEY = "adv-dev-key-123"

Write-Host "Killing old processes on 8080/3000..."
Get-Process | Where-Object { $_.Path -like "*uvicorn*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }

Write-Host "1. Starting API (Port 8080)..."
Start-Process -FilePath "python" -ArgumentList "-m uvicorn main:app --reload --host 0.0.0.0 --port 8080" -WorkingDirectory "$root\api" -WindowStyle Normal

Write-Host "2. Starting Frontend (Port 3000)..."
Start-Process -FilePath "cmd" -ArgumentList "/c npm run dev" -WorkingDirectory "$root\frontend" -WindowStyle Normal

Write-Host "   Waiting 15 seconds for services to warm up..."
Start-Sleep -Seconds 15

Write-Host "3. Submitting Auto-Audit..."
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8080/audit" -Method POST -Headers @{"X-API-Key" = "adv-dev-key-123" } -Body (@{target_path = $root; project_name = "Auto-Test" } | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
    $job = $response.Content | ConvertFrom-Json
    Write-Host "   SUCCESS! Audit Job ID: $($job.id)" -ForegroundColor Green
    Write-Host "   Check Dashboard: http://localhost:3000/audits/$($job.id)" -ForegroundColor Cyan
}
catch {
    Write-Host "   FAILED to submit audit: $_" -ForegroundColor Red
}

Write-Host "Done."
