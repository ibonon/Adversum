# Script de redémarrage (Application des correctifs IPv4)
$root = "f:\Adversum\adversum"
$env:PYTHONPATH = $root
$env:API_KEY = "adv-dev-key-123"

Write-Host "🛑 Arrêt des services..." -ForegroundColor Yellow
# Kill via ports to be sure
Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

Write-Host "🧹 Nettoyage de la base de données..." -ForegroundColor Yellow
Remove-Item -Force "f:\Adversum\adversum\adversum.db", "f:\Adversum\adversum\api\adversum.db" -ErrorAction SilentlyContinue


Write-Host "🚀 Redémarrage de l'API (127.0.0.1:8080)..." -ForegroundColor Cyan
# Start API on 127.0.0.1 explicitly to match frontend config
Start-Process -FilePath "python" -ArgumentList "-m uvicorn main:app --reload --host 127.0.0.1 --port 8080" -WorkingDirectory "$root\api" -WindowStyle Normal

Write-Host "🚀 Redémarrage du Frontend..." -ForegroundColor Cyan
Start-Process -FilePath "cmd" -ArgumentList "/c npm run dev" -WorkingDirectory "$root\frontend" -WindowStyle Normal

Write-Host "⏳ Attente initialisation (10s)..."
Start-Sleep -Seconds 10

Write-Host "✅ Terminé. Veuillez rafraîchir http://localhost:3000" -ForegroundColor Green
Write-Host "   (Utilisez maintenant http://127.0.0.1:3000 si localhost pose problème)" -ForegroundColor Gray
