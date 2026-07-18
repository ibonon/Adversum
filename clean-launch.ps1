# Force Clean Launch
$root = "f:\Adversum\adversum"
$dbFile = "$root\adversum.db"
$apiDbFile = "$root\api\adversum.db" # Just in case

Write-Host "🛑 Killing all Python/Node processes..." -ForegroundColor Red
Stop-Process -Name "python", "node" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Host "🧹 Deleting Database Files..." -ForegroundColor Yellow
if (Test-Path $dbFile) { Remove-Item -Force $dbFile; Write-Host "Deleted $dbFile" }
if (Test-Path $apiDbFile) { Remove-Item -Force $apiDbFile; Write-Host "Deleted $apiDbFile" }

Write-Host "🧹 Cleaning Frontend Cache..." -ForegroundColor Yellow
$frontendNext = "$root\frontend\.next"
$frontendCache = "$root\frontend\node_modules\.cache"
if (Test-Path $frontendNext) { Remove-Item -Recurse -Force $frontendNext; Write-Host "Cleared .next cache" }
if (Test-Path $frontendCache) { Remove-Item -Recurse -Force $frontendCache; Write-Host "Cleared node_modules cache" }

$env:PYTHONPATH = $root
$env:API_KEY = "adv-dev-key-123"

Write-Host "🚀 Starting API..." -ForegroundColor Cyan
Start-Process -FilePath "python" -ArgumentList "-m uvicorn main:app --host 127.0.0.1 --port 8080" -WorkingDirectory "$root\api" -WindowStyle Normal

Write-Host "🚀 Starting Frontend..." -ForegroundColor Cyan
Start-Process -FilePath "cmd" -ArgumentList "/c npm run dev" -WorkingDirectory "$root\frontend" -WindowStyle Normal

Write-Host "✅ Done. Access at http://127.0.0.1:3000" -ForegroundColor Green
