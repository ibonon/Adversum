# ==============================================================================
# Adversum 1-Click Production Deployment Script (Windows PowerShell)
# ==============================================================================
param (
    [switch]$Build = $false,
    [switch]$Down = $false,
    [switch]$Logs = $false
)

$ErrorActionPreference = "Stop"

Write-Host "`n=== [ADVERSUM INSTITUTIONAL STACK DEPLOYER] ===" -ForegroundColor Cyan

if ($Down) {
    Write-Host "Shutting down Adversum stack..." -ForegroundColor Yellow
    docker compose down
    Write-Host "[OK] Stack stopped." -ForegroundColor Green
    exit 0
}

if ($Logs) {
    docker compose logs -f
    exit 0
}

# Verify Docker engine
Write-Host "Verifying Docker engine..." -ForegroundColor Gray
try {
    docker info > $null 2>&1
    Write-Host "[OK] Docker daemon is running." -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Docker daemon is not running. Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

# Build / Launch stack
if ($Build) {
    Write-Host "Building fresh containers..." -ForegroundColor Yellow
    docker compose build
}

Write-Host "Starting multi-container orchestration..." -ForegroundColor Cyan
docker compose up -d

Write-Host "`nWaiting for backend readiness probe..." -ForegroundColor Gray
$maxRetries = 20
$retry = 0
$ready = $false

while ($retry -lt $maxRetries -and -not $ready) {
    Start-Sleep -Seconds 2
    $retry++
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:8000/health/ready" -Method Get -TimeoutSec 3 -ErrorAction SilentlyContinue
        if ($response.ready -eq $true) {
            $ready = $true
        }
    } catch {
        Write-Host "  Probe attempt $retry/$maxRetries waiting..." -ForegroundColor DarkGray
    }
}

if ($ready) {
    Write-Host "`n[SUCCESS] Adversum Stack is 100% OPERATIONAL!" -ForegroundColor Green
    Write-Host "  • Frontend Web UI     : http://localhost" -ForegroundColor White
    Write-Host "  • Live SOC Dashboard   : http://localhost/soc" -ForegroundColor White
    Write-Host "  • Adversum War Room    : http://localhost/war-room" -ForegroundColor White
    Write-Host "  • API & Swagger Docs   : http://localhost:8000/docs" -ForegroundColor White
    Write-Host "  • WebSocket Stream     : ws://localhost:8000/ws/threat-stream" -ForegroundColor White
    Write-Host "  • Anvil EVM Node       : http://localhost:8545" -ForegroundColor White
    Write-Host "`nTo view logs: .\deploy.ps1 -Logs" -ForegroundColor Gray
    Write-Host "To shut down: .\deploy.ps1 -Down`n" -ForegroundColor Gray
} else {
    Write-Host "`n[WARNING] Stack started but readiness probe timed out." -ForegroundColor Yellow
    Write-Host "Check container logs with: docker compose logs" -ForegroundColor Yellow
}
