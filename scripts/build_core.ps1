# Adversum Build Automation for Rust Core
# ---------------------------------------

$ErrorActionPreference = "Stop"

Write-Host "--- Adversum Rust Core Build Pipeline ---" -ForegroundColor Cyan

# Check for required tools
if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
    Write-Error "Cargo (Rust) is not installed. Please install Rustup."
}

if (-not (Get-Command "maturin" -ErrorAction SilentlyContinue)) {
    Write-Host "Maturin not found. Installing..." -ForegroundColor Yellow
    pip install maturin
}

$CORE_DIR = "core"
$TARGET_FILE = "adversum_core.pyd"

if (-not (Test-Path $CORE_DIR)) {
    Write-Error "Core directory not found: $CORE_DIR"
}

Push-Location $CORE_DIR

try {
    Write-Host "Running release build with maturin..." -ForegroundColor Cyan
    maturin build --release --out ..
    
    # maturin usually names it something like adversum_core.cp310-win_amd64.pyd
    # We might need to rename it to a consistent name for common FFI if not using --strip
    # But usually maturin works fine with the complex name if imported as 'adversum_core'
    
    Write-Host "Build successful!" -ForegroundColor Green
}
finally {
    Pop-Location
}

Write-Host "--- Pipeline Complete ---" -ForegroundColor Cyan
