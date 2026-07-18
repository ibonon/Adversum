# Script de compilation avec gestion des conflits de fichiers Windows
# Ce script compile les tests adversarial avec des délais pour éviter l'erreur 32

Write-Host "=== Compilation des tests adversarial avec approche progressive ===" -ForegroundColor Cyan
Write-Host ""

# Étape 1 : Vérifier que nous sommes dans le bon répertoire
$expectedPath = "F:\Adversum\adversum\core"
$currentPath = Get-Location
if ($currentPath.Path -ne $expectedPath) {
    Write-Host "Changement de répertoire vers $expectedPath" -ForegroundColor Yellow
    Set-Location $expectedPath
}

# Étape 2 : Attendre que les processus antivirus se calment
Write-Host "Étape 1/4 : Attente de 5 secondes pour stabiliser le système..." -ForegroundColor Green
Start-Sleep -Seconds 5

# Étape 3 : Compiler en mode single-threaded (évite les conflits)
Write-Host "Étape 2/4 : Compilation en mode single-threaded (-j 1)..." -ForegroundColor Green
Write-Host "Cela peut prendre plusieurs minutes..." -ForegroundColor Yellow
Write-Host ""

$env:CARGO_BUILD_JOBS = "1"

# Essayer de compiler avec un seul thread
try {
    cargo test --lib adversarial --no-run -j 1 2>&1 | Tee-Object -Variable compileOutput
    $compileExitCode = $LASTEXITCODE
    
    if ($compileExitCode -eq 0) {
        Write-Host ""
        Write-Host "✓ Compilation réussie!" -ForegroundColor Green
        Write-Host ""
        
        # Étape 4 : Attendre avant d'exécuter les tests
        Write-Host "Étape 3/4 : Attente de 3 secondes avant l'exécution..." -ForegroundColor Green
        Start-Sleep -Seconds 3
        
        # Étape 5 : Exécuter les tests
        Write-Host "Étape 4/4 : Exécution des tests..." -ForegroundColor Green
        Write-Host ""
        cargo test --lib adversarial -- --nocapture
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host ""
            Write-Host "=== ✓ TOUS LES TESTS ONT RÉUSSI! ===" -ForegroundColor Green
        }
        else {
            Write-Host ""
            Write-Host "=== ✗ Certains tests ont échoué ===" -ForegroundColor Red
        }
    }
    else {
        Write-Host ""
        Write-Host "✗ Erreur de compilation" -ForegroundColor Red
        Write-Host ""
        Write-Host "Si vous voyez encore l'erreur 32 (fichier verrouillé), essayez :" -ForegroundColor Yellow
        Write-Host "1. Désactiver temporairement Windows Defender" -ForegroundColor Yellow
        Write-Host "2. Fermer tous les programmes inutiles" -ForegroundColor Yellow
        Write-Host "3. Redémarrer votre ordinateur" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Ou exécutez en tant qu'administrateur :" -ForegroundColor Yellow
        Write-Host "Add-MpPreference -ExclusionPath 'F:\Adversum\adversum\core\target'" -ForegroundColor Cyan
    }
}
catch {
    Write-Host "Erreur inattendue : $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "Script terminé." -ForegroundColor Cyan
