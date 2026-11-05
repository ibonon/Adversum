# Adversum — résolution de la clé API pour les scripts de développement
#
# Source unique, sans valeur en dur : la variable d'environnement API_KEY,
# sinon la ligne API_KEY= du fichier .env à la racine du dépôt (celui que
# l'application charge elle-même). Aucun script ne doit forcer une clé connue :
# en production, api/main.py refuse de démarrer avec la clé de développement.
#
# Usage :
#   . "$PSScriptRoot\scripts\lib\api-key.ps1"    # depuis la racine
#   $key = Get-AdversumApiKey
#   if (-not $key) { Write-Host "API_KEY introuvable" -ForegroundColor Red; exit 1 }

function Get-AdversumApiKey {
    param(
        # Racine du dépôt ; par défaut, deux niveaux au-dessus de scripts/lib.
        [string]$RepoRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    )

    if ($env:API_KEY) { return $env:API_KEY }

    $envFile = Join-Path $RepoRoot ".env"
    if (Test-Path $envFile) {
        $match = Select-String -Path $envFile -Pattern '^\s*API_KEY\s*=' | Select-Object -First 1
        if ($match) {
            $value = ($match.Line -split '=', 2)[1].Trim().Trim('"').Trim("'")
            if ($value) {
                $env:API_KEY = $value
                return $value
            }
        }
    }

    # Rien de configuré : en développement, l'application retombe sur sa clé de
    # dev documentée et affiche un avertissement. On ne l'invente pas ici.
    return $null
}
