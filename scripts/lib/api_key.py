"""
Résolution de la clé API pour les scripts de développement — équivalent Python
de ``scripts/lib/api-key.ps1``.

Source unique, sans valeur en dur : ``API_KEY`` dans l'environnement, sinon la
ligne ``API_KEY=`` du ``.env`` à la racine du dépôt (celui que l'application
charge elle-même).

Rappel : en production (``ADVERSUM_ENV=production``), ``api/main.py`` refuse de
démarrer si la clé est absente, publique, un marqueur ou trop courte. Aucun
script ne doit donc forcer une valeur connue.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def find_repo_root(start: Optional[Path] = None) -> Path:
    """Remonte jusqu'au répertoire contenant ``scripts/lib/api_key.py``."""
    here = (start or Path(__file__)).resolve()
    for parent in [here, *here.parents]:
        if (parent / "scripts" / "lib" / "api_key.py").exists():
            return parent
    return here.parent


def get_api_key(required: bool = False) -> Optional[str]:
    """
    Renvoie la clé API à utiliser, ou ``None`` si aucune n'est configurée.

    :param required: lève ``SystemExit`` avec un message explicite si aucune
        clé n'est trouvée (utile pour les scripts clients qui échoueraient de
        toute façon en 401/403).
    """
    key = (os.getenv("API_KEY") or "").strip()
    if key:
        return key

    env_file = find_repo_root() / ".env"
    if env_file.exists():
        try:
            for raw in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, value = line.split("=", 1)
                if name.strip() == "API_KEY":
                    value = value.strip().strip('"').strip("'")
                    if value:
                        os.environ["API_KEY"] = value
                        return value
        except OSError:
            pass

    if required:
        raise SystemExit(
            "API_KEY is not set (neither environment nor .env). "
            "Export the same key the server uses, or set it in .env."
        )
    return None
