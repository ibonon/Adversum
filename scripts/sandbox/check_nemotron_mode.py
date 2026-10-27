"""Vérification factuelle du mode Nemotron AVANT N2.

Reproduit exactement le chargement de l'application (api/main.py:12) :
`load_dotenv(<racine>/.env)`, puis interroge les mêmes fonctions de détection
de mode que le reste du pipeline (`_is_demo_mode`, `_is_available`).

Aucune clé API complète n'est affichée — uniquement préfixe + longueur.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

SEP = "=" * 78


def masked(value: str) -> str:
    if not value:
        return "(non défini)"
    return f"{value[:6]}… ({len(value)} caractères)"


print(SEP)
print("A. ENVIRONNEMENT BRUT (avant chargement .env)")
print(SEP)
print("NEBIUS_MOCK            :", repr(os.getenv("NEBIUS_MOCK")))
print("NEBIUS_API_KEY         :", masked(os.getenv("NEBIUS_API_KEY", "")))
print("NEBIUS_BASE_URL        :", repr(os.getenv("NEBIUS_BASE_URL")))
print("NEBIUS_MODEL           :", repr(os.getenv("NEBIUS_MODEL")))

# Chargement identique à api/main.py:11-12
from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

print()
print(SEP)
print("B. ENVIRONNEMENT APRÈS load_dotenv(<racine>/.env)")
print(SEP)
print("NEBIUS_MOCK            :", repr(os.getenv("NEBIUS_MOCK")))
key = os.getenv("NEBIUS_API_KEY", "")
print("NEBIUS_API_KEY         :", masked(key))
print("NEBIUS_BASE_URL        :", repr(os.getenv("NEBIUS_BASE_URL")))
print("NEBIUS_MODEL           :", repr(os.getenv("NEBIUS_MODEL")))

print()
print(SEP)
print("C. VERDICT DES FONCTIONS DE DÉTECTION (orchestrator/services/nebius_llm.py)")
print(SEP)
from orchestrator.services import nebius_llm as nb

demo = nb._is_demo_mode()
avail = nb._is_available()
print("_is_demo_mode()        :", demo)
print("_is_available()        :", avail)
print("get_active_model()     :", nb.get_active_model())
print("get_active_base_url()  :", nb.get_active_base_url())

print()
key_ok = key.startswith("nvapi-")
mock_raw = os.getenv("NEBIUS_MOCK")
print("clé commence par 'nvapi-' :", key_ok)
print("NEBIUS_MOCK absent/inerte :", mock_raw is None)

print()
print(SEP)
if key_ok and not demo and avail:
    print("ÉTAT : APPEL RÉEL NVIDIA NIM ACTIF — N2 peut procéder.")
    print(SEP)
    sys.exit(0)
else:
    print("ÉTAT : BLOCAGE — l'appel réel n'est PAS garanti dans cet environnement.")
    print("       (clé 'nvapi-' absente, ou _is_demo_mode() == True)")
    print(SEP)
    sys.exit(2)
