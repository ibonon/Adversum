"""Vérification du filtre Layer 4 élargi (CRYPTO-001 faux positifs MD5).

Cas 1 — certification_program.py : hashlib.md5 utilisé pour un ID d'application ([:12]).
Cas 2 — feedback_loop.py         : hashlib.md5 utilisé pour un fingerprint (graph_hash).
Ces deux usages sont non sécuritaires → attendus : 0 finding CRYPTO-001.

Contre-épreuve — un vrai MD5 sur un mot de passe DOIT rester détecté.

Sortie code 0 si tous les attendus sont respectés, 1 sinon.
"""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules"))

from crypto_misuse.scanner import CryptoMisuseScanner  # noqa: E402

TEMP = Path(os.environ.get("TEMP", tempfile.gettempdir()))

REAL_NON_SECURITY = [
    TEMP / "sigui_certification_program.py",  # MD5 -> ID applicatif ([:12])
    TEMP / "sigui_feedback_loop.py",          # MD5 -> graph_hash (fingerprint)
]

GENUINE_VULNERABLE = (
    "import hashlib\n"
    "def h(pw):\n"
    "    return hashlib.md5(pw.encode()).hexdigest()\n"
)

failures = []

print("=" * 78)
print("VÉRIFICATION — filtre Layer 4 (faux positifs MD5 non-sécuritaires)")
print("=" * 78)

scanner = CryptoMisuseScanner()

print("\n[1] Usages NON sécuritaires réels (Sigui) — attendus : 0 finding")
for path in REAL_NON_SECURITY:
    if not path.exists():
        print(f"  SKIP (absent) : {path}")
        continue
    findings = scanner.scan_file(str(path))
    crypto = [f for f in findings if f.get("rule_id") == "CRYPTO-001"]
    status = "OK" if not crypto else "ÉCHEC"
    print(f"  {status} — {path.name} : {len(crypto)} finding(s) CRYPTO-001 {[f['line'] for f in crypto]}")
    if crypto:
        failures.append(path.name)

print("\n[2] Contre-épreuve — MD5 sur mot de passe (vulnérable réel) — attendu : >= 1 finding")
tmp = TEMP / "adversum_genuine_md5.py"
tmp.write_text(GENUINE_VULNERABLE, encoding="utf-8")
genuine = [f for f in scanner.scan_file(str(tmp)) if f.get("rule_id") == "CRYPTO-001"]
status = "OK" if genuine else "ÉCHEC"
print(f"  {status} — attendu >= 1, obtenu {len(genuine)} : lignes {[f['line'] for f in genuine]}")
if not genuine:
    failures.append("genuine_md5")

print("\n" + "=" * 78)
if failures:
    print(f"ÉCHECS : {failures}")
    print("=" * 78)
    sys.exit(1)
print("TOUS LES ATTENDUS RESPECTÉS")
print("=" * 78)
sys.exit(0)
