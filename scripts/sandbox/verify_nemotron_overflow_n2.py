"""ÉTAPE N2 — Nemotron génère des hypothèses d'overflow sur code Solidity BRUT.

Appel RÉEL NVIDIA NIM uniquement (garde-fou explicite : aucun mock).
Compare, ligne par ligne et dans les deux sens, Nemotron vs la regex SOL-004
(arithmetic.py) sur les deux fixtures déjà documentées en R1/R2.

Contrat d'erreur distingué (nebius_llm.generate_overflow_hypotheses) :
  - `[]`                              → appel réussi, modèle sans hypothèse.
  - `NebiusOverflowGenerationError`   → échec réel (API/timeout/JSON) : signalé
                                        explicitement, JAMAIS déguisé en `[]`,
                                        et le script sort en code non-zéro.
"""
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

from orchestrator.services import nebius_llm as nb
from modules.solidity.rules import arithmetic

SEP = "=" * 78

OVERFLOW_SOL = (ROOT / "modules" / "solidity" / "tests" / "test_contracts" / "overflow.sol").read_text(
    encoding="utf-8"
)

# Fixture protégée — copie exacte de R1 (verify_z3_edge_cases.py:26-33)
SAFEMATH_SOL = """pragma solidity ^0.4.24;
library SafeMath { function add(uint a, uint b) internal pure returns (uint c) { c = a + b; require(c >= a); } }
contract Guarded {
    using SafeMath for uint256;
    uint256 public totalSupply;
    function add(uint256 amount) public { totalSupply = totalSupply.add(amount); }
}
"""

FIXTURES = [
    ("overflow.sol", OVERFLOW_SOL, "vulnerable (pragma 0.4.24, sans SafeMath)"),
    ("GuardedSafeMath.sol", SAFEMATH_SOL, "protégé (SafeMath + using)"),
]


def regex_lines(src: str) -> list:
    return [f["line"] for f in arithmetic.analyze(src)]


async def main() -> int:
    print(SEP)
    print("N2 — GARDE-FOU D'EXÉCUTION")
    print(SEP)
    print("_is_demo_mode() :", nb._is_demo_mode())
    print("_is_available() :", nb._is_available())
    if nb._is_demo_mode() or not nb._is_available():
        print("\nARRÊT : appel réel indisponible — aucun mock ne sera produit.")
        return 2

    report = {}
    failures = []
    for name, src, desc in FIXTURES:
        print()
        print(SEP)
        print(f"FICHIER : {name}  —  {desc}")
        print(SEP)

        r_lines = regex_lines(src)
        print(f"[regex SOL-004] lignes détectées : {r_lines}")

        try:
            hypotheses = await nb.generate_overflow_hypotheses(src, file_path=name)
        except nb.NebiusOverflowGenerationError as e:
            # Échec réel : on le signale, on n'affiche AUCUN résultat fabriqué.
            print(f"[Nemotron]      ÉCHEC RÉEL (aucune hypothèse produite) : {e}")
            failures.append(name)
            report[name] = {
                "regex_lines": r_lines,
                "error": str(e),
                "status": "NebiusOverflowGenerationError",
            }
            continue

        lines_from_hypotheses = [h["line"] for h in hypotheses if h["line"] is not None]
        print(f"[Nemotron]      {len(hypotheses)} hypothèse(s) — lignes : {lines_from_hypotheses}")

        print("\n[Nemotron] JSON brut normalisé :")
        print(json.dumps(hypotheses, indent=2, ensure_ascii=False))

        only_regex = sorted(set(r_lines) - set(lines_from_hypotheses))
        only_nemotron = sorted(set(lines_from_hypotheses) - set(r_lines))
        both = sorted(set(r_lines) & set(lines_from_hypotheses))
        print(f"\n[ÉCART] communes            : {both}")
        print(f"[ÉCART] regex seulement     : {only_regex}")
        print(f"[ÉCART] Nemotron seulement  : {only_nemotron}")

        report[name] = {
            "status": "ok",
            "regex_lines": r_lines,
            "nemotron_lines": lines_from_hypotheses,
            "nemotron_hypotheses": hypotheses,
            "both": both,
            "only_regex": only_regex,
            "only_nemotron": only_nemotron,
        }

    out = Path(os.environ.get("TEMP", "/tmp")) / "nemotron_overflow_n2.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print()
    print(SEP)
    print(f"Rapport JSON écrit : {out}")
    if failures:
        print(f"ÉCHECS RÉELS (appel Nemotron) : {failures} — aucune valeur simulée affichée.")
        print(SEP)
        return 3
    print(SEP)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
