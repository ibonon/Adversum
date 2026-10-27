"""ÉTAPE N3 — Verdicts Z3 sur les snippets ISOLÉS par l'ancrage.

Pour chaque hypothèse Nemotron ancrée avec succès, appelle `prove_overflow()`
avec le snippet strictement isolé (`c = a + b;`, pas la ligne entière) et la
largeur de bits déduite du contexte (256 par défaut si non déterminable).

Aucun appel réseau : les hypothèses sont celles, verbatim, du run N2 réel.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from modules.solidity.overflow_anchor import anchor_hypotheses
from modules.formal_verification import z3_prover as z3p

SEP = "=" * 78

OVERFLOW_SOL = (ROOT / "modules" / "solidity" / "tests" / "test_contracts" / "overflow.sol").read_text(
    encoding="utf-8"
)

SAFEMATH_SOL = """pragma solidity ^0.4.24;
library SafeMath { function add(uint a, uint b) internal pure returns (uint c) { c = a + b; require(c >= a); } }
contract Guarded {
    using SafeMath for uint256;
    uint256 public totalSupply;
    function add(uint256 amount) public { totalSupply = totalSupply.add(amount); }
}
"""

# Hypothèses VERBATIM du run N2 réel (numéros de ligne erronés inclus).
NEMOTRON_HYPOTHESES = {
    "overflow.sol": [
        {"line": 9, "variable": "totalSupply", "operation": "+", "protection_apparente": "aucune"},
        {"line": 12, "variable": "totalSupply", "operation": "-", "protection_apparente": "aucune"},
    ],
    "GuardedSafeMath.sol": [
        {"line": 4, "variable": "c", "operation": "+", "protection_apparente": "require"},
    ],
}

FIXTURES = [
    ("overflow.sol", OVERFLOW_SOL),
    ("GuardedSafeMath.sol", SAFEMATH_SOL),
]


def infer_bit_width(finding: dict, content: str) -> int:
    """Largeur déduite du contexte ; 256 si non déterminable."""
    parsed = z3p._parse_arithmetic(finding.get("snippet", ""))
    if not parsed:
        return 256
    _, left, right = parsed
    width = z3p._infer_bit_width(content, left)
    if width == 256:
        width = z3p._infer_bit_width(content, right)
    return width


def main() -> int:
    for name, source in FIXTURES:
        print()
        print(SEP)
        print(f"FICHIER : {name}")
        print(SEP)
        anchored = anchor_hypotheses(NEMOTRON_HYPOTHESES[name], source)

        for a in anchored:
            if a["anchor_status"] != "ANCRAGE_OK":
                print(f"[{a['anchor_status']}] hypothèse (variable={a.get('variable')}) NON soumise à Z3 "
                      f"— {a.get('anchor_reason')}")
                continue

            finding = a["z3_finding"]
            width = infer_bit_width(finding, source)
            print(f"\nnemotron_line={a['nemotron_line']}  ->  résolu ligne {a['resolved_line']}")
            print(f"  snippet isolé : {finding['snippet']!r}")
            print(f"  largeur bits déduite : {width}")

            # 1) appel demandé : snippet isolé, garde NON forcée (détectée du contexte)
            auto_guarded = z3p._detect_guard(source)
            res_auto = z3p.prove_overflow(
                finding,
                bit_width=width,
                bounds=z3p._extract_bounds(source),
                guarded=auto_guarded,
            )
            print(f"  [prove_overflow, guarded={auto_guarded}] verdict={res_auto['verdict']} "
                  f"exploitable={res_auto['exploitable']} smt_verified={res_auto['smt_verified']}")
            print(f"    proof : {res_auto['proof']}")
            if res_auto.get("counterexample"):
                print(f"    contre-exemple : {res_auto['counterexample']}")

            # 2) contre-épreuve : snippet seul, sans garde du tout
            res_bare = z3p.prove_overflow(finding, bit_width=width, bounds={}, guarded=False)
            print(f"  [prove_overflow, guarded=False] verdict={res_bare['verdict']} "
                  f"exploitable={res_bare['exploitable']}")
            if res_bare.get("counterexample"):
                print(f"    contre-exemple : {res_bare['counterexample']}")

    print()
    print(SEP)
    print("FIN — verdicts réels ci-dessus (aucune valeur simulée).")
    print(SEP)
    return 0


if __name__ == "__main__":
    sys.exit(main())
