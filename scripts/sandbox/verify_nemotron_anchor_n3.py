"""ÉTAPE N3 — Recoupement textuel des hypothèses Nemotron (ancrage réel).

Vérifie que `anchor_hypothesis()` retrouve la ligne RÉELLE de l'opération dans
le texte source, malgré les numéros erronés rapportés par Nemotron.

Entrées : les hypothèses VERBATIM du run N2 réel (appel NVIDIA NIM), enregistrées
dans `%TEMP%/nemotron_overflow_n2.json` puis recopiées ici telles quelles pour
rendre le test déterministe et reproductible.

Attendu :
  - overflow.sol       : Nemotron 9 / 12  ->  ancré sur 10 / 14
  - GuardedSafeMath.sol: Nemotron 4       ->  ancré sur 2
Aucun appel réseau n'est effectué par ce script.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from modules.solidity.overflow_anchor import anchor_hypotheses

SEP = "=" * 78

OVERFLOW_SOL = (ROOT / "modules" / "solidity" / "tests" / "test_contracts" / "overflow.sol").read_text(
    encoding="utf-8"
)

# Copie exacte de la fixture R1 (verify_z3_edge_cases.py) — utilisée en N2.
SAFEMATH_SOL = """pragma solidity ^0.4.24;
library SafeMath { function add(uint a, uint b) internal pure returns (uint c) { c = a + b; require(c >= a); } }
contract Guarded {
    using SafeMath for uint256;
    uint256 public totalSupply;
    function add(uint256 amount) public { totalSupply = totalSupply.add(amount); }
}
"""

# Hypothèses VERBATIM renvoyées par Nemotron lors du run N2 réel (voir
# verify_nemotron_overflow_n2.py). Les numéros de ligne sont ceux — erronés —
# rapportés par le modèle.
NEMOTRON_HYPOTHESES = {
    "overflow.sol": [
        {
            "line": 9,
            "variable": "totalSupply",
            "operation": "+",
            "protection_apparente": "aucune",
            "guard_detail": "Aucune protection : pragma ^0.4.24 pré-0.8.0, pas de SafeMath, pas de require autour de l'addition.",
        },
        {
            "line": 12,
            "variable": "totalSupply",
            "operation": "-",
            "protection_apparente": "aucune",
            "guard_detail": "Aucune protection : pragma ^0.4.24 pré-0.8.0, pas de SafeMath, pas de require autour de la soustraction.",
        },
    ],
    "GuardedSafeMath.sol": [
        {
            "line": 4,
            "variable": "c",
            "operation": "+",
            "protection_apparente": "require",
            "guard_detail": "require(c >= a) on line 5 validates addition result >= a",
        },
    ],
}

FIXTURES = [
    ("overflow.sol", OVERFLOW_SOL, [10, 14]),
    ("GuardedSafeMath.sol", SAFEMATH_SOL, [2]),
]

# Cas de non-résolution : ligne inexistante -> ANCRAGE_ECHOUE, jamais devinée.
NEGATIVE_CASES = [
    {
        "label": "variable absente du source",
        "hyp": {"line": 3, "variable": "ghostVar", "operation": "+", "protection_apparente": "aucune"},
        "source": OVERFLOW_SOL,
        "expect": "ANCRAGE_ECHOUE",
    },
    {
        "label": "ambiguïté (2 lignes candidates)",
        "hyp": {"line": 1, "variable": "a", "operation": "+", "protection_apparente": "aucune"},
        "source": "contract C {\n    a = a + b;\n    a = a + c;\n}\n",
        "expect": "ANCRAGE_ECHOUE",
    },
]


def main() -> int:
    failures = []
    for name, source, expected_lines in FIXTURES:
        print()
        print(SEP)
        print(f"FICHIER : {name}")
        print(SEP)
        anchored = anchor_hypotheses(NEMOTRON_HYPOTHESES[name], source)
        print(json.dumps(anchored, indent=2, ensure_ascii=False))

        resolved = sorted(a["resolved_line"] for a in anchored if a["anchor_status"] == "ANCRAGE_OK")
        statuses = [a["anchor_status"] for a in anchored]
        print(f"\n[lignes Nemotron rapportées] : {[a['nemotron_line'] for a in anchored]}")
        print(f"[lignes réellement ancrées]  : {resolved}")
        print(f"[statuts]                    : {statuses}")
        print("[snippet ancré, caractère par caractère] :")
        for a in anchored:
            if a["anchor_status"] == "ANCRAGE_OK":
                print(f"  ligne {a['resolved_line']} -> {a['z3_finding']['snippet']!r}")

        if resolved != expected_lines:
            failures.append(f"{name}: attendu {expected_lines}, obtenu {resolved}")
            print(f"ÉCHEC : attendu {expected_lines}")
        else:
            print(f"OK : ancrage correct {expected_lines}")

    print()
    print(SEP)
    print("CHEMIN D'ÉCHEC — aucune ligne ne doit être devinée")
    print(SEP)
    for case in NEGATIVE_CASES:
        result = anchor_hypotheses([case["hyp"]], case["source"])[0]
        status = result["anchor_status"]
        ok = status == case["expect"]
        print(f"{case['label']:38s} -> {status:15s} (ligne ancrée : {result['resolved_line']})  {'OK' if ok else 'ÉCHEC'}")
        if not ok:
            failures.append(f"{case['label']}: attendu {case['expect']}, obtenu {status}")

    print()
    print(SEP)
    if failures:
        print("ÉCHECS :")
        for f in failures:
            print("  -", f)
        print(SEP)
        return 1
    print("RÉSULTAT : ancrage réel validé — 10/14 et 2 retrouvés, échecs correctement marqués.")
    print(SEP)
    return 0


if __name__ == "__main__":
    sys.exit(main())
