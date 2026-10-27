"""ÉTAPE R2 — hypothèses implicites de prove_overflow(). Sortie réelle."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from modules.solidity.rules import arithmetic
from modules.formal_verification.z3_prover import prove_finding_in_source

SEP = "=" * 78


def contract(body, decls="    uint256 a;\n    uint256 b;\n    uint256 c;"):
    return f"""pragma solidity ^0.4.24;
contract C {{
{decls}
    function run(uint256 x, uint256 y) public {{
{body}
    }}
}}
"""


def verdict(src, line, snippet=None):
    f = {"rule_id": "SOL-004", "line": line, "snippet": snippet or src.split("\n")[line - 1].strip()}
    return prove_finding_in_source(f, src)


def stmt_line(src, stmt):
    """Numero de ligne (1-based) de l'instruction dans la source."""
    for i, ln in enumerate(src.split("\n"), start=1):
        if ln.strip() == stmt.strip():
            return i
    return 1


print(f"\n{SEP}\nA1 — operateurs : +, -, * (R1.3 ne testait que +)\n{SEP}")
for op, stmt in (("+", "a = a + b;"), ("-", "a = a - b;"), ("*", "a = a * b;")):
    src = contract("        " + stmt)
    r = verdict(src, stmt_line(src, stmt))
    print(f"  '{op}' -> verdict={r['verdict']} operation={r.get('operation')} exploitable={r['exploitable']}")

print(f"\n{SEP}\nA2 — ordre des operandes (asymetrie de la soustraction)\n{SEP}")
for stmt in ("a = b - a;", "a = a - b;"):
    src = contract("        " + stmt)
    r = verdict(src, stmt_line(src, stmt))
    print(f"  '{stmt:12s}' -> verdict={r['verdict']} modele={r['counterexample']}")

print(f"\n{SEP}\nA3 — plusieurs operandes : a + b + c (BINOP_RE ne prend que les 2 premiers)\n{SEP}")
src = contract("        a = a + b + c;")
r = verdict(src, 5, "a = a + b + c;")
print(f"  'a = a + b + c;' -> verdict={r['verdict']} operation={r.get('operation')} modele={r['counterexample']}")

print(f"\n{SEP}\nA4 — largeurs mixtes (uint8 a ; uint256 b ; a = a + b)\n{SEP}")
src = contract("        s = s + b;", decls="    uint8 s;\n    uint256 b;\n    uint256 c;")
r = verdict(src, 5, "s = s + b;")
print(f"  bits_inferes={r['bit_width']} verdict={r['verdict']} modele={r['counterexample']}")

print(f"\n{SEP}\nA5 — le modele SAT respecte-t-il la largeur declaree ? (uint8)\n{SEP}")
src = contract("        s = s + t;", decls="    uint8 s;\n    uint8 t;\n    uint256 c;")
r = verdict(src, 5, "s = s + t;")
mx = max(r["counterexample"].values()) if r["counterexample"] else None
print(f"  bits={r['bit_width']} verdict={r['verdict']} modele={r['counterexample']} max={mx} (<256 ? {mx is not None and mx < 256})")

print(f"\n{SEP}\nA6 — portee de la garde : SafeMath 'using' dans 1 fonction, + nu ailleurs\n{SEP}")
GUARD_SCOPE = """pragma solidity ^0.4.24;
library SafeMath { function add(uint p, uint q) internal pure returns (uint r) { r = p + q; require(r >= p); } }
contract C {
    using SafeMath for uint256;
    uint256 a;
    function safe(uint256 x) public { a = a.add(x); }
    function unsafe(uint256 x) public { a = a + x; }
}
"""
findings = arithmetic.analyze(GUARD_SCOPE)
print(f"  findings regex sur le fichier : {len(findings)}")
for f in findings:
    r = prove_finding_in_source(f, GUARD_SCOPE)
    print(f"    ligne {f['line']:2d} snippet={f['snippet'][:40]!r} -> verdict={r['verdict']} guarded={r['guarded']}")

print(f"\n{SEP}\nA7 — forme composee (+=) : meme traitement que la forme binaire ?\n{SEP}")
src = contract("        a += b;")
r = verdict(src, 5, "a += b;")
print(f"  'a += b;' -> verdict={r['verdict']} operation={r.get('operation')} modele={r['counterexample']}")
