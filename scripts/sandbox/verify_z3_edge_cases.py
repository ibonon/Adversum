"""ÉTAPE R1 — cas limites du prover Z3 (overflow). Sortie réelle, non décrite."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from modules.solidity.rules import arithmetic
from modules.formal_verification.z3_prover import (
    prove_finding_in_source,
    prove_overflow,
)

SEP = "=" * 78


def show(title, payload):
    print(f"\n{SEP}\n{title}\n{SEP}")
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


# ─────────────────────────────────────────────────────────────────────────────
# R1.1 — Cas négatif : contrat protégé (SafeMath et pragma >= 0.8)
# ─────────────────────────────────────────────────────────────────────────────
SAFEMATH_CONTRACT = """pragma solidity ^0.4.24;
library SafeMath { function add(uint a, uint b) internal pure returns (uint c) { c = a + b; require(c >= a); } }
contract Guarded {
    using SafeMath for uint256;
    uint256 public totalSupply;
    function add(uint256 amount) public { totalSupply = totalSupply.add(amount); }
}
"""

PRAGMA_08_CONTRACT = """pragma solidity ^0.8.20;
contract Guarded08 {
    uint256 public totalSupply;
    function add(uint256 amount) public { totalSupply = totalSupply + amount; }
}
"""

print(f"\n{SEP}\nR1.1a — detecte par la regle regex sur contrat PROTEGE\n{SEP}")
for name, src in (("SafeMath", SAFEMATH_CONTRACT), ("pragma >=0.8", PRAGMA_08_CONTRACT)):
    print(f"{name:14s} -> findings regex SOL-004 : {len(arithmetic.analyze(src))}")

print(f"\n{SEP}\nR1.1b — verdict du SOLVEUR sur l'operation protegee (pragma >=0.8)\n{SEP}")
protected_finding = {"rule_id": "SOL-004", "line": 4, "snippet": "totalSupply = totalSupply + amount;"}
show("pragma >=0.8 (garde detectee)", prove_finding_in_source(protected_finding, PRAGMA_08_CONTRACT))
show("SafeMath (garde detectee)", prove_finding_in_source(protected_finding, SAFEMATH_CONTRACT))

# ─────────────────────────────────────────────────────────────────────────────
# R1.2 — Tailles d'entiers variables (uint8 / uint128 / uint256)
# ─────────────────────────────────────────────────────────────────────────────
def width_contract(uint_type):
    return f"""pragma solidity ^0.4.24;
contract C {{
    {uint_type} public totalSupply;
    function add({uint_type} amount) public {{
        require(amount <= 200);
        require(totalSupply <= 200);
        totalSupply = totalSupply + amount;
    }}
}}
"""

WIDTH_FINDING = {"rule_id": "SOL-004", "line": 6, "snippet": "totalSupply = totalSupply + amount;"}
print(f"\n{SEP}\nR1.2 — meme operation, largeurs differentes (bornes 200/200)\n{SEP}")
for t in ("uint8", "uint128", "uint256"):
    r = prove_finding_in_source(WIDTH_FINDING, width_contract(t))
    print(f"{t:8s} -> bits={r['bit_width']:3d}  verdict={r['verdict']:7s}  exploitable={r['exploitable']}")

# ─────────────────────────────────────────────────────────────────────────────
# R1.3 — 14 operations arithmetiques dans un meme fichier
# ─────────────────────────────────────────────────────────────────────────────
N = 14
decls = "\n".join(f"    uint256 a{i};\n    uint256 b{i};" for i in range(N))
body = "\n".join(f"        a{i} = a{i} + b{i};" for i in range(N))
MULTI_CONTRACT = f"""pragma solidity ^0.4.24;
contract Multi {{
{decls}
    function run() public {{
{body}
    }}
}}
"""

print(f"\n{SEP}\nR1.3 — {N} operations dans un meme fichier : temps + isolation des modeles\n{SEP}")
findings = arithmetic.analyze(MULTI_CONTRACT)
start = time.perf_counter()
results = [prove_finding_in_source(f, MULTI_CONTRACT) for f in findings]
elapsed = time.perf_counter() - start
print(f"findings={len(findings)}  duree_totale={elapsed:.4f}s  duree_moyenne={elapsed/max(len(findings),1)*1000:.2f}ms")

crossed = []
import re as _re
for f, r in zip(findings, results):
    # Les operandes attendus sont ceux du snippet lui-meme (a<i>/b<i>),
    # pas derives de la ligne (l'ancienne formule f["line"]-1 etait fausse).
    expected = set(_re.findall(r"\b([ab]\d+)\b", f.get("snippet", "")))
    if r["counterexample"] is not None and set(r["counterexample"]) != expected:
        crossed.append((f["line"], sorted(r["counterexample"]), sorted(expected)))
    print(f"  ligne {f['line']:3d} verdict={r['verdict']:7s} cles_modele={sorted(r['counterexample'] or {})} attendu={sorted(expected)}")
print(f"contaminations croisees detectees : {len(crossed)}")
for c in crossed:
    print(f"    CONTAMINATION ligne={c[0]} modele={c[1]} attendu={c[2]}")

# ─────────────────────────────────────────────────────────────────────────────
# R1.4 — Snippets malformes / faux positifs de la regex
# ─────────────────────────────────────────────────────────────────────────────
MALFORMED = [
    "totalSupply = totalSupply + ;",
    "totalSupply = (",
    "= + ;",
    "",
    "x.y[1 = a + b;",
    "emit Transfer(a + b);",
]
print(f"\n{SEP}\nR1.4 — snippets invalides : echec propre, pas de crash ni faux SAT\n{SEP}")
for snip in MALFORMED:
    try:
        r = prove_overflow({"rule_id": "SOL-004", "line": 1, "snippet": snip})
        print(f"  {snip!r:36s} -> verdict={r['verdict']:8s} smt_verified={r['smt_verified']} exploitable={r['exploitable']}")
    except Exception as exc:
        print(f"  {snip!r:36s} -> EXCEPTION {type(exc).__name__}: {exc}")
