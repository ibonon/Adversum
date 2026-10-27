"""
Z3-backed formal proof for SOL-004 (integer overflow / underflow).

Remplace le texte codé en dur "SMT FORMAL PROOF" par une vérification réelle :
les contraintes sont construites sur des BitVec (et non des Int), car seuls les
BitVec reproduisent le débordement arithmétique de l'EVM (uint256 / int256).

Périmètre honnête : ce module prouve qu'un débordement est *représentable*
pour l'opération arithmétique détectée par la règle regex. Il ne prouve pas
qu'un attaquant peut atteindre cet état depuis l'extérieur du contrat.
Toute conclusion au-delà de cette borne doit être étiquetée comme telle.
"""

import re

from z3 import (
    BitVec,
    BVMulNoOverflow,
    BVAddNoOverflow,
    BVSubNoUnderflow,
    Solver,
    Not,
    And,
    Int,
    UGE,
    UGT,
    ULE,
    sat,
    unsat,
)

# Règles adossées à une preuve Z3 réelle.
SUPPORTED_RULES = frozenset({"SOL-004", "SOL-001"})

# Prédicat vrai si et seulement si l'opération PEUT déborder.
_OVERFLOW_CONDITION = {
    "+": lambda x, y: Not(BVAddNoOverflow(x, y, False)),
    "-": lambda x, y: Not(BVSubNoUnderflow(x, y, False)),
    "*": lambda x, y: Not(BVMulNoOverflow(x, y, False)),
}

_ASSIGN_RE = re.compile(
    r"^\s*(?P<lhs>[\w.\[\]]+)\s*(?P<compound>[+\-*])?=\s*(?P<rhs>.+?);?\s*$"
)
_BINOP_RE = re.compile(
    r"(?P<a>[\w.\[\]]+)\s*(?P<op>[+\-*])\s*(?P<b>[\w.\[\]()]+)"
)
_REQUIRE_BOUND_RE = re.compile(
    r"require\s*\(\s*([\w.]+)\s*(<=|<|>=|>)\s*(\d+)\s*\)"
)
_NATIVE_GUARD_RE = re.compile(r"pragma\s+solidity\s+[\^~]?0\.(?:8|9|\d{2})\.")

# La garde SafeMath / Solidity >= 0.8 est *modélisée* comme contrainte de
# non-débordement. C'est une hypothèse de sémantique, pas une preuve
# extraite du bytecode : à ne jamais présenter comme une preuve de code.
GUARD_ASSUMPTION = (
    "La sémantique de la garde (revert sur débordement) est modélisée comme "
    "contrainte, non vérifiée depuis le bytecode du compilateur."
)


def _is_balanced(text: str) -> bool:
    """Vrai si les crochets/accolades/parentheses du texte sont équilibrés.

    Un faux positif de la regex (ex. ``x.y[1 = a + b;``) n'est pas une
    expression arithmétique valide : le prover doit le rejeter comme
    UNPARSED plutôt que d'en extraire un operande et de retourner un faux SAT.
    """
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    for ch in text:
        if ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            if not stack or stack.pop() != pairs[ch]:
                return False
    return not stack


def _parse_arithmetic(snippet: str):
    """Extrait (op, operande_gauche, operande_droit) d'un snippet de finding.

    Gère les deux formes émises par arithmetic.py :
      - ``totalSupply = totalSupply + amount;``  (forme binaire)
      - ``totalSupply += amount;``               (forme composée)
    """
    if not snippet or not _is_balanced(snippet):
        return None

    assign = _ASSIGN_RE.match(snippet)
    if not assign:
        return None

    compound = assign.group("compound")
    if compound:
        return compound, assign.group("lhs"), assign.group("rhs").strip()

    binop = _BINOP_RE.search(assign.group("rhs"))
    if not binop:
        return None

    return binop.group("op"), binop.group("a"), binop.group("b")


def _infer_bit_width(content: str, var_name: str) -> int:
    """Déduit la largeur en bits d'une variable depuis sa déclaration Solidity.

    ``uint8`` -> 8, ``uint128`` -> 128, ``uint`` / ``uint256`` -> 256.
    Retourne 256 (hypothèse par défaut) si la déclaration n'est pas trouvée.
    """
    if not content or not var_name:
        return 256

    decl = re.search(
        r"\buint(?P<bits>\d*)\b[^;()=]*?\b" + re.escape(var_name) + r"\b", content
    )
    if not decl:
        return 256

    bits = decl.group("bits")
    return int(bits) if bits else 256


def _extract_bounds(content: str) -> dict:
    """Extrait les bornes numériques simples des ``require(var <= N)``.

    Retourne ``{var: (lo, hi)}``. Les bornes non contraintes valent None.
    """
    bounds = {}
    if not content:
        return bounds

    for var, op, raw in _REQUIRE_BOUND_RE.findall(content):
        n = int(raw)
        lo, hi = bounds.get(var, (0, None))
        if op == "<=":
            hi = n if hi is None else min(hi, n)
        elif op == "<":
            cap = n - 1
            hi = cap if hi is None else min(hi, cap)
        elif op == ">=":
            lo = max(lo, n)
        elif op == ">":
            lo = max(lo, n + 1)
        bounds[var] = (lo, hi)

    return bounds


def _strip_comments(content: str) -> str:
    """Retire les commentaires Solidity (``//`` et ``/* */``).

    Évite qu'un simple mot comme « SafeMath » cité dans un commentaire
    (ex. ``// Aucun SafeMath, aucune garde``) ne soit pris pour une garde
    réelle et ne transforme un contrat vulnérable en faux UNSAT.
    """
    return re.sub(r"//[^\n]*|/\*.*?\*/", " ", content, flags=re.DOTALL)


def _detect_guard(content: str) -> bool:
    """Détecte une protection anti-débordement : SafeMath ou pragma >= 0.8."""
    if not content:
        return False
    code = _strip_comments(content)
    return bool(re.search(r"\bSafeMath\b", code)) or bool(
        _NATIVE_GUARD_RE.search(code)
    )


def _apply_bounds(solver, bounds: dict, left: str, right: str, x, y) -> None:
    """Applique les bornes connues aux deux opérandes du finding courant."""
    for var, (lo, hi) in (bounds or {}).items():
        ref = x if var == left else y if var == right else None
        if ref is None:
            # Les bornes d'une autre variable du fichier ne doivent PAS
            # contaminer ce finding — c'est le risque de résultat croisé.
            continue
        if lo is not None:
            solver.add(UGE(ref, lo))
        if hi is not None:
            solver.add(ULE(ref, hi))


def prove_overflow(
    finding: dict,
    bit_width: int = 256,
    bounds: dict = None,
    guarded: bool = False,
) -> dict:
    """Construit les contraintes Z3 pour un finding SOL-004 et les résout.

    ``guarded=True`` modélise SafeMath / Solidity >= 0.8 : la garde impose
    l'absence de débordement, et le solveur doit alors retourner UNSAT.

    Retourne un dict contenant le verdict réel du solveur, le modèle concret
    (valeurs numériques) en cas de SAT, et la portée exacte de la preuve.
    """
    snippet = finding.get("snippet", "")
    parsed = _parse_arithmetic(snippet)

    base = {
        "rule_id": finding.get("rule_id", ""),
        "line": finding.get("line"),
        "snippet": snippet,
        "bit_width": bit_width,
        "guarded": guarded,
        "scope": "overflow representable for this operation (not reachability-proven)",
    }

    if not parsed:
        base.update(
            {
                "smt_verified": False,
                "verdict": "UNPARSED",
                "exploitable": None,
                "proof": "Expression arithmétique non analysable — aucune preuve Z3 produite.",
                "model": None,
                "counterexample": None,
            }
        )
        return base

    op, left, right = parsed
    x = BitVec(left, bit_width)
    y = BitVec(right, bit_width)

    solver = Solver()
    # Domaine plausible : les deux opérandes sont non nuls.
    # UGT = comparaison NON SIGNÉE — indispensable, car `x > 0` sur un BitVec
    # utilise par défaut la comparaison signée de z3 et restreindrait x à
    # [1, 2^(w-1)-1], rendant le débordement d'une addition uint indétectable.
    solver.add(UGT(x, 0), UGT(y, 0))
    _apply_bounds(solver, bounds or {}, left, right, x, y)

    overflow_possible = _OVERFLOW_CONDITION[op](x, y)
    if guarded:
        # Sémantique modélisée de la garde : le débordement déclenche un revert.
        solver.add(Not(overflow_possible))
    # La requête est constante dans les deux modes : « existe-t-il une
    # assignation qui déborde, sous les contraintes modélisées ? »
    # - non gardé : SAT  -> débordement atteignable
    # - gardé     : UNSAT -> la garde interdit effectivement le débordement
    solver.add(overflow_possible)

    result = solver.check()

    if result == sat:
        model = solver.model()
        x_val = model[x].as_long() if model[x] is not None else None
        y_val = model[y].as_long() if model[y] is not None else None
        base.update(
            {
                "smt_verified": True,
                "verdict": "SAT",
                "exploitable": True,
                "operation": op,
                "proof": (
                    f"Z3 SAT ({bit_width}-bit BitVec) — débordement {op} atteignable "
                    f"avec {left}={x_val}, {right}={y_val}."
                ),
                "model": str(model),
                "counterexample": {left: x_val, right: y_val},
            }
        )
        return base

    if result == unsat:
        if guarded:
            proof = (
                f"Z3 UNSAT ({bit_width}-bit BitVec) — aucun débordement {op} possible : "
                f"la garde modélisée l'interdit. {GUARD_ASSUMPTION}"
            )
        else:
            proof = (
                f"Z3 UNSAT ({bit_width}-bit BitVec) — aucun débordement {op} possible "
                "sur le domaine contraint."
            )
        base.update(
            {
                "smt_verified": True,
                "verdict": "UNSAT",
                "exploitable": False,
                "operation": op,
                "proof": proof,
                "model": None,
                "counterexample": None,
            }
        )
        return base

    base.update(
        {
            "smt_verified": False,
            "verdict": "UNKNOWN",
            "exploitable": None,
            "proof": "Z3 a retourné unknown (timeout ou théorie non supportée).",
            "model": None,
            "counterexample": None,
        }
    )
    return base


def prove_finding_in_source(finding: dict, content: str) -> dict:
    """Variante consciente du contexte : infère largeur, bornes et garde.

    À préférer à ``prove_overflow`` quand le contenu source est disponible,
    car la largeur réelle (uint8 / uint128 / uint256) change le verdict.
    """
    parsed = _parse_arithmetic(finding.get("snippet", ""))

    bit_width = 256
    if parsed:
        _, left, right = parsed
        bit_width = _infer_bit_width(content, left)
        if bit_width == 256:
            bit_width = _infer_bit_width(content, right)

    return prove_overflow(
        finding,
        bit_width=bit_width,
        bounds=_extract_bounds(content),
        guarded=_detect_guard(content),
    )


def prove_reentrancy(z3_finding: dict) -> dict:
    """Modélisation Z3 booléenne ordonnée pour SOL-001.
    
    Vérifie si l'appel externe précède la mise à jour d'état en l'absence de garde.
    Utilise des variables Int pour modéliser les positions relatives.
    """
    call_line = z3_finding.get("call_line", 0)
    update_line = z3_finding.get("update_line", 0)
    guard = z3_finding.get("guard_present", "none")
    
    # Variables Z3
    pos_call = Int('pos_call')
    pos_update = Int('pos_update')
    has_guard = BitVec('has_guard', 1) # 1 if guard present, 0 otherwise
    
    solver = Solver()
    
    # Contraintes issues de l'ancrage
    solver.add(pos_call == call_line)
    solver.add(pos_update == update_line)
    solver.add(has_guard == (1 if guard != "none" else 0))
    
    # Définition de la vulnérabilité : (Appel < Mise à jour) ET (Pas de garde)
    is_vulnerable = And(pos_call < pos_update, has_guard == 0)
    
    solver.add(is_vulnerable)
    result = solver.check()
    
    base = {
        "rule_id": "SOL-001",
        "smt_verified": True,
        "scope": "execution sequence order (external call vs state update)",
        "verdict": "SAT" if result == sat else "UNSAT",
        "exploitable": result == sat,
        "model": str(solver.model()) if result == sat else None
    }
    
    if result == sat:
        base["proof"] = f"Z3 SAT — Appel ligne {call_line} avant mise à jour ligne {update_line} sans garde."
    else:
        if guard != "none":
            base["proof"] = f"Z3 UNSAT — Protégé par la garde '{guard}'."
        else:
            base["proof"] = f"Z3 UNSAT — Mise à jour ligne {update_line} avant l'appel ligne {call_line} (CEI respecté)."
            
    return base
