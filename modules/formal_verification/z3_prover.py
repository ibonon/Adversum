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
    Or,
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


_TYPE_PREFIX_RE = re.compile(
    r"^(?:uint\d{0,3}|int\d{0,3}|address|bool|bytes\d{0,2})(?:\s+(?:public|private|internal))?\s+(?P<rest>[A-Za-z_].*)$"
)


def _normalize_snippet(snippet: str) -> str:
    """Strip a leading type declaration (``uint256 total = a * b;``)."""
    if not snippet:
        return snippet
    m = _TYPE_PREFIX_RE.match(snippet.strip())
    if m and "=" in m.group("rest"):
        return m.group("rest").strip()
    return snippet


def _parse_arithmetic(snippet: str):
    """Extrait (op, operande_gauche, operande_droit) d'un snippet de finding.

    Gère les deux formes émises par arithmetic.py :
      - ``totalSupply = totalSupply + amount;``  (forme binaire)
      - ``totalSupply += amount;``               (forme composée)
    """
    snippet = _normalize_snippet(snippet)
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


def _parse_chain(snippet: str):
    """Parse a (possibly multi-operand) arithmetic assignment.

    Returns ``(first_operand, [(op, operand), ...])`` or ``None``.
    Covers A3 (``a = a + b + c`` folds left, every step can overflow)
    where the old parser silently dropped operands past the second.
    """
    snippet = _normalize_snippet(snippet)
    if not snippet or not _is_balanced(snippet):
        return None
    assign = _ASSIGN_RE.match(snippet)
    if not assign:
        return None
    compound = assign.group("compound")
    rhs = assign.group("rhs").strip().rstrip(";")
    if compound:
        first = assign.group("lhs")
        toks = re.findall(r"[\w.\[\]()]+|[+\-*]", rhs)
        if not toks:
            return None
        return first, [(compound, toks[0])]
    parts = re.findall(r"[\w.\[\]()]+|[+\-*]", rhs)
    if len(parts) < 3 or parts[1] not in ("+", "-", "*"):
        return None
    steps = []
    for i in range(1, len(parts) - 1, 2):
        if parts[i] in ("+", "-", "*") and i + 1 < len(parts):
            steps.append((parts[i], parts[i + 1]))
    if not steps:
        return None
    return parts[0], steps


def _function_slice(content: str, line_no) -> str:
    """Source slice of the function enclosing ``line_no`` (best effort).

    Used to scope ``require`` bounds to their own function (A8): bounds
    from a same-named variable in another function no longer leak.
    Falls back to the whole content when no function is located.
    """
    if not content or not line_no:
        return content or ""
    try:
        from modules.solidity.function_parser import function_at, parse_source
        _lines, _c, functions = parse_source(content)
        fn = function_at(functions, int(line_no))
        if fn is not None:
            src_lines = content.split("\n")
            return "\n".join(src_lines[fn.body_start - 1:fn.end_line])
    except Exception:
        pass
    return content


def prove_overflow(
    finding: dict,
    bit_width: int = 256,
    bounds: dict = None,
    guarded: bool = False,
    operand_widths: dict = None,
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
    chain = _parse_chain(snippet) or (left, [(op, right)])
    first_operand, steps = chain
    operand_names = [first_operand] + [o for _op, o in steps]
    # Solidity promotion (A4): the operation runs at the widest operand
    # width; narrower operands keep their original range as a constraint.
    widths = {n: int((operand_widths or {}).get(n, bit_width)) for n in operand_names}
    promoted = max([bit_width] + list(widths.values())) if operand_widths else bit_width
    if operand_widths:
        promoted = max(widths.values())
    base["bit_width"] = promoted
    base["operand_widths"] = widths

    solver = Solver()
    vars_by_name: dict = {}

    def _bv(name: str):
        if name not in vars_by_name:
            v = BitVec(name, promoted)
            vars_by_name[name] = v
            # Domaine plausible : opérandes non nuls (comparaison NON
            # SIGNÉE, sinon le débordement uint devient indétectable).
            solver.add(UGT(v, 0))
            origin = widths.get(name, promoted)
            if origin < promoted:
                solver.add(ULE(v, (1 << origin) - 1))
            for var_name, (lo, hi) in (bounds or {}).items():
                if var_name == name:
                    if lo is not None:
                        solver.add(UGE(v, lo))
                    if hi is not None:
                        solver.add(ULE(v, hi))
        return vars_by_name[name]

    expr = _bv(first_operand)
    overflow_terms = []
    for step_op, operand in steps:
        y = _bv(operand)
        overflow_terms.append(_OVERFLOW_CONDITION[step_op](expr, y))
        if step_op == "+":
            expr = expr + y
        elif step_op == "-":
            expr = expr - y
        else:
            expr = expr * y
    x = vars_by_name[first_operand]
    y = vars_by_name[steps[0][1]] if steps else x
    overflow_possible = Or(*overflow_terms) if len(overflow_terms) > 1 else overflow_terms[0]
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
        counterexample = {}
        for name, var in vars_by_name.items():
            try:
                counterexample[name] = model[var].as_long() if model[var] is not None else None
            except Exception:
                counterexample[name] = None
        x_val = counterexample.get(left)
        y_val = counterexample.get(right)
        base.update(
            {
                "smt_verified": True,
                "verdict": "SAT",
                "exploitable": True,
                "operation": op,
                "proof": (
                    f"Z3 SAT ({promoted}-bit BitVec) — débordement {op} atteignable "
                    f"avec {left}={x_val}, {right}={y_val}."
                ),
                "model": str(model),
                "counterexample": counterexample,
            }
        )
        return base

    if result == unsat:
        if guarded:
            proof = (
                f"Z3 UNSAT ({promoted}-bit BitVec) — aucun débordement {op} possible : "
                f"la garde modélisée l'interdit. {GUARD_ASSUMPTION}"
            )
        else:
            proof = (
                f"Z3 UNSAT ({promoted}-bit BitVec) — aucun débordement {op} possible "
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
    chain = _parse_chain(finding.get("snippet", ""))

    bit_width = 256
    operand_widths: dict = {}
    if chain:
        first_operand, steps = chain
        names = [first_operand] + [o for _op, o in steps]
        for name in names:
            base_name = re.split(r"[.\[]", name)[0]
            operand_widths[name] = _infer_bit_width(content, base_name)
        bit_width = max(operand_widths.values()) if operand_widths else 256
    elif parsed:
        _, left, right = parsed
        bit_width = _infer_bit_width(content, left)
        if bit_width == 256:
            bit_width = _infer_bit_width(content, right)

    # Bounds are scoped to the enclosing function (A8 fix).
    scoped = _function_slice(content, finding.get("line"))
    return prove_overflow(
        finding,
        bit_width=bit_width,
        bounds=_extract_bounds(scoped),
        guarded=_detect_guard(content),
        operand_widths=operand_widths or None,
    )


def prove_overflow_reachable(finding: dict, content: str) -> dict:
    """Overflow proof + single-function reachability (P1).

    Reachability is heuristic and explicitly scoped: the enclosing
    function must be externally reachable (public/external/fallback, or
    internal with a located caller) and at least one operand must be
    tainted by a function parameter or ``msg.value``. The result never
    upgrades an UNSAT, and ``exploitable`` requires SAT *and* reachable.
    """
    result = prove_finding_in_source(finding, content)
    reach = {"reachable": None, "entry_point": None, "taint_sources": [],
             "reachability_scope": "single-function heuristic (entry + param taint); not a whole-contract proof"}
    try:
        from modules.solidity.function_parser import function_at, parse_source
        _lines, _c, functions = parse_source(content or "")
        fn = function_at(functions, int(finding.get("line") or 0))
        if fn is not None:
            reach["entry_point"] = fn.name
            header = fn.header.lower()
            externally = any(k in header for k in ("public", "external")) or fn.kind in ("fallback", "receive", "constructor")
            if not externally and fn.kind == "function":
                # Internal/private: reachable only if a caller is located.
                callers = [o for o in functions if o is not fn and re.search(
                    r"\b" + re.escape(fn.name) + r"\s*\(", "\n".join(
                        (content or "").split("\n")[o.body_start - 1:o.end_line]))]
                externally = bool(callers)
            parsed = _parse_chain(finding.get("snippet", "")) or (None, [])
            names = []
            if parsed[0]:
                names = [parsed[0]] + [o for _op, o in parsed[1]]
            taint = [n for n in names
                     if re.split(r"[.\[]", n)[0] in set(fn.params)
                     or n.startswith("msg.")]
            reach["taint_sources"] = taint
            reach["reachable"] = bool(externally and taint)
    except Exception:
        pass
    result.update(reach)
    result["scope"] = (
        "overflow representable + single-function reachability-checked"
        if reach["reachable"] else
        "overflow representable for this operation (not reachability-proven)"
    )
    if result.get("verdict") == "SAT":
        result["exploitable"] = True if reach["reachable"] else result.get("exploitable")
        result["reachability_proven"] = bool(reach["reachable"])
    return result


def apply_z3_binding(findings: list, contents_by_file: dict, binding: bool = True):
    """Split findings into (kept, suppressed) using binding Z3 verdicts.

    P1: an UNSAT verdict (guard modelled, no overflow representable)
    now *removes* the SOL-004 finding from the exploitable list instead
    of merely annotating it (KNOWN_LIMITATIONS §4). SAT and UNPARSED
    findings are kept, annotated with their verdict. When ``binding``
    is False the legacy annotate-only behaviour is preserved.
    """
    kept, suppressed = [], []
    for f in findings:
        if not binding or f.get("rule_id") != "SOL-004":
            kept.append(f)
            continue
        content = contents_by_file.get(f.get("file_path") or f.get("file") or "", "")
        if not content:
            kept.append(f)
            continue
        try:
            res = prove_finding_in_source(
                {"rule_id": "SOL-004", "line": f.get("line"), "snippet": f.get("snippet", "")},
                content,
            )
        except Exception:
            kept.append(f)
            continue
        annotated = {**f, "z3_verdict": res.get("verdict"), "z3_exploitable": res.get("exploitable")}
        if res.get("verdict") == "UNSAT":
            suppressed.append(annotated)
        else:
            kept.append(annotated)
    return kept, suppressed


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
