"""Ancrage réel des hypothèses Nemotron sur le texte source (SOL-004).

Nemotron identifie correctement la *nature* d'une opération à risque (variable,
opérateur, protection apparente) mais pas toujours son numéro de ligne exact
(non-déterminisme observé même à ``temperature=0.0``). Utiliser directement le
champ ``line`` renvoyé par le modèle comme ancrage pour Z3 risquerait de faire
prouver une opération qui n'existe pas.

Ce module recoupe chaque hypothèse avec une recherche textuelle dans le fichier
source réel (même logique de motif que
``modules/solidity/rules/arithmetic.py``) pour retrouver la ligne *effective* de
l'opération. En l'absence de correspondance ou en cas d'ambiguïté (plusieurs
lignes candidates), l'hypothèse est marquée ``ANCRAGE_ECHOUE`` et n'est **pas**
soumise à Z3.
"""
from __future__ import annotations

import re

# Motifs d'opérateur : l'opérateur est précédé d'un opérande (identifiant, '.',
# ')', ']') — hérite de la logique de ``_ARITH_PATTERN`` d'arithmetic.py.
_OP_PATTERNS = {
    "+": re.compile(r"[\w.\]\)]\s*\+"),
    "-": re.compile(r"[\w.\]\)]\s*-"),
    "*": re.compile(r"[\w.\]\)]\s*\*"),
}

_COMMENT_PREFIXES = ("//", "*", "/*")

# Une ligne Solidity peut contenir plusieurs instructions (ex. library déclarée
# sur une seule ligne). On découpe sur les séparateurs d'instructions pour
# isoler l'assignation arithmétique réelle.
_STATEMENT_SEPARATORS = re.compile(r"[;{}]")


def _candidate_lines(source: str, variable: str, operation: str) -> list:
    """Lignes réelles contenant ``variable`` ET l'opérateur ``operation``.

    Retourne une liste ``[(numéro_de_ligne, texte_de_la_ligne), ...]``.
    """
    op_re = _OP_PATTERNS.get(operation)
    if op_re is None or not variable:
        return []

    var_re = re.compile(r"\b" + re.escape(variable) + r"\b")
    candidates = []
    for idx, raw_line in enumerate(source.split("\n"), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(_COMMENT_PREFIXES):
            continue
        if not var_re.search(stripped):
            continue
        if not op_re.search(stripped):
            continue
        candidates.append((idx, stripped))
    return candidates


def _isolate_assignment(line_text: str, variable: str, operation: str) -> tuple:
    """Isole l'assignation arithmétique stricte dans une ligne de code.

    Retourne ``(snippet, count)`` :
      - ``snippet`` : la seule instruction d'assignation impliquant ``variable``
        et l'opérateur ``operation`` (terminée par ``;``), ou ``None`` si aucune.
      - ``count``   : nombre d'assignations candidates trouvées sur la ligne
        (``> 1`` = ambigu). Une ligne comme
        ``library SafeMath { ... { c = a + b; require(c >= a); } }`` doit
        produire ``"c = a + b;"`` et non la déclaration complète.
    """
    op_re = _OP_PATTERNS.get(operation)
    if op_re is None or not variable:
        return None, 0

    var_re = re.compile(r"\b" + re.escape(variable) + r"\b")
    matches = []
    for statement in _STATEMENT_SEPARATORS.split(line_text):
        stmt = statement.strip()
        if not stmt or "=" not in stmt:
            continue
        if re.search(r"(==|!=|<=|>=)", stmt):
            continue
        if not var_re.search(stmt):
            continue
        if not op_re.search(stmt):
            continue
        matches.append(stmt.rstrip(";").strip() + ";")

    if not matches:
        return None, 0
    return matches[0], len(matches)


def anchor_hypothesis(hypothesis: dict, source: str) -> dict:
    """Recoupe une hypothèse Nemotron avec le texte source réel.

    Retourne une copie de l'hypothèse enrichie de :
      - ``anchor_status`` : ``"ANCRAGE_OK"`` ou ``"ANCRAGE_ECHOUE"``
      - ``nemotron_line`` : numéro rapporté par le modèle (conservé pour comparaison)
      - ``anchor_lines``  : lignes réelles candidates trouvées
      - ``resolved_line`` : ligne réellement retenue (uniquement si ANCRAGE_OK)
      - ``snippet_isolated`` : True si le snippet est l'assignation stricte isolée
      - ``z3_finding``    : finding prêt pour ``prove_overflow()`` (uniquement si ANCRAGE_OK)
    """
    variable = str(hypothesis.get("variable", "") or "").strip()
    operation = str(hypothesis.get("operation", "") or "").strip()
    candidates = _candidate_lines(source, variable, operation)

    enriched = {
        **hypothesis,
        "nemotron_line": hypothesis.get("line"),
        "anchor_lines": [line_no for line_no, _ in candidates],
        "resolved_line": None,
        "snippet_isolated": False,
        "z3_finding": None,
    }

    if len(candidates) != 1:
        enriched["anchor_status"] = "ANCRAGE_ECHOUE"
        enriched["anchor_reason"] = (
            "aucune ligne ne contient cette variable avec cet opérateur"
            if not candidates
            else f"ambiguïté : {len(candidates)} lignes candidates {enriched['anchor_lines']}"
        )
        return enriched

    line_no, line_text = candidates[0]
    snippet, statement_count = _isolate_assignment(line_text, variable, operation)

    if statement_count > 1:
        enriched["anchor_status"] = "ANCRAGE_ECHOUE"
        enriched["anchor_reason"] = (
            f"ambiguïté : {statement_count} assignations candidates sur la ligne {line_no}"
        )
        return enriched

    enriched["anchor_status"] = "ANCRAGE_OK"
    enriched["anchor_reason"] = "correspondance unique"
    enriched["resolved_line"] = line_no
    # Si aucune assignation stricte n'a pu être isolée, on transmet la ligne
    # entière : Z3 la rejettera en UNPARSED (verdict honnête) plutôt que de
    # faire croire à une preuve.
    enriched["snippet_isolated"] = snippet is not None
    enriched["z3_finding"] = {
        "rule_id": "SOL-004",
        "line": line_no,
        "snippet": snippet if snippet is not None else line_text[:200],
    }
    return enriched


def anchor_hypotheses(hypotheses: list, source: str) -> list:
    """Applique :func:`anchor_hypothesis` à chaque hypothèse d'une liste."""
    return [anchor_hypothesis(h, source) for h in (hypotheses or [])]
