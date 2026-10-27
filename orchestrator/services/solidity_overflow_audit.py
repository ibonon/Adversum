"""Audit SOL-004 bout-en-bout : Nemotron (réel) -> ancrage -> Z3, avec repli regex.

Chaîne de traitement par fichier Solidity :

  1. ``generate_overflow_hypotheses()`` demande à Nemotron les opérations
     arithmétiques à risque sur le code **brut** ;
  2. ``anchor_hypotheses()`` recoupe chaque hypothèse avec le texte source réel
     (jamais la ligne rapportée par le modèle) ;
  3. chaque hypothèse ancrée est soumise à Z3 (``prove_finding_in_source``) qui
     rend un verdict SAT / UNSAT / UNPARSED.

Provenance explicite par finding :
  - ``nemotron``       : hypothèse du modèle, ancrée puis vérifiée par Z3 ;
  - ``regex_fallback`` : Nemotron indisponible/échec réel -> repli sur la règle
                         statique ``arithmetic.py``, vérifiée par Z3.

Un échec réel de l'appel Nemotron (``NebiusOverflowGenerationError``) est
journalisé et déclenche le repli regex ; il n'est jamais déguisé en « 0 finding ».
"""

import logging
from pathlib import Path
from typing import Dict, List

from orchestrator.services import nebius_llm as nb
from modules.solidity.overflow_anchor import anchor_hypotheses
from modules.solidity.rules import arithmetic
from modules.formal_verification import z3_prover as z3p

logger = logging.getLogger("adversum.solidity.sol004")

# Correspondance verdict Z3 -> statut de validation persisté.
_VERDICT_TO_STATUS = {
    "SAT": "CONFIRMED",
    "UNSAT": "REJECTED",
    "UNPARSED": "SUSPICIOUS",
    "UNKNOWN": "SUSPICIOUS",
}


def _verify(snippet: str, line, content: str) -> dict:
    """Soumet un snippet isolé à Z3, largeur/bornes/garde déduites du contexte."""
    return z3p.prove_finding_in_source(
        {"rule_id": "SOL-004", "line": line, "snippet": snippet}, content
    )


def _record(
    *,
    line,
    snippet,
    provenance: str,
    anchor_status: str,
    anchor_reason: str,
    nemotron_line,
    variable,
    operation,
    z3_res: dict = None,
) -> dict:
    """Construit un finding SOL-004 homogène (provenance + verdict Z3 inclus)."""
    verdict = z3_res["verdict"] if z3_res else None
    exploitable = z3_res["exploitable"] if z3_res else None
    proof = z3_res["proof"] if z3_res else ""

    if verdict is None:
        message = (
            f"SOL-004 — hypothèse Nemotron ({variable} {operation}) non vérifiable : "
            f"ancrage impossible sur le source ({anchor_reason})."
        )
    else:
        message = (
            f"SOL-004 — overflow/underflow (provenance={provenance}) : verdict Z3 {verdict}."
        )

    notes = (
        f"provenance={provenance}; z3_verdict={verdict or 'N/A'}; "
        f"anchor_status={anchor_status}; nemotron_line={nemotron_line}; "
        f"operation={operation}; {anchor_reason}"
    )
    if proof:
        notes += f"; z3_proof={proof}"

    return {
        "rule_id": "SOL-004",
        "line": line,
        # Ligne réellement ancrée : None si l'ancrage a échoué (jamais devinée).
        "resolved_line": line if anchor_status == "ANCRAGE_OK" else None,
        "snippet": snippet,
        "provenance": provenance,
        "anchor_status": anchor_status,
        "anchor_reason": anchor_reason,
        "nemotron_line": nemotron_line,
        "z3_verdict": verdict,
        "z3_exploitable": exploitable,
        "message": message,
        "reasoning_notes": notes,
        "validation_status": _VERDICT_TO_STATUS.get(verdict, "PENDING"),
        "ai_confidence": 1.0 if verdict == "SAT" else 0.0,
        "proof_anchor": proof or None,
    }


async def audit_solidity_source(source: str, file_path: str) -> List[Dict]:
    """Retourne les findings SOL-004 d'une source Solidity (provenance + verdict Z3)."""
    if not (source or "").strip():
        return []

    provenance = "nemotron"
    try:
        hypotheses = await nb.generate_overflow_hypotheses(source, file_path=file_path)
        anchored = anchor_hypotheses(hypotheses, source)
    except nb.NebiusOverflowGenerationError as e:
        # Échec réel signalé et repli explicite — jamais masqué en « 0 finding ».
        logger.warning(
            "[SOL-004] Nemotron indisponible/échec réel pour %s — repli regex : %s",
            file_path,
            e,
        )
        provenance = "regex_fallback"
        anchored = [
            {
                "anchor_status": "ANCRAGE_OK",
                "anchor_reason": "détection par la règle statique arithmetic.py",
                "nemotron_line": None,
                "resolved_line": f["line"],
                "variable": None,
                "operation": None,
                "z3_finding": {
                    "rule_id": "SOL-004",
                    "line": f["line"],
                    "snippet": f["snippet"],
                },
            }
            for f in arithmetic.analyze(source)
        ]

    findings = []
    for a in anchored:
        if a["anchor_status"] != "ANCRAGE_OK":
            findings.append(
                _record(
                    # Ligne 0 = ancrage inconnu : on ne persiste JAMAIS le numéro
                    # (non fiable) rapporté par le modèle comme position vérifiée.
                    line=0,
                    snippet="",
                    provenance=provenance,
                    anchor_status=a["anchor_status"],
                    anchor_reason=a.get("anchor_reason", ""),
                    nemotron_line=a.get("nemotron_line"),
                    variable=a.get("variable"),
                    operation=a.get("operation"),
                    z3_res=None,
                )
            )
            continue

        finding = a["z3_finding"]
        z3_res = _verify(finding["snippet"], finding["line"], source)
        findings.append(
            _record(
                line=finding["line"],
                snippet=finding["snippet"],
                provenance=provenance,
                anchor_status="ANCRAGE_OK",
                anchor_reason=a.get("anchor_reason", ""),
                nemotron_line=a.get("nemotron_line"),
                variable=a.get("variable"),
                operation=a.get("operation"),
                z3_res=z3_res,
            )
        )
    return findings


async def audit_solidity_path(real_path: str) -> List[Dict]:
    """Parcourt ``real_path`` (fichier ou dossier) et audite chaque ``*.sol``."""
    root = Path(real_path)
    if root.is_file():
        sol_files = [root] if root.suffix.lower() == ".sol" else []
    else:
        sol_files = sorted(root.rglob("*.sol"))

    all_findings = []
    for sol in sol_files:
        try:
            source = sol.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning("[SOL-004] Lecture impossible de %s : %s", sol, e)
            continue
        file_findings = await audit_solidity_source(source, str(sol))
        for f in file_findings:
            f["file_path"] = str(sol)
        all_findings.extend(file_findings)
    return all_findings
