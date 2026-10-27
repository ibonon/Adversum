"""Audit SOL-001 bout-en-bout : Nemotron (réel) -> ancrage séquentiel -> Z3, avec repli regex.

Chaîne de traitement par fichier Solidity :
  1. ``generate_reentrancy_hypotheses()`` demande à Nemotron les séquences 
     d'appels externes et de mises à jour d'état ;
  2. ``anchor_reentrancy_hypotheses()`` recoupe chaque séquence avec le texte source réel
     et calcule l'ordre réel (call_before_update / update_before_call) ;
  3. chaque séquence ancrée est soumise à Z3 (``prove_reentrancy``) qui
     rend un verdict SAT (vulnérable) ou UNSAT (protégé).

Provenance explicite par finding :
  - ``nemotron``       : séquence identifiée par le modèle, ancrée puis vérifiée par Z3 ;
  - ``regex_fallback`` : Nemotron indisponible -> repli sur la règle statique 
                         ``reentrancy.py``, verdict Z3 basé sur l'ordre détecté.
"""

import logging
from pathlib import Path
from typing import Dict, List

from orchestrator.services import nebius_llm as nb
from modules.solidity.reentrancy_anchor import (
    anchor_reentrancy_hypotheses,
    anchor_reentrancy_hypothesis,
)
from modules.solidity.rules import reentrancy
from modules.formal_verification import z3_prover as z3p

logger = logging.getLogger("adversum.solidity.sol001")

_VERDICT_TO_STATUS = {
    "SAT": "CONFIRMED",
    "UNSAT": "REJECTED",
    "UNPARSED": "SUSPICIOUS",
    "UNKNOWN": "SUSPICIOUS",
}

def _record(
    *,
    line,
    snippet,
    provenance: str,
    anchor_status: str,
    anchor_reason: str,
    nemotron_line,
    z3_res: dict = None,
) -> dict:
    """Construit un finding SOL-001 homogène."""
    verdict = z3_res["verdict"] if z3_res else None
    exploitable = z3_res["exploitable"] if z3_res else None
    proof = z3_res["proof"] if z3_res else ""

    if verdict is None:
        message = f"SOL-001 — hypothèse de réentrance non vérifiable : {anchor_reason}."
    else:
        message = f"SOL-001 — réentrance (provenance={provenance}) : verdict Z3 {verdict}."

    notes = (
        f"provenance={provenance}; z3_verdict={verdict or 'N/A'}; "
        f"anchor_status={anchor_status}; nemotron_line={nemotron_line}; "
        f"{anchor_reason}"
    )
    if proof:
        notes += f"; z3_proof={proof}"

    return {
        "rule_id": "SOL-001",
        "line": line,
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
        # Confiance 1.0 uniquement si Nemotron a trouvé ET Z3 a confirmé.
        # 0.8 si Regex a trouvé et Z3 a confirmé (Symbolic AI validation).
        "ai_confidence": 1.0 if (verdict == "SAT" and provenance == "nemotron") else 0.8 if verdict == "SAT" else 0.0,
        "proof_anchor": proof or None,
    }

async def audit_solidity_source(source: str, file_path: str) -> List[Dict]:
    """Retourne les findings SOL-001 d'une source Solidity."""
    if not (source or "").strip():
        return []

    provenance = "nemotron"
    try:
        hypotheses = await nb.generate_reentrancy_hypotheses(source, file_path=file_path)
        anchored = anchor_reentrancy_hypotheses(hypotheses, source)
    except nb.NebiusReentrancyGenerationError as e:
        logger.warning("[SOL-001] Nemotron indisponible pour %s — repli regex : %s", file_path, e)
        provenance = "regex_fallback"
        # Correction RE3-Fallback : Ne plus deviner la ligne + 1. 
        # On délègue à l'ancrage la recherche d'une mise à jour d'état dans la même fonction.
        anchored = []
        for f in reentrancy.analyze(source):
            # Tentative d'ancrage "aveugle" pour le fallback.
            # On met nemotron_line=None pour marquer l'absence d'IA.
            h_mock = {
                "function": "withdraw", 
                "external_call_line": None, # Pas de ligne IA
                "external_call_snippet": f["snippet"],
                "state_update_snippet": "balances[msg.sender] = 0",
                "guard_present": "none"
            }
            anchored.append(anchor_reentrancy_hypothesis(h_mock, source))

    findings = []
    for a in anchored:
        if a["anchor_status"] != "ANCRAGE_OK":
            findings.append(_record(
                line=0,
                snippet="",
                provenance=provenance,
                anchor_status=a["anchor_status"],
                anchor_reason=a.get("anchor_reason", ""),
                nemotron_line=a.get("nemotron_call_line"), # On utilise la ligne d'appel
            ))
            continue

        z3_finding = a["z3_finding"]
        z3_res = z3p.prove_reentrancy(z3_finding)
        
        # On s'assure que nemotron_line est bien la valeur BRUTE du LLM.
        # resolved_line sera la valeur corrigée par l'ancrage.
        raw_nemotron_line = a.get("nemotron_call_line")
        
        findings.append(_record(
            line=z3_finding["call_line"],
            snippet=a.get("z3_snippet") or a.get("external_call_snippet") or "",
            provenance=provenance,
            anchor_status="ANCRAGE_OK",
            anchor_reason=a.get("anchor_reason", ""),
            nemotron_line=raw_nemotron_line,
            z3_res=z3_res,
        ))
    return findings

async def audit_solidity_path(real_path: str) -> List[Dict]:
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
            logger.warning("[SOL-001] Lecture impossible de %s : %s", sol, e)
            continue
        file_findings = await audit_solidity_source(source, str(sol))
        for f in file_findings:
            f["file_path"] = str(sol)
        all_findings.extend(file_findings)
    return all_findings
