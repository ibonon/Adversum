"""Ancrage séquentiel pour la réentrance (SOL-001).

Contrairement à l'overflow, la réentrance nécessite d'ancrer deux points :
1. L'appel externe (external call).
2. La mise à jour d'état (state update).

Ce module vérifie que les deux existent dans la même fonction et calcule leur
ordre réel dans le code source pour confirmer l'hypothèse Nemotron.
"""
from __future__ import annotations
import re

# Patterns pour identifier les appels externes
_CALL_PATTERNS = [
    re.compile(r'\.call\s*\{'),
    re.compile(r'\.transfer\s*\('),
    re.compile(r'\.send\s*\('),
]

def _normalize(text: str) -> str:
    """Normalise un snippet pour la comparaison (espaces, guillemets)."""
    if not text:
        return ""
    # Remplace les guillemets simples par des doubles pour uniformiser
    text = text.replace("'", '"')
    # Supprime les points-virgules parasites en fin de ligne
    text = text.rstrip(';').strip()
    # Supprime les espaces superflus
    return " ".join(text.split())

def _find_function_scope(source: str, function_name: str) -> tuple[int, int] | None:
    """Trouve le début et la fin approximative d'une fonction."""
    lines = source.split('\n')
    func_pattern = re.compile(r'\bfunction\s+' + re.escape(function_name) + r'\b')
    
    start_line = -1
    for i, line in enumerate(lines):
        if func_pattern.search(line):
            start_line = i
            break
            
    if start_line == -1:
        return None
        
    # Trouve la fin de la fonction (prochain mot-clé function ou fin de fichier)
    # Note : C'est une approximation, mais suffisante pour l'ancrage LLM.
    end_line = len(lines)
    for i in range(start_line + 1, len(lines)):
        if re.search(r'\bfunction\s+\w+\b', lines[i]) or re.search(r'\bmodifier\s+\w+\b', lines[i]):
            end_line = i
            break
            
    return start_line + 1, end_line

def anchor_reentrancy_hypothesis(hypothesis: dict, source: str) -> dict:
    """Recoupe une hypothèse de réentrance avec le texte source réel.
    
    Calcule l'ordre réel (call_before_update / update_before_call) basé sur
    les lignes trouvées dans le fichier.
    """
    func_name = hypothesis.get("function", "")
    scope = _find_function_scope(source, func_name)
    
    enriched = {
        **hypothesis,
        "nemotron_call_line": hypothesis.get("external_call_line"),
        "nemotron_update_line": hypothesis.get("state_update_line"),
        "resolved_call_line": None,
        "resolved_update_line": None,
        "actual_order": "unknown",
        "anchor_status": "ANCRAGE_ECHOUE"
    }
    
    if not scope:
        enriched["anchor_reason"] = f"fonction '{func_name}' introuvable"
        return enriched
        
    start, end = scope
    lines = source.split('\n')
    scope_lines = lines[start-1:end]
    
    call_snippet = _normalize(hypothesis.get("external_call_snippet", ""))
    update_snippet = _normalize(hypothesis.get("state_update_snippet", ""))
    
    # Recherche de l'appel externe dans le scope
    found_call_line = -1
    for i, line in enumerate(scope_lines, start=start):
        norm_line = _normalize(line)
        if call_snippet and call_snippet in norm_line:
            found_call_line = i
            break
        # Fallback sur pattern si le snippet est trop différent
        if any(p.search(line) for p in _CALL_PATTERNS) and not call_snippet:
             found_call_line = i
             break

    # Recherche de la mise à jour d'état dans le scope
    found_update_line = -1
    for i, line in enumerate(scope_lines, start=start):
        norm_line = _normalize(line)
        if update_snippet and update_snippet in norm_line:
            found_update_line = i
            break

    if found_call_line == -1 or found_update_line == -1:
        reasons = []
        if found_call_line == -1: reasons.append("appel externe introuvable")
        if found_update_line == -1: reasons.append("mise à jour d'état introuvable")
        enriched["anchor_reason"] = " / ".join(reasons)
        return enriched

    enriched["resolved_call_line"] = found_call_line
    enriched["resolved_update_line"] = found_update_line
    enriched["actual_order"] = "call_before_update" if found_call_line < found_update_line else "update_before_call"
    enriched["anchor_status"] = "ANCRAGE_OK"
    enriched["anchor_reason"] = "séquence ancrée avec succès"
    
    # Préparation pour Z3 (RE4)
    enriched["z3_finding"] = {
        "rule_id": "SOL-001",
        "function": func_name,
        "call_line": found_call_line,
        "update_line": found_update_line,
        "is_vulnerable_order": enriched["actual_order"] == "call_before_update",
        "guard_present": hypothesis.get("guard_present", "none")
    }
    
    return enriched

def anchor_reentrancy_hypotheses(hypotheses: list, source: str) -> list:
    return [anchor_reentrancy_hypothesis(h, source) for h in (hypotheses or [])]
