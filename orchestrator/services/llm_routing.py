"""LLM routing, G-ASR context and output-schema enforcement (P2).

Frontier-grade usage of the LLM means: a fast model triages, a strong
model verifies, the prompt carries real graph context (enclosing
function, state variables, call/write ordering — not a 300-char
snippet), and the answer is validated against a schema before anyone
trusts it. Recorded-hypothesis evaluation lives in
``benchmarks/run_llm_eval.py``.
"""
from __future__ import annotations

import os
import re

TRIAGE_MODEL_DEFAULT = "nvidia/Nemotron-3_5-Lightning"
VERIFY_MODEL_DEFAULT = "nvidia/nemotron-3-super-120b-a12b"
ULTRA_MODEL = "nvidia/Nemotron-3-Ultra-550b-a55b"

VALIDATION_SCHEMA = {
    "type": "object",
    "required": ["is_true_positive", "confidence", "ai_explanation", "ai_remediation", "cwe_reference"],
    "properties": {
        "is_true_positive": {"type": "boolean"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "ai_explanation": {"type": "string", "minLength": 1},
        "ai_remediation": {"type": "string"},
        "attack_scenario": {"type": "string"},
        "cwe_reference": {"type": "string", "pattern": "^CWE-\\d+$"},
    },
}


def get_model_for_task(task: str) -> str:
    """Route by task: triage -> Lightning, verification -> strong model.

    Overrides: ``ADVERSUM_LLM_TRIAGE_MODEL``, ``ADVERSUM_LLM_VERIFY_MODEL``
    (set the latter to the Ultra id for frontier verification), then
    ``NEBIUS_MODEL`` for backwards compatibility.
    """
    if task in ("verification", "verify", "executive_summary"):
        return (
            os.getenv("ADVERSUM_LLM_VERIFY_MODEL")
            or os.getenv("NEBIUS_MODEL")
            or VERIFY_MODEL_DEFAULT
        )
    # Triage never inherits the global/verification model: speed first.
    return os.getenv("ADVERSUM_LLM_TRIAGE_MODEL") or TRIAGE_MODEL_DEFAULT


def validate_validation_payload(data) -> tuple:
    """Validate an LLM validation payload against VALIDATION_SCHEMA.

    Returns ``(ok, errors)``. No external jsonschema dependency: the
    schema is small and the checks are explicit and auditable.
    """
    errors = []
    if not isinstance(data, dict):
        return False, ["payload is not an object"]
    for key in VALIDATION_SCHEMA["required"]:
        if key not in data:
            errors.append(f"missing required key: {key}")
    if "is_true_positive" in data and not isinstance(data["is_true_positive"], bool):
        errors.append("is_true_positive must be boolean")
    conf = data.get("confidence")
    if conf is not None and (not isinstance(conf, (int, float)) or not 0 <= float(conf) <= 1):
        errors.append("confidence must be a number in [0, 1]")
    cwe = data.get("cwe_reference")
    if cwe is not None and not re.match(r"^CWE-\d+$", str(cwe)):
        errors.append("cwe_reference must match CWE-<digits>")
    for key in ("ai_explanation",):
        if key in data and (not isinstance(data[key], str) or not data[key].strip()):
            errors.append(f"{key} must be a non-empty string")
    return not errors, errors


def build_gasr_context(finding: dict, source: str, max_chars: int = 4000) -> str:
    """Graph-augmented context for a finding (G-ASR, P2).

    Includes the enclosing function (header, params, state vars it can
    touch), external-call/state-write ordering and require guards —
    the facts a verifier needs — instead of an isolated snippet.
    """
    if not source:
        return (finding.get("snippet") or "")[:max_chars]
    try:
        from modules.solidity.function_parser import (
            external_calls_in,
            function_at,
            parse_source,
            state_writes_in,
        )
        lines, _contracts, functions = parse_source(source)
        fn = function_at(functions, int(finding.get("line") or finding.get("resolved_line") or 0))
        if fn is None:
            return (finding.get("snippet") or "")[:max_chars]
        body = lines[fn.body_start - 1:fn.end_line]
        calls = external_calls_in(body, fn.body_start)
        writes = state_writes_in(fn, body, fn.body_start)
        state_vars = sorted(getattr(fn, "state_vars", set()) or set())
        parts = [
            f"Function: {fn.header.strip()[:200]}",
            f"State variables in scope: {', '.join(state_vars) or '(none parsed)'}",
            "External calls (line): " + ("; ".join(f"{ln}: {tx[:80]}" for ln, tx, _v in calls) or "(none)"),
            "State writes (line): " + ("; ".join(f"{ln}: {tx[:80]}" for ln, _b, tx in writes) or "(none)"),
            "Function source:",
            "\n".join(body),
        ]
        return "\n".join(parts)[:max_chars]
    except Exception:
        return (finding.get("snippet") or "")[:max_chars]
