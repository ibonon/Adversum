from __future__ import annotations

import json
from typing import Any


def _core():
    import adversum_core

    return adversum_core


def verify_invariant_smt(ir_json: str, invariant_type: str) -> Any:
    return _core().verify_invariant_smt(ir_json, invariant_type)


def prove_contract_safety(solidity_code: str) -> Any:
    return _core().prove_contract_safety(solidity_code)


def format_report(report: Any) -> str:
    if hasattr(report, "proofs"):
        payload = {
            "overall_status": getattr(report, "overall_status", "unknown"),
            "proofs": [
                {
                    "invariant_type": proof.invariant_type,
                    "status": proof.status,
                    "proved": proof.proved,
                    "checked_obligations": proof.checked_obligations,
                    "counterexample": proof.counterexample,
                    "details": proof.details,
                }
                for proof in report.proofs
            ],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    payload = {
        "invariant_type": getattr(report, "invariant_type", "unknown"),
        "status": getattr(report, "status", "unknown"),
        "proved": getattr(report, "proved", False),
        "checked_obligations": getattr(report, "checked_obligations", 0),
        "counterexample": getattr(report, "counterexample", None),
        "details": getattr(report, "details", None),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
