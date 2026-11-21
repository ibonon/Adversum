"""Step 1 — three-state proof verdicts with mandatory witness.

Guarantees under test:
- PROVEN is impossible without an attached witness (model downgrades).
- Representability alone (Z3 SAT, not reachable) is never PROVEN.
- UNPARSED / failed anchoring is UNKNOWN, never a safety claim.
- Solidity audits emit the three states distinctly.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "modules" / "solidity"))

from orchestrator.models.findings import (  # noqa: E402
    ProofVerdict,
    RawFinding,
    Severity,
    ValidatedFinding,
    Witness,
    classify_proof_verdict,
)


def _validated(**kw):
    return ValidatedFinding(
        raw=RawFinding(id="SOL-004", message="m", severity=Severity.HIGH,
                       file_path="x.sol", line=1, snippet="t = t + a;"),
        **kw,
    )


def test_proven_without_witness_is_downgraded():
    f = _validated(proof_verdict=ProofVerdict.PROVEN, witness=None)
    assert f.proof_verdict == ProofVerdict.DETECTED_UNPROVEN
    assert "downgraded" in f.verdict_reason


def test_proven_with_witness_is_kept():
    w = Witness(kind="z3_counterexample", solver="z3", entry_point="add",
                call_path=["add", "line 1"], counterexample={"a": 1}, scope="single-function")
    f = _validated(proof_verdict=ProofVerdict.PROVEN, witness=w)
    assert f.proof_verdict == ProofVerdict.PROVEN


def test_classifier_matrix():
    w = Witness(kind="z3_counterexample", solver="z3")
    assert classify_proof_verdict(z3_verdict="SAT", reachable=True, witness=w) == ProofVerdict.PROVEN
    # Representability alone is not a proof of existence.
    assert classify_proof_verdict(z3_verdict="SAT", reachable=False, witness=w) == ProofVerdict.DETECTED_UNPROVEN
    assert classify_proof_verdict(z3_verdict="SAT", reachable=True, witness=None) == ProofVerdict.DETECTED_UNPROVEN
    assert classify_proof_verdict(z3_verdict="UNPARSED") == ProofVerdict.UNKNOWN
    assert classify_proof_verdict(z3_verdict="SAT", reachable=True, witness=w,
                                   anchor_status="ANCRAGE_ECHOUE") == ProofVerdict.UNKNOWN
    assert classify_proof_verdict(validation_status="REJECTED") == ProofVerdict.UNKNOWN
    assert classify_proof_verdict() == ProofVerdict.DETECTED_UNPROVEN


@pytest.mark.asyncio
async def test_overflow_audit_verdicts_are_distinct():
    from orchestrator.services.solidity_overflow_audit import audit_solidity_source

    # Nemotron unavailable in tests -> regex fallback + Z3 reachable path.
    import orchestrator.services.nebius_llm as nb
    if nb._is_available() and not nb._is_demo_mode():
        pytest.skip("live Nebius configured; fallback path not exercised")
    src = (
        "pragma solidity ^0.7.0;\n"
        "contract T {\n"
        "    uint256 public total;\n"
        "    function add(uint256 amount) public {\n"
        "        total = total + amount;\n"
        "    }\n"
        "}\n"
    )
    findings = await audit_solidity_source(src, "T.sol")
    assert findings, "expected an overflow finding on the fallback path"
    for f in findings:
        assert f["proof_verdict"] in ("PROVEN", "DETECTED_UNPROVEN", "UNKNOWN")
        if f["proof_verdict"] == "PROVEN":
            assert f["witness"], "PROVEN must carry a witness"
            assert f["witness"]["counterexample"], "witness must carry a counterexample"
        if f["z3_verdict"] == "UNPARSED":
            assert f["proof_verdict"] == "UNKNOWN"
