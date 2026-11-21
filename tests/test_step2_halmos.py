"""Step 2 — Halmos witnesses for the provable subset (real execution).

Skipped (never faked) when forge/halmos are unavailable. A vulnerable
harness must yield PROVEN + a concrete witness; the safe counterpart
must never yield a false PROVEN; a missing toolchain must yield
UNKNOWN/unavailable, not silence.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from modules.halmos.runner import (  # noqa: E402
    halmos_available,
    halmos_result_to_verdict,
    run_halmos_harness,
)
from orchestrator.models.findings import (  # noqa: E402
    ProofVerdict,
    Witness,
    classify_proof_verdict,
)

_BINS = halmos_available()
requires_halmos = pytest.mark.skipif(
    not (_BINS.get("halmos") and _BINS.get("forge")),
    reason=f"forge/halmos unavailable: {_BINS}",
)


def test_unavailable_maps_to_unknown_never_safe():
    fragment = halmos_result_to_verdict({"status": "timeout", "error": "exceeded 180s"})
    assert fragment["proof_verdict"] == "UNKNOWN"
    assert fragment["witness"] is None
    fragment = halmos_result_to_verdict({"status": "unavailable", "error": "not found"})
    assert fragment["proof_verdict"] == "UNKNOWN"


def test_halmos_witness_classifies_proven_only_with_evidence():
    empty = Witness(kind="halmos_counterexample", solver="halmos")
    assert classify_proof_verdict(witness=empty) == ProofVerdict.DETECTED_UNPROVEN
    real = Witness(kind="halmos_counterexample", solver="halmos",
                   entry_point="check_vulnerable_add_no_overflow",
                   call_path=["check_vulnerable_add_no_overflow", "OverflowVulnerable.add"],
                   counterexample={"amount": 2**255})
    assert classify_proof_verdict(witness=real) == ProofVerdict.PROVEN


@requires_halmos
@pytest.mark.parametrize("rule_id", ["SOL-004", "SOL-001", "SOL-012", "SOL-007", "SOL-002"])
def test_vulnerable_harness_yields_counterexample(rule_id):
    result = run_halmos_harness(rule_id, timeout=300)
    assert result["status"] == "counterexample", f"{rule_id}: {result}"
    fragment = halmos_result_to_verdict(result)
    assert fragment["proof_verdict"] == "PROVEN"
    assert fragment["witness"]["kind"] == "halmos_counterexample"
    assert fragment["witness"]["call_path"], "witness must carry the explored path"


SIMPLE_DAO_04 = """pragma solidity ^0.4.2;
contract SimpleDAO {
  mapping (address => uint) public credit;
  function donate(address to) payable { credit[to] += msg.value; }
  function withdraw(uint amount) {
    if (credit[msg.sender] >= amount) {
      bool res = msg.sender.call.value(amount)();
      credit[msg.sender] -= amount;
    }
  }
}
"""


@requires_halmos
def test_per_contract_halmos_proves_actual_old_contract():
    from modules.halmos.per_contract import run_per_contract
    from modules.solidity.rules import reentrancy

    findings = reentrancy.analyze(SIMPLE_DAO_04)
    assert findings, "CEI rule must find the reentrancy first"
    res = run_per_contract(SIMPLE_DAO_04, findings[0], timeout=300)
    assert res["proof_verdict"] == "PROVEN", res
    assert res["witness"]["kind"] == "halmos_counterexample"
    assert res["witness"]["counterexample"]["contract"] == "SimpleDAO"


UNCHECKED_08 = """pragma solidity ^0.8.20;
contract Failing { receive() external payable { revert("no"); } }
contract Pay {
    bool public paid;
    function pay(address target) public {
        target.call{value: 1}("");
        paid = true;
    }
}
"""


@requires_halmos
def test_per_contract_rules_dispatch_and_honest_unknown():
    from modules.halmos.per_contract_rules import run_per_contract_rule

    res = run_per_contract_rule("SOL-007", UNCHECKED_08,
                                {"rule_id": "SOL-007", "line": 6, "snippet": 'target.call{value: 1}("");'},
                                timeout=300)
    assert res["proof_verdict"] in ("PROVEN", "DETECTED_UNPROVEN", "UNKNOWN")
    if res["halmos"].get("status") == "counterexample":
        assert res["proof_verdict"] == "PROVEN"
    # Unsupported rule / shape must be UNKNOWN, never fabricated.
    bad = run_per_contract_rule("SOL-004", UNCHECKED_08,
                                {"rule_id": "SOL-004", "line": 6, "snippet": "x = x + y;"}, timeout=60)
    assert bad["proof_verdict"] == "UNKNOWN"


@requires_halmos
def test_sol003_selfdestruct_is_unknown_not_faked():
    """Halmos 0.3.3 cannot symbolically execute SELFDESTRUCT.

    Requalified in Step 2: the engine error must surface as UNKNOWN,
    never as a fabricated PROVEN or a silent pass.
    """
    result = run_halmos_harness("SOL-003", timeout=300)
    assert result["status"] in ("error", "timeout", "unavailable")
    fragment = halmos_result_to_verdict(result)
    assert fragment["proof_verdict"] == "UNKNOWN"
    assert fragment["witness"] is None
