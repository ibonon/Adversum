"""P0/P1 regression tests: scoped guards, CEI, Z3 chain/binding, benchmark.

These encode the frontier-gap fixes: file-scoped guards must not hide
vulnerabilities in sibling functions, CEI-safe code must not be flagged,
Z3 must model multi-operand and mixed-width arithmetic, an UNSAT
verdict must suppress the finding, and the bundled benchmark corpus
must stay reproducible offline.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "modules" / "solidity"))

from modules.solidity.rules import arithmetic, reentrancy  # noqa: E402
from modules.formal_verification.z3_prover import (  # noqa: E402
    apply_z3_binding,
    prove_overflow,
    prove_overflow_reachable,
)

MIXED_GUARDS = """pragma solidity ^0.8.0;
contract Mixed {
    mapping(address => uint256) public balances;
    bool private locked;
    modifier noReenter() { require(!locked); locked = true; _; locked = false; }
    function safeWithdraw(uint256 amount) public noReenter {
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
    function vulnWithdraw(uint256 amount) public {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"""

SAFEMATH_SCOPE = """pragma solidity ^0.7.0;
contract Scoped {
    using SafeMath for uint256;
    uint256 public total;
    function safe(uint256 a) public { total = total.add(a); }
    function unsafeOp(uint256 x) public { total = total + x; }
}
"""


def test_guard_is_function_scoped_not_file_scoped():
    findings = reentrancy.analyze(MIXED_GUARDS)
    funcs = {f.get("function") for f in findings}
    assert "vulnWithdraw" in funcs
    assert "safeWithdraw" not in funcs


def test_safemath_using_does_not_hide_bare_arithmetic():
    findings = arithmetic.analyze(SAFEMATH_SCOPE)
    snippets = " ".join(f["snippet"] for f in findings)
    assert "total + x" in snippets
    assert ".add(a)" not in snippets


def test_cei_safe_order_is_not_flagged():
    src = """pragma solidity ^0.8.0;
contract Safe {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
"""
    assert reentrancy.analyze(src) == []


def test_z3_multi_operand_and_mixed_width():
    chain = prove_overflow({"rule_id": "SOL-004", "line": 1, "snippet": "a = a + b + c;"})
    assert chain["verdict"] == "SAT"
    assert set(chain["counterexample"]) == {"a", "b", "c"}
    mixed = prove_overflow(
        {"rule_id": "SOL-004", "line": 1, "snippet": "s = s + b;"},
        operand_widths={"s": 8, "b": 256},
    )
    assert mixed["verdict"] == "SAT"
    assert mixed["counterexample"]["s"] <= 255


def test_z3_binding_unsat_suppresses_and_reachability():
    src = "pragma solidity ^0.8.0; contract T { uint256 public t; function add(uint256 a) public { t = t + a; } }"
    kept, suppressed = apply_z3_binding(
        [{"rule_id": "SOL-004", "line": 1, "snippet": "t = t + a;", "file": "x.sol"}],
        {"x.sol": src},
    )
    assert kept == [] and len(suppressed) == 1
    reach = prove_overflow_reachable(
        {"rule_id": "SOL-004", "line": 1, "snippet": "t = t + amount;"},
        "pragma solidity ^0.7.0; contract T { uint256 public t; function add(uint256 amount) public { t = t + amount; } }",
    )
    # Line 1 has no enclosing function in this synthetic source; the
    # prover must stay honest (representability, SAT) without crashing.
    assert reach["verdict"] in ("SAT", "UNPARSED", "UNKNOWN")


def test_p2_llm_routing_schema_and_gasr():
    from orchestrator.services.llm_routing import (
        build_gasr_context,
        get_model_for_task,
        validate_validation_payload,
    )

    assert "Lightning" in get_model_for_task("triage")
    assert get_model_for_task("verification") != get_model_for_task("triage")
    ok, _ = validate_validation_payload({
        "is_true_positive": True, "confidence": 0.9,
        "ai_explanation": "real", "ai_remediation": "fix", "cwe_reference": "CWE-841",
    })
    assert ok
    bad, errors = validate_validation_payload({"is_true_positive": "yes", "confidence": 2})
    assert not bad and errors
    ctx = build_gasr_context({"line": 5, "snippet": "x"}, (ROOT / "benchmarks/corpus/ReentrancyVuln.sol").read_text())
    assert "State variables" in ctx and "External calls" in ctx


def test_p3_simulated_exploit_is_labelled_not_proof():
    from modules.live_fork.engine import LiveForkEngine

    proof = LiveForkEngine().execute_live_exploit(
        {"rule_id": "SOL-001", "file": "contracts/Vault.sol"}, initial_vault_eth=10.0
    )
    assert proof.is_real_execution is False
    assert proof.execution_mode == "simulated"
    assert proof.empirical_badge == "SIMULATED_NOT_AN_ONCHAIN_PROOF"
    assert not proof.tx_hash.startswith("0x")


def test_p4_postgres_url_is_supported_config():
    # URL/dialect parsing only: creating the async engine would import
    # asyncpg (optional production driver, see requirements.txt).
    from sqlalchemy.engine import make_url

    url = make_url("postgresql+asyncpg://user:pass@localhost:5432/adversum")
    assert url.get_dialect().name == "postgresql"
    assert url.get_driver_name() == "asyncpg"


def test_bundled_benchmark_reproducible():
    from benchmarks.run_benchmark import evaluate

    report = evaluate(ROOT / "benchmarks" / "corpus", "dappscan", 3)
    assert report["totals"]["contracts"] >= 8
    assert report["per_category"]["reentrancy"]["f1"] >= 70.0
    assert report["per_cwe"]["CWE-841"]["f1"] >= 70.0
