"""
Phase 4 Tests — Adversarial Invariant Evaluator
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from modules.incident_response.adversarial_evaluator import (
    AdversarialInvariantEvaluator, ProtocolEvaluationReport, InvariantResult
)


class TestAdversarialInvariantEvaluator:
    def test_clean_contract_high_score(self):
        clean_code = """
        // Clean contract with all invariant guards
        contract SafeLending is ReentrancyGuard, Ownable {
            using SafeERC20 for IERC20;
            
            function swap(uint256 amountIn, uint256 amountOutMin) external nonReentrant {
                require(amountIn > 0);
            }
            
            function readOracle() public view returns (uint256) {
                (uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound) = oracle.latestRoundData();
                require(answeredInRound >= roundId, "stale");
                return uint256(price);
            }
        }
        """
        evaluator = AdversarialInvariantEvaluator()
        report = evaluator.evaluate_code(clean_code, protocol_name="SafeLending")
        assert isinstance(report, ProtocolEvaluationReport)
        assert report.total_invariants == 10
        assert report.passed_count >= 8
        assert report.resilience_score >= 80.0

    def test_vulnerable_contract_detects_violations(self):
        vuln_code = """
        contract VulnerableVault {
            // Donate attack
            function donateToReserve() external payable {}
            
            // Reentrancy without guard
            function withdraw(uint256 amount) external {
                msg.sender.call{value: amount}("");
            }
            
            // Swap without slippage
            function swap(uint256 amountIn) external {}
            
            // Raw transfer
            function rawSend(address token, address to, uint256 amount) external {
                IERC20(token).transfer(to, amount);
            }
        }
        """
        evaluator = AdversarialInvariantEvaluator()
        report = evaluator.evaluate_code(vuln_code, protocol_name="VulnerableVault")
        assert report.failed_count >= 3
        failed_ids = [r.invariant_id for r in report.invariant_results if not r.passed]
        assert "INV-01" in failed_ids  # donate
        assert "INV-03" in failed_ids  # reentrancy
        assert "INV-06" in failed_ids  # slippage

    def test_report_to_dict_structure(self):
        evaluator = AdversarialInvariantEvaluator()
        report = evaluator.evaluate_code("// Empty", protocol_name="EmptyProtocol")
        d = report.to_dict()
        assert "protocol" in d
        assert "total_invariants" in d
        assert "passed_count" in d
        assert "failed_count" in d
        assert "resilience_score" in d
        assert "invariant_results" in d
        assert len(d["invariant_results"]) == 10
