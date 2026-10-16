"""
Phase 3 Tests — Cross-Protocol Attack Simulator
Tests: chain executor, cascade propagation, scenarios, risk scorer, risk matrix
"""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("NEBIUS_MOCK", "1")

from modules.attack_simulator.chain_executor import (
    AttackChainExecutor, AttackChain, AttackStep, AttackPrimitive,
)
from modules.attack_simulator.risk_scorer import DeFiRiskScorer
from modules.attack_simulator.scenarios import SCENARIO_REGISTRY


# ── Helpers ────────────────────────────────────────────────────────────────

def simple_chain(loss: float = 10_000_000.0) -> AttackChain:
    chain = AttackChain(
        name="Test Chain",
        scenario_id="test",
        description="Unit test chain",
        chain_id=1,
        loss_usd=loss,
    )
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.FLASH_LOAN,
        protocol="Aave",
        description="Borrow 10M",
        capital_in=0, capital_out=10_000_000, gas_usd=20, block_delta=0, token="DAI",
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.ORACLE_MANIP,
        protocol="Uniswap",
        description="Pump oracle",
        capital_in=8_000_000, capital_out=40_000_000, gas_usd=25, block_delta=0, token="USDC",
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.REPAY_FLASH,
        protocol="Aave",
        description="Repay",
        capital_in=10_009_000, capital_out=0, gas_usd=5, block_delta=0, token="DAI",
    ))
    return chain


# ── AttackStep tests ────────────────────────────────────────────────────────

class TestAttackStep:
    def test_net_impact_positive(self):
        step = AttackStep(
            primitive=AttackPrimitive.LIQUIDATION,
            protocol="Euler", description="Extract",
            capital_in=0, capital_out=5_000_000, gas_usd=50, token="DAI",
        )
        assert step.net_impact == pytest.approx(4_999_950, rel=1e-3)

    def test_net_impact_negative_cost(self):
        step = AttackStep(
            primitive=AttackPrimitive.REPAY_FLASH,
            protocol="Aave", description="Repay",
            capital_in=10_000_000, capital_out=0, gas_usd=10, token="DAI",
        )
        assert step.net_impact < 0

    def test_to_dict_has_net_impact(self):
        step = AttackStep(
            primitive=AttackPrimitive.PRICE_PUMP,
            protocol="DEX", description="Pump",
            capital_in=100, capital_out=200, gas_usd=5, token="ETH",
        )
        d = step.to_dict()
        assert "net_impact" in d
        assert d["net_impact"] == pytest.approx(95.0)


# ── AttackChain tests ───────────────────────────────────────────────────────

class TestAttackChain:
    def test_total_gas(self):
        chain = simple_chain()
        assert chain.total_gas() == pytest.approx(50.0)

    def test_block_span(self):
        chain = simple_chain()
        assert chain.block_span() == 0  # all steps have block_delta=0

    def test_attacker_profit_positive(self):
        chain = simple_chain()
        profit = chain.attacker_profit()
        # capital_out net: 40M - 8M - 10.009M = positive
        assert profit > 0

    def test_protocol_loss_uses_loss_usd(self):
        chain = simple_chain(loss=5_000_000)
        assert chain.protocol_loss() == pytest.approx(5_000_000)


# ── Executor tests ──────────────────────────────────────────────────────────

class TestAttackChainExecutor:
    def test_execute_returns_simulation_result(self):
        executor = AttackChainExecutor()
        result = executor.execute(simple_chain())
        assert result.simulation_id
        assert result.success is True
        assert result.attacker_profit > 0

    def test_history_accumulates(self):
        executor = AttackChainExecutor()
        executor.execute(simple_chain())
        executor.execute(simple_chain())
        assert len(executor.get_history()) == 2

    def test_get_by_id(self):
        executor = AttackChainExecutor()
        result = executor.execute(simple_chain())
        fetched = executor.get_by_id(result.simulation_id)
        assert fetched is not None
        assert fetched.simulation_id == result.simulation_id

    def test_get_by_id_unknown_returns_none(self):
        executor = AttackChainExecutor()
        assert executor.get_by_id("nonexistent-id") is None

    def test_result_to_dict_structure(self):
        executor = AttackChainExecutor()
        result = executor.execute(simple_chain())
        d = result.to_dict()
        assert "simulation_id" in d
        assert "attacker_profit_usd" in d
        assert "protocol_loss_usd" in d
        assert "risk_index" in d
        assert "steps" in d
        assert isinstance(d["steps"], list)

    def test_cascade_triggered_for_large_loss(self):
        executor = AttackChainExecutor()
        # Euler Finance chain triggers cascade to Compound, Aave, Balancer
        from modules.attack_simulator.scenarios.euler_finance import euler_finance_scenario
        chain = euler_finance_scenario()
        result = executor.execute(chain)
        assert result.cascade_triggered is True
        assert len(result.cascade_protocols) > 0

    def test_risk_index_range(self):
        executor = AttackChainExecutor()
        result = executor.execute(simple_chain())
        assert 0 <= result.risk_index <= 100

    def test_mitre_techniques_populated(self):
        executor = AttackChainExecutor()
        result = executor.execute(simple_chain())
        assert len(result.mitre_techniques) > 0
        for technique in result.mitre_techniques:
            assert "T1" in technique

    def test_clear_history(self):
        executor = AttackChainExecutor()
        executor.execute(simple_chain())
        executor.clear_history()
        assert len(executor.get_history()) == 0


# ── Scenario tests ──────────────────────────────────────────────────────────

class TestScenarios:
    def test_all_scenarios_registered(self):
        expected = {"euler_finance", "ronin_bridge", "mango_markets", "wormhole", "generic_flashloan_cascade"}
        assert expected == set(SCENARIO_REGISTRY.keys())

    def test_euler_finance_loss(self):
        chain = SCENARIO_REGISTRY["euler_finance"]()
        assert chain.loss_usd == pytest.approx(197_000_000)
        assert len(chain.steps) >= 5

    def test_ronin_bridge_loss(self):
        chain = SCENARIO_REGISTRY["ronin_bridge"]()
        assert chain.loss_usd == pytest.approx(625_000_000)
        assert any(s.primitive == AttackPrimitive.BRIDGE_DRAIN for s in chain.steps)

    def test_mango_markets_has_oracle_step(self):
        chain = SCENARIO_REGISTRY["mango_markets"]()
        assert any(s.primitive == AttackPrimitive.ORACLE_MANIP for s in chain.steps)

    def test_wormhole_has_unbacked_mint(self):
        chain = SCENARIO_REGISTRY["wormhole"]()
        assert any(s.primitive == AttackPrimitive.UNBACKED_MINT for s in chain.steps)

    def test_generic_flashloan_configurable(self):
        fn = SCENARIO_REGISTRY["generic_flashloan_cascade"]
        chain = fn(flash_loan_amount=100_000_000, borrow_amount=80_000_000)
        assert chain.loss_usd > 80_000_000

    def test_all_scenarios_executable(self):
        executor = AttackChainExecutor()
        for sid, fn in SCENARIO_REGISTRY.items():
            chain = fn()
            result = executor.execute(chain)
            assert result.simulation_id
            assert result.scenario_id == sid


# ── Risk Scorer tests ───────────────────────────────────────────────────────

class TestDeFiRiskScorer:
    def test_score_known_protocol(self):
        scorer = DeFiRiskScorer()
        score = scorer.score_protocol("Euler Finance")
        assert score.protocol == "Euler Finance"
        assert 0 <= score.composite <= 100
        assert score.grade in ("A", "B", "C", "D", "F")

    def test_euler_high_flash_loan_risk(self):
        scorer = DeFiRiskScorer()
        score = scorer.score_protocol("Euler Finance")
        assert score.scores["flash_loan_risk"] > 80

    def test_ronin_high_bridge_risk(self):
        scorer = DeFiRiskScorer()
        score = scorer.score_protocol("Ronin Bridge")
        assert score.scores["bridge_risk"] > 90

    def test_mango_high_oracle_risk(self):
        scorer = DeFiRiskScorer()
        score = scorer.score_protocol("Mango Markets")
        assert score.scores["oracle_risk"] > 90

    def test_unknown_protocol_uses_defaults(self):
        scorer = DeFiRiskScorer()
        score = scorer.score_protocol("SomeUnknownProtocol", tvl_usd=5_000_000)
        assert score.composite > 0
        assert score.tvl_usd == 5_000_000

    def test_custom_overrides_applied(self):
        scorer = DeFiRiskScorer()
        score = scorer.score_protocol("Aave", custom_overrides={"oracle_risk": 99.0})
        assert score.scores["oracle_risk"] == pytest.approx(99.0)

    def test_score_all_known_returns_all(self):
        scorer = DeFiRiskScorer()
        all_scores = scorer.score_all_known()
        assert len(all_scores) == len(scorer.known_protocols())

    def test_risk_matrix_structure(self):
        scorer = DeFiRiskScorer()
        matrix = scorer.risk_matrix()
        assert "Euler Finance" in matrix
        assert "Oracle Manipulation" in matrix["Euler Finance"]

    def test_top_risk_is_highest_score(self):
        scorer = DeFiRiskScorer()
        score = scorer.score_protocol("Mango Markets")
        # top_risk should correspond to the vector with the highest score
        all_scores = score.scores
        max_vector = max(all_scores, key=lambda k: all_scores[k])
        # The top_risk label should match
        from modules.attack_simulator.risk_scorer import VECTOR_LABELS
        assert score.top_risk == max_vector

    def test_to_dict_has_required_keys(self):
        scorer = DeFiRiskScorer()
        score = scorer.score_protocol("Compound")
        d = score.to_dict()
        for key in ("protocol", "scores", "composite_risk", "grade", "tvl_usd", "chain", "audit_count"):
            assert key in d
