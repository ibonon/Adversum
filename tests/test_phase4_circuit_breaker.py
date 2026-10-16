"""
Phase 4 Tests — Circuit Breaker Synthesizer
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from modules.incident_response.circuit_breaker import (
    CircuitBreakerConfig, CircuitBreakerSynthesizer, SynthesizedCircuitBreaker
)


class TestCircuitBreakerSynthesizer:
    def test_default_synthesis(self):
        synth = CircuitBreakerSynthesizer()
        res = synth.synthesize()
        assert isinstance(res, SynthesizedCircuitBreaker)
        assert "pragma solidity ^0.8.20;" in res.solidity_code
        assert "CircuitBreaker is Ownable" in res.solidity_code
        assert "recordOutflow" in res.solidity_code
        assert "verifyOracleBounds" in res.solidity_code
        assert "checkFlashLoanConstraint" in res.solidity_code
        assert res.estimated_gas_overhead > 0
        assert len(res.active_protections) >= 3

    def test_custom_config_synthesis(self):
        synth = CircuitBreakerSynthesizer()
        cfg = CircuitBreakerConfig(
            protocol_name="AaveFork",
            target_token="DAI",
            max_tvl_outflow_pct_per_window=3.0,
            window_blocks=20,
            max_oracle_divergence_pct=2.5,
            enable_flash_loan_guard=False,
        )
        res = synth.synthesize(cfg)
        assert "AaveForkCircuitBreaker" in res.solidity_code
        assert "maxOutflowBps = 300;" in res.solidity_code
        assert "windowBlocks = 20;" in res.solidity_code
        assert "maxOracleDivergenceBps = 250;" in res.solidity_code
        assert res.estimated_gas_overhead < 10000

    def test_watcher_policy_json_structure(self):
        synth = CircuitBreakerSynthesizer()
        res = synth.synthesize()
        policy = res.watcher_policy_json
        assert policy["protocol"] == "DeFiProtocol"
        assert len(policy["rules"]) >= 3
        rule_ids = [r["rule_id"] for r in policy["rules"]]
        assert "RATE_LIMIT_RULE" in rule_ids
        assert "ORACLE_DEVIATION_RULE" in rule_ids

    def test_to_dict_serializable(self):
        synth = CircuitBreakerSynthesizer()
        res = synth.synthesize()
        d = res.to_dict()
        assert "protocol_name" in d
        assert "solidity_code" in d
        assert "watcher_policy_json" in d
        assert "active_protections" in d
        assert "estimated_gas_overhead" in d
