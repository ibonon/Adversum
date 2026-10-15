"""
Phase 2 Tests — MEV Intelligence Engine
pytest tests/test_phase2_mev.py
"""

import asyncio
import hashlib
import pytest

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.mev_intelligence.engine import (
    MEVIntelligenceEngine,
    MEVTransaction,
    MEVChain,
    MEVAttackType,
    MEVRiskLevel,
)


def _make_tx(from_addr: str, to_addr: str, value_eth: float, gas_gwei: float, index: int, input_data: str = "0xd0e30db0") -> MEVTransaction:
    return MEVTransaction(
        tx_hash      = hashlib.sha256(f"tx{index}".encode()).hexdigest()[:64],
        from_address = from_addr,
        to_address   = to_addr,
        value_wei    = int(value_eth * 1e18),
        gas_price    = int(gas_gwei * 1e9),
        gas_limit    = 300_000,
        input_data   = input_data,
        position     = index,
    )


ATTACKER = "0x" + "dead" * 10
VICTIM   = "0x" + "cafe" * 10
POOL     = "0x" + "1234" * 10


@pytest.mark.asyncio
async def test_sandwich_attack_detection():
    """Detect classic sandwich attack: front-run → victim → back-run."""
    engine = MEVIntelligenceEngine(eth_price_usd=2650.0)

    txs = [
        _make_tx(ATTACKER, POOL, 50.0, 200.0, 0),   # front-run (200 gwei)
        _make_tx(VICTIM,   POOL, 10.0, 50.0,  1),    # victim    (50 gwei)
        _make_tx(ATTACKER, POOL, 49.0, 30.0,  2),    # back-run  (30 gwei)
    ]

    result = await engine.analyze_block(txs, chain=MEVChain.ETHEREUM)
    sandwich_patterns = [p for p in result.patterns_found if p.attack_type == MEVAttackType.SANDWICH]

    assert len(sandwich_patterns) >= 1, "Should detect sandwich attack"
    p = sandwich_patterns[0]
    assert p.attacker_address == ATTACKER
    assert p.victim_address   == VICTIM
    assert p.risk_level in (MEVRiskLevel.HIGH, MEVRiskLevel.CRITICAL)
    assert p.chain == MEVChain.ETHEREUM
    assert len(p.tx_hashes) == 3
    assert p.mitre_technique is not None
    assert p.mitigation is not None


@pytest.mark.asyncio
async def test_flash_loan_attack_detection():
    """Detect flash loan pattern: multiple high-value txs from same sender."""
    engine = MEVIntelligenceEngine(eth_price_usd=2650.0)

    # Same attacker, multiple large-value transactions with calldata
    txs = [
        _make_tx(ATTACKER, POOL, 100.0, 80.0, 0, "0xdeadbeef"),
        _make_tx(ATTACKER, POOL, 95.0,  80.0, 1, "0xcafe1234"),
        _make_tx(VICTIM,   POOL, 1.0,   50.0, 2),
    ]

    result = await engine.analyze_block(txs, chain=MEVChain.ARBITRUM)
    flash_loan = [p for p in result.patterns_found if p.attack_type == MEVAttackType.FLASH_LOAN]

    assert len(flash_loan) >= 1, "Should detect flash loan pattern"
    p = flash_loan[0]
    assert p.attacker_address == ATTACKER
    assert p.value_at_risk_eth >= 10.0
    assert p.value_at_risk_usd >= 10.0 * 2650.0 * 0.9  # at least ~90% of threshold


@pytest.mark.asyncio
async def test_oracle_manipulation_detection():
    """Detect oracle manipulation: single tx distorting >15% of pool."""
    engine = MEVIntelligenceEngine(eth_price_usd=2650.0)

    # Single tx = 200 ETH in a 1000 ETH pool = 20% distortion
    txs = [_make_tx(ATTACKER, POOL, 200.0, 100.0, 0, "0xabcdef01")]

    result = await engine.analyze_block(
        txs, chain=MEVChain.BASE, pool_liquidity_eth=1000.0
    )
    oracle_patterns = [p for p in result.patterns_found if p.attack_type == MEVAttackType.ORACLE_MANIPULATION]

    assert len(oracle_patterns) >= 1, "Should detect oracle manipulation"
    p = oracle_patterns[0]
    assert p.evidence["distortion_pct"] >= 15.0
    assert p.attacker_address == ATTACKER


@pytest.mark.asyncio
async def test_rug_pull_detection():
    """Detect rug pull: single address draining >80% of block value."""
    engine = MEVIntelligenceEngine(eth_price_usd=2650.0)

    # Attacker moves 900 ETH, others move 50 ETH total
    txs = [
        _make_tx(ATTACKER, POOL, 900.0, 50.0, 0),
        _make_tx(VICTIM,   POOL,  25.0, 50.0, 1),
        _make_tx(VICTIM,   POOL,  25.0, 50.0, 2),
    ]

    result = await engine.analyze_block(txs, chain=MEVChain.POLYGON)
    rug_patterns = [p for p in result.patterns_found if p.attack_type == MEVAttackType.RUG_PULL]

    assert len(rug_patterns) >= 1, "Should detect rug pull"
    p = rug_patterns[0]
    assert p.attacker_address == ATTACKER
    assert p.risk_level == MEVRiskLevel.CRITICAL
    assert p.evidence["drain_percentage"] >= 80.0


@pytest.mark.asyncio
async def test_clean_block_no_patterns():
    """No patterns detected in a normal block."""
    engine = MEVIntelligenceEngine(eth_price_usd=2650.0)

    import random, hashlib
    rng = random.Random(999)
    txs = []
    addrs = ["0x" + f"{rng.randint(1, 2**160):040x}" for _ in range(8)]
    for i in range(8):
        txs.append(MEVTransaction(
            tx_hash      = hashlib.sha256(f"clean{i}".encode()).hexdigest()[:64],
            from_address = addrs[i % len(addrs)],
            to_address   = "0x" + "a" * 40,
            value_wei    = int(rng.uniform(0.01, 2.0) * 1e18),
            gas_price    = int(rng.uniform(25, 35) * 1e9),
            input_data   = "0x",
            position     = i,
        ))

    result = await engine.analyze_block(txs, chain=MEVChain.OPTIMISM)

    # No sandwich (different senders/receivers, no gas ordering manipulation)
    sandwich = [p for p in result.patterns_found if p.attack_type == MEVAttackType.SANDWICH]
    rug      = [p for p in result.patterns_found if p.attack_type == MEVAttackType.RUG_PULL]
    assert len(sandwich) == 0 and len(rug) == 0


@pytest.mark.asyncio
async def test_multi_chain_support():
    """Engine correctly tags patterns with the specified chain."""
    engine = MEVIntelligenceEngine(eth_price_usd=2650.0)

    for chain in [MEVChain.ETHEREUM, MEVChain.ARBITRUM, MEVChain.BASE]:
        txs = [
            _make_tx(ATTACKER, POOL, 50.0, 200.0, 0),
            _make_tx(VICTIM,   POOL, 10.0, 50.0,  1),
            _make_tx(ATTACKER, POOL, 49.0, 30.0,  2),
        ]
        result = await engine.analyze_block(txs, chain=chain)
        assert result.chain == chain
        for p in result.patterns_found:
            assert p.chain == chain


@pytest.mark.asyncio
async def test_signature_ruleset_export():
    """Patterns can be exported as SIEM-compatible detection rules."""
    engine = MEVIntelligenceEngine(eth_price_usd=2650.0)
    txs = [
        _make_tx(ATTACKER, POOL, 50.0, 200.0, 0),
        _make_tx(VICTIM,   POOL, 10.0, 50.0,  1),
        _make_tx(ATTACKER, POOL, 49.0, 30.0,  2),
    ]
    result  = await engine.analyze_block(txs, chain=MEVChain.ETHEREUM)
    ruleset = engine.generate_signature_ruleset(result.patterns_found)

    for rule in ruleset:
        assert "rule_id"   in rule
        assert "severity"  in rule
        assert "signature" in rule
        assert "mitre"     in rule
        assert "mitigation" in rule
