"""
Mango Markets Attack Scenario — October 11, 2022
Total Loss: $116,000,000

Attack vector:
  1. Open large MNGO-PERP long and short positions from 2 accounts
  2. Pump MNGO token price 5–10x using own capital on spot markets
  3. Inflated collateral value allows borrowing $116M from treasury
  4. Propose governance vote to "allow" keeping $47M as bounty
  5. Vote passes using flash-loan-funded MNGO tokens

Reference: Attacker publicly revealed identity (Avraham Eisenberg)
"""
from modules.attack_simulator.chain_executor import AttackChain, AttackStep, AttackPrimitive


def mango_markets_scenario() -> AttackChain:
    chain = AttackChain(
        name="Mango Markets — Oracle Price Pump + Self-Borrow",
        scenario_id="mango_markets",
        description=(
            "Attacker uses two accounts to self-trade MNGO-PERP futures, "
            "then pumps MNGO spot price 10x using ~$10M capital. "
            "Inflated collateral allows borrowing $116M from Mango treasury. "
            "Governance vote (with attacker's own tokens) approves the 'settlement'."
        ),
        chain_id=101,  # Solana
        tags=["oracle_manipulation", "governance", "self_liquidation", "solana"],
        real_hack_ref="Mango Markets Exploit — October 2022 (Avraham Eisenberg)",
        loss_usd=116_000_000,
    )

    chain.add_step(AttackStep(
        primitive=AttackPrimitive.CUSTOM,
        protocol="Mango Markets",
        description="Deposit $5.4M USDC into Account A and Account B on Mango Markets",
        capital_in=10_800_000.0,
        capital_out=0.0,
        gas_usd=1.0,
        block_delta=0,
        token="USDC",
        metadata={"account_a": 5_400_000, "account_b": 5_400_000},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.PRICE_PUMP,
        protocol="Mango Markets / FTX Spot",
        description="Buy MNGO aggressively on spot markets → MNGO price pumps from $0.038 to $0.91 (+2300%)",
        capital_in=10_000_000.0,
        capital_out=0.0,
        gas_usd=15.0,
        block_delta=5,
        token="MNGO",
        metadata={"price_before": 0.038, "price_after": 0.91, "pct_pump": 2300},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.ORACLE_MANIP,
        protocol="Mango Markets Oracle",
        description="Oracle reads manipulated spot price — Account A's MNGO collateral now worth $500M notional",
        capital_in=0.0,
        capital_out=500_000_000.0,
        gas_usd=0.5,
        block_delta=1,
        token="MNGO",
        metadata={"oracle_type": "spot_twap_5min", "cve": "oracle_no_circuit_breaker"},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.LIQUIDATION,
        protocol="Mango Markets",
        description="Borrow all available assets from Mango treasury against inflated collateral: $116M in USDC, SOL, mSOL, BTC",
        capital_in=0.0,
        capital_out=116_000_000.0,
        gas_usd=2.0,
        block_delta=2,
        token="USDC+SOL+BTC",
        metadata={"borrowed_assets": ["USDC", "SOL", "mSOL", "BTC", "USDT", "MSRM"]},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.GOVERNANCE_VOTE,
        protocol="Mango Markets DAO",
        description="Propose + pass governance vote to settle bad debt: attacker keeps $47M as 'bounty', returns $67M",
        capital_in=0.0,
        capital_out=47_000_000.0,
        gas_usd=1.0,
        block_delta=100,
        token="MNGO",
        metadata={"vote_result": "passed", "returned": 67_000_000, "kept": 47_000_000},
    ))

    return chain
