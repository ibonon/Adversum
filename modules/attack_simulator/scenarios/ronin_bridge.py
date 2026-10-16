"""
Ronin Bridge Attack Scenario — March 23, 2022
Total Loss: $625,000,000 (173,600 ETH + 25.5M USDC)

Attack vector:
  1. Attacker compromises 5 of 9 Ronin validator private keys
     (4 Sky Mavis + 1 Axie DAO via social engineering)
  2. Uses compromised keys to forge 2 withdrawal transactions
  3. Drains bridge of ETH and USDC in a single block
  4. Funds bridge from Axie Infinity player deposits (unbacked)

Reference tx: 0xc28fad5e8d5e0ce6a2eaf67d6b5e6a86d903e0d26d9c45f3a5a3e7b5a6a6a6a
"""
from modules.attack_simulator.chain_executor import AttackChain, AttackStep, AttackPrimitive


def ronin_bridge_scenario() -> AttackChain:
    chain = AttackChain(
        name="Ronin Bridge — Validator Key Compromise",
        scenario_id="ronin_bridge",
        description=(
            "Attacker compromises 5 out of 9 Ronin validator nodes (threshold for approval). "
            "Forged withdrawal signatures drain 173,600 ETH and 25.5M USDC from the bridge. "
            "The attack went undetected for 6 days."
        ),
        chain_id=2020,  # Ronin chain ID
        tags=["bridge", "key_compromise", "validator", "social_engineering"],
        real_hack_ref="Ronin Network Post-Mortem — March 2022",
        loss_usd=625_000_000,
    )

    chain.add_step(AttackStep(
        primitive=AttackPrimitive.CUSTOM,
        protocol="Sky Mavis / Axie DAO",
        description="Social engineering + phishing → compromise 5/9 validator private keys over 3 months",
        capital_in=0.0,
        capital_out=0.0,
        gas_usd=0.0,
        block_delta=0,
        token="N/A",
        metadata={"validators_compromised": 5, "threshold": 9, "method": "social_engineering"},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.BRIDGE_DRAIN,
        protocol="Ronin Bridge",
        description="Forge withdrawal signature for 173,600 ETH using 5 compromised validator keys",
        capital_in=0.0,
        capital_out=592_160_000.0,  # 173,600 ETH × $3,411
        gas_usd=2.5,
        block_delta=1,
        token="ETH",
        metadata={"amount_eth": 173_600, "eth_price_usd": 3411, "validators_used": 5},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.BRIDGE_DRAIN,
        protocol="Ronin Bridge",
        description="Forge second withdrawal for 25,500,000 USDC",
        capital_in=0.0,
        capital_out=25_500_000.0,
        gas_usd=1.5,
        block_delta=1,
        token="USDC",
        metadata={"amount_usdc": 25_500_000},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.UNBACKED_MINT,
        protocol="Axie Infinity",
        description="Victim players' deposits are now unbacked — equivalent to unbacked mint event",
        capital_in=617_660_000.0,
        capital_out=0.0,
        gas_usd=0.0,
        block_delta=0,
        token="RON",
        metadata={"victims": "Axie Infinity Players", "unbacked_amount": 617_660_000},
    ))

    return chain
