"""
Wormhole Bridge Attack Scenario — February 2, 2022
Total Loss: $320,000,000 (120,000 wETH)

Attack vector:
  1. Attacker finds critical bug in Solana Wormhole guardian signature verification
  2. Forge a fake VAA (Verifiable Action Approval) message claiming 120K ETH deposit on Ethereum
  3. Wormhole contract mints 120,000 wETH on Solana without any real ETH backing
  4. Attacker bridges wETH back to Ethereum, swapping for real ETH

Reference tx (Ethereum): 0xf09f4bc...
Jump Crypto replenished the $320M to protect users.
"""
from modules.attack_simulator.chain_executor import AttackChain, AttackStep, AttackPrimitive


def wormhole_scenario() -> AttackChain:
    chain = AttackChain(
        name="Wormhole Bridge — Fake VAA Signature Bypass",
        scenario_id="wormhole",
        description=(
            "Critical vulnerability in Wormhole's Solana contract allowed an attacker to forge "
            "a Verifiable Action Approval (VAA) without valid guardian signatures. "
            "120,000 wETH were minted on Solana unbacked, then bridged back to Ethereum. "
            "Jump Crypto replenished $320M to protect user funds."
        ),
        chain_id=101,  # Solana
        tags=["bridge", "signature_bypass", "unbacked_mint", "cross_chain"],
        real_hack_ref="Wormhole Bridge Post-Mortem — February 2022",
        loss_usd=320_000_000,
    )

    chain.add_step(AttackStep(
        primitive=AttackPrimitive.CUSTOM,
        protocol="Wormhole (Solana)",
        description="Identify verify_signatures() function bug: uses deprecated load_instruction_at() which can be spoofed",
        capital_in=0.0,
        capital_out=0.0,
        gas_usd=0.05,
        block_delta=0,
        token="N/A",
        metadata={
            "vulnerability": "verify_signatures uses deprecated sysvar instruction loader",
            "cwe": "CWE-347 Improper Verification of Cryptographic Signature",
        },
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.BRIDGE_DRAIN,
        protocol="Wormhole (Solana)",
        description="Submit crafted transaction with fake VAA claiming 120,000 ETH deposited on Ethereum",
        capital_in=0.0,
        capital_out=0.0,
        gas_usd=0.02,
        block_delta=1,
        token="VAA",
        metadata={"fake_vaa": True, "claimed_eth": 120_000, "guardians_bypassed": 19},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.UNBACKED_MINT,
        protocol="Wormhole Token Bridge",
        description="Wormhole mints 120,000 wETH on Solana — fully unbacked, no real ETH locked",
        capital_in=0.0,
        capital_out=320_000_000.0,
        gas_usd=0.1,
        block_delta=1,
        token="wETH",
        metadata={"minted": 120_000, "weth_price_usd": 2667, "backed_by": 0},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.BRIDGE_DRAIN,
        protocol="Wormhole Bridge → Ethereum",
        description="Bridge 80,000 wETH back to Ethereum mainnet via Wormhole token bridge",
        capital_in=213_360_000.0,
        capital_out=213_360_000.0,
        gas_usd=85.0,
        block_delta=3,
        token="ETH",
        metadata={"bridged_eth": 80_000, "remaining_on_solana": 40_000},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.CUSTOM,
        protocol="Ethereum DEXes",
        description="Swap wETH for real ETH via Curve and Uniswap pools — drain complete",
        capital_in=0.0,
        capital_out=106_680_000.0,
        gas_usd=120.0,
        block_delta=2,
        token="ETH",
        metadata={"venues": ["Curve", "Uniswap v3"], "slippage_pct": 0.3},
    ))

    return chain
