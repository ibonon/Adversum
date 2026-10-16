"""
Generic Flash Loan Cascade Attack Scenario
Configurable multi-protocol DeFi attack template.

Default configuration:
  Flash Loan (Aave) → Oracle Manipulation (Uniswap v2) → Undercollateralized Borrow (Compound)
  → Liquidation Cascade → Bridge drain → Repay flash loan

This scenario serves as a template for custom attack chain simulations.
"""
from modules.attack_simulator.chain_executor import AttackChain, AttackStep, AttackPrimitive


def generic_flashloan_cascade_scenario(
    flash_loan_amount: float = 50_000_000.0,
    oracle_inflation_pct: float = 500.0,
    target_protocol: str = "Compound",
    borrow_amount: float = 40_000_000.0,
    bridge_drain_amount: float = 15_000_000.0,
) -> AttackChain:
    """
    Configurable generic flash loan cascade attack.

    Args:
        flash_loan_amount: Flash loan size in USD
        oracle_inflation_pct: % price inflation on oracle
        target_protocol: Protocol to borrow from post-oracle manipulation
        borrow_amount: Amount borrowed from victim protocol in USD
        bridge_drain_amount: Amount siphoned via bridge in USD
    """
    profit = borrow_amount + bridge_drain_amount - flash_loan_amount * 0.001  # 0.1% fee

    chain = AttackChain(
        name=f"Generic Flash Loan Cascade → {target_protocol}",
        scenario_id="generic_flashloan_cascade",
        description=(
            f"Configurable multi-step DeFi attack: "
            f"${flash_loan_amount/1e6:.0f}M flash loan → {oracle_inflation_pct:.0f}% oracle pump "
            f"→ ${borrow_amount/1e6:.0f}M drain from {target_protocol} "
            f"→ ${bridge_drain_amount/1e6:.0f}M bridge drain → repay."
        ),
        chain_id=1,
        tags=["flash_loan", "oracle", "cascade", "template"],
        real_hack_ref="Generic template based on bZx / Cream Finance attack patterns",
        loss_usd=borrow_amount + bridge_drain_amount,
    )

    chain.add_step(AttackStep(
        primitive=AttackPrimitive.FLASH_LOAN,
        protocol="Aave v3",
        description=f"Flash loan ${flash_loan_amount/1e6:.1f}M WETH from Aave",
        capital_in=0.0,
        capital_out=flash_loan_amount,
        gas_usd=18.0,
        block_delta=0,
        token="WETH",
        metadata={"provider": "Aave v3", "amount_usd": flash_loan_amount, "fee_pct": 0.09},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.ORACLE_MANIP,
        protocol="Uniswap v2",
        description=f"Dump WETH into Uniswap v2 WETH/USDC pool → token price inflated by {oracle_inflation_pct:.0f}%",
        capital_in=flash_loan_amount * 0.8,
        capital_out=flash_loan_amount * 0.8 * (1 + oracle_inflation_pct / 100),
        gas_usd=25.0,
        block_delta=0,
        token="USDC",
        metadata={"pool": "WETH/USDC Uniswap v2", "oracle_type": "spot", "inflation_pct": oracle_inflation_pct},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.CUSTOM,
        protocol=target_protocol,
        description=f"Use inflated collateral value to borrow ${borrow_amount/1e6:.1f}M from {target_protocol}",
        capital_in=0.0,
        capital_out=borrow_amount,
        gas_usd=15.0,
        block_delta=0,
        token="USDC",
        metadata={"protocol": target_protocol, "collateral_ratio_effective": 0.05},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.LIQUIDATION,
        protocol=target_protocol,
        description="Cascade liquidation: other borrowers' positions become undercollateralized, amplifying the drain",
        capital_in=0.0,
        capital_out=borrow_amount * 0.05,
        gas_usd=30.0,
        block_delta=1,
        token="USDC",
        metadata={"liquidation_bonus": "5%", "cascade_victims": 3},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.BRIDGE_DRAIN,
        protocol="Multichain Bridge",
        description=f"Bridge ${bridge_drain_amount/1e6:.1f}M out via Multichain to avoid Ethereum monitoring",
        capital_in=bridge_drain_amount,
        capital_out=bridge_drain_amount * 0.995,
        gas_usd=40.0,
        block_delta=2,
        token="USDC",
        metadata={"bridge": "Multichain", "destination": "BSC"},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.REPAY_FLASH,
        protocol="Aave v3",
        description=f"Repay flash loan ${flash_loan_amount/1e6:.1f}M + 0.09% fee",
        capital_in=flash_loan_amount * 1.0009,
        capital_out=0.0,
        gas_usd=10.0,
        block_delta=0,
        token="WETH",
        metadata={"fee_usd": flash_loan_amount * 0.0009},
    ))

    return chain
