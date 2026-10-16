"""
Euler Finance Attack Scenario — March 13, 2023
Total Loss: $197,000,000

Attack vector:
  1. Flash loan 30M DAI from Aave
  2. Deposit into Euler as collateral (eDAI minted)
  3. Leverage 10x via repeated deposit/borrow loops → eDAI inflated
  4. Call donateToReserves() → removes collateral from accounting
  5. Trigger self-liquidation → liquidation bonus extracted
  6. Repay flash loan

Reference tx: 0xc310a0affe2169d1f6feec1c63dbc7f7c62a887ad5e2ce79b7a72ca0e6ad5e01
"""
from modules.attack_simulator.chain_executor import AttackChain, AttackStep, AttackPrimitive


def euler_finance_scenario() -> AttackChain:
    chain = AttackChain(
        name="Euler Finance — donateToReserves Flash Loan",
        scenario_id="euler_finance",
        description=(
            "Attacker exploits a flawed donateToReserves() function that removes collateral "
            "from accounting without reducing debt. Combined with flash loan leverage, "
            "this enables a ~$197M liquidation bonus extraction in a single transaction."
        ),
        chain_id=1,
        tags=["flash_loan", "liquidation", "accounting_bug", "defi_lending"],
        real_hack_ref="0xc310a0affe2169d1f6feec1c63dbc7f7c62a887ad5e2ce79b7a72ca0e6ad5e01",
        loss_usd=197_000_000,
    )

    chain.add_step(AttackStep(
        primitive=AttackPrimitive.FLASH_LOAN,
        protocol="Aave v2",
        description="Flash loan 30,000,000 DAI from Aave liquidity pool",
        capital_in=0.0,
        capital_out=30_000_000.0,
        gas_usd=12.0,
        block_delta=0,
        token="DAI",
        metadata={"provider": "Aave", "amount": 30_000_000, "fee_pct": 0.09},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.CUSTOM,
        protocol="Euler Finance",
        description="Deposit 30M DAI and leverage 10x via repeated mint/borrow loops → eDAI balance inflated to 300M",
        capital_in=30_000_000.0,
        capital_out=300_000_000.0,
        gas_usd=45.0,
        block_delta=0,
        token="eDAI",
        metadata={"leverage_factor": 10, "loops": 8},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.DONATE_ATTACK,
        protocol="Euler Finance",
        description="Call donateToReserves(100M eDAI) → collateral removed from accounting but debt remains, creating phantom insolvency",
        capital_in=100_000_000.0,
        capital_out=0.0,
        gas_usd=8.0,
        block_delta=0,
        token="eDAI",
        metadata={"function": "donateToReserves", "cwe": "CWE-682"},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.LIQUIDATION,
        protocol="Euler Finance",
        description="Self-liquidation captures 10% liquidation bonus on 197M insolvent position",
        capital_in=0.0,
        capital_out=197_000_000.0,
        gas_usd=15.0,
        block_delta=0,
        token="DAI",
        metadata={"liquidation_bonus_pct": 10, "position_size": 197_000_000},
    ))
    chain.add_step(AttackStep(
        primitive=AttackPrimitive.REPAY_FLASH,
        protocol="Aave v2",
        description="Repay flash loan (30M DAI + 0.09% fee = $27,000)",
        capital_in=30_027_000.0,
        capital_out=0.0,
        gas_usd=5.0,
        block_delta=0,
        token="DAI",
        metadata={"repay_amount": 30_027_000},
    ))

    return chain
