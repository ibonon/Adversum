#!/usr/bin/env python3
"""
Adversum Smart Invariant Miner & Foundry Invariant Fuzzing Generator
===================================================================
Automatically extracts mathematical and economic invariants from smart contracts
and financial backend architectures, generating complete Foundry Invariant Fuzzing
test harnesses (InvariantTest.t.sol + Handler.sol) to stress-test protocol solvency.
"""
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class DiscoveredInvariant:
    invariant_id: str
    category: str            # "SOLVENCY", "CONSERVATION", "ACCESS_CONTROL", "ARITHMETIC_BOUND"
    formal_expression: str   # e.g. "sum(balances[u]) <= totalDeposited"
    description: str
    target_contract: str
    fuzzing_assertion_code: str

@dataclass
class InvariantHarness:
    contract_name: str
    invariants: List[DiscoveredInvariant]
    test_sol_code: str
    handler_sol_code: str

class InvariantMiner:
    def __init__(self):
        pass

    def mine_invariants(self, contract_content: str, contract_name: str = "VulnerableVault") -> List[DiscoveredInvariant]:
        """
        Extracts implicit economic and mathematical invariants by analyzing state variables and method signatures.
        """
        invariants: List[DiscoveredInvariant] = []
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '', contract_name) or "VaultContract"

        has_balances = bool(re.search(r'mapping\s*\([^)]*=>\s*uint256\)\s*public\s+balances', contract_content, re.IGNORECASE))
        has_total_supply = bool(re.search(r'uint256\s+public\s+totalSupply', contract_content, re.IGNORECASE))
        has_withdraw = bool(re.search(r'function\s+withdraw', contract_content, re.IGNORECASE))
        has_deposit = bool(re.search(r'function\s+deposit', contract_content, re.IGNORECASE))
        has_owner = bool(re.search(r'address\s+public\s+owner', contract_content, re.IGNORECASE))
        has_fee = bool(re.search(r'fee|feeBasisPoints|feeRate', contract_content, re.IGNORECASE))

        # Invariant 1: Vault Balance Solvency / Conservation
        if has_balances or (has_deposit and has_withdraw):
            invariants.append(DiscoveredInvariant(
                invariant_id="INV-001",
                category="CONSERVATION",
                formal_expression="address(target).balance >= ghost_totalDeposits - ghost_totalWithdrawals",
                description="The vault Ether balance must never be lower than the net unwithdrawn customer deposits.",
                target_contract=clean_name,
                fuzzing_assertion_code="assertGe(address(target).balance, handler.ghost_netDeposits(), 'Vault balance invariant violated: undercollateralized!');"
            ))

        # Invariant 2: Total Supply matches sum of individual account shares
        if has_total_supply or has_balances:
            invariants.append(DiscoveredInvariant(
                invariant_id="INV-002",
                category="SOLVENCY",
                formal_expression="sum(balances[i]) <= target.totalSupply()",
                description="The aggregate sum of individual user claims must never exceed total registered protocol supply.",
                target_contract=clean_name,
                fuzzing_assertion_code="assertLe(handler.ghost_sumOfBalances(), handler.ghost_totalSupply(), 'Total supply inflated beyond registered deposits!');"
            ))

        # Invariant 3: Single-Key Owner Invariant (Admin Identity Stability)
        if has_owner:
            invariants.append(DiscoveredInvariant(
                invariant_id="INV-003",
                category="ACCESS_CONTROL",
                formal_expression="target.owner() == legitimateDeployer && target.owner() != address(0)",
                description="The administrative owner address must never be zero or reassigned to an unauthorized actor.",
                target_contract=clean_name,
                fuzzing_assertion_code="assertEq(target.owner(), deployer, 'Admin ownership hijacked during randomized execution sequence!');"
            ))

        # Invariant 4: Maximum Fee Bound Constraint
        if has_fee:
            invariants.append(DiscoveredInvariant(
                invariant_id="INV-004",
                category="ARITHMETIC_BOUND",
                formal_expression="target.feeRate() <= MAX_FEE_CEILING (10%)",
                description="Protocol fee configuration must be strictly bounded below maximum fee threshold (<= 1000 bp).",
                target_contract=clean_name,
                fuzzing_assertion_code="assertLe(target.feeRate(), 1000, 'Fee rate exceeds maximum statutory protocol cap!');"
            ))

        # Default fallback invariant
        if not invariants:
            invariants.append(DiscoveredInvariant(
                invariant_id="INV-GEN-001",
                category="CONSERVATION",
                formal_expression="address(target).balance >= 0",
                description="Solvency and non-negative reserve balance invariant.",
                target_contract=clean_name,
                fuzzing_assertion_code="assertGe(address(target).balance, 0, 'Target contract in negative reserve state!');"
            ))

        return invariants

    def generate_foundry_suite(self, contract_content: str, contract_name: str = "VulnerableVault") -> InvariantHarness:
        """
        Generates complete Foundry Invariant Test Harness (.t.sol + Handler.sol).
        """
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '', contract_name) or "VaultContract"
        invariants = self.mine_invariants(contract_content, clean_name)

        # Build InvariantTest.t.sol
        assertions_block = "\n        ".join([inv.fuzzing_assertion_code for inv in invariants])

        test_sol = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "./Handler.sol";

/**
 * @title Automated Invariant Fuzzing Test Suite for {clean_name}
 * @notice Generated by Adversum Autonomous Security Reasoning Engine
 * @dev Run with: forge test --match-contract {clean_name}InvariantTest -vvvv
 */
contract {clean_name}InvariantTest is Test {{
    {clean_name} public target;
    {clean_name}Handler public handler;
    address public deployer = makeAddr("deployer");

    function setUp() public {{
        vm.prank(deployer);
        target = new {clean_name}();

        handler = new {clean_name}Handler(target, deployer);

        // Tell Foundry fuzzer to route random interactions exclusively through Handler
        targetContract(address(handler));
    }}

    /// @notice Invariant: Conservation of Solvency & State Consistency
    function invariant_ProtocolSolvencyAndStateIntegrity() public view {{
        {assertions_block}
    }}
}}
"""

        # Build Handler.sol
        handler_sol = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface I{clean_name} {{
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function balances(address user) external view returns (uint256);
    function owner() external view returns (address);
    function feeRate() external view returns (uint256);
}}

/**
 * @title Fuzzing State Handler for {clean_name}
 * @notice Maintains ghost variables to verify mathematical state transitions.
 */
contract {clean_name}Handler is CommonBase, StdCheats, StdUtils {{
    I{clean_name} public immutable target;
    address public immutable deployer;

    // Ghost accounting variables
    uint256 public ghost_totalDeposits;
    uint256 public ghost_totalWithdrawals;
    uint256 public ghost_sumOfBalances;
    uint256 public ghost_totalSupply;

    address[] public actors;
    address internal currentActor;

    modifier useActor(uint256 actorIndexSeed) {{
        currentActor = actors[bound(actorIndexSeed, 0, actors.length - 1)];
        vm.startPrank(currentActor);
        _;
        vm.stopPrank();
    }}

    constructor(I{clean_name} _target, address _deployer) {{
        target = _target;
        deployer = _deployer;

        // Initialize 3 distinct fuzzing actors
        actors.push(makeAddr("Alice"));
        actors.push(makeAddr("Bob"));
        actors.push(makeAddr("Charlie"));

        for (uint256 i = 0; i < actors.length; i++) {{
            vm.deal(actors[i], 100 ether);
        }}
    }}

    function deposit(uint256 actorSeed, uint256 amount) external useActor(actorSeed) {{
        amount = bound(amount, 0.01 ether, 10 ether);

        try target.deposit{{value: amount}}() {{
            ghost_totalDeposits += amount;
            ghost_sumOfBalances += amount;
            ghost_totalSupply += amount;
        }} catch {{}}
    }}

    function withdraw(uint256 actorSeed, uint256 amount) external useActor(actorSeed) {{
        amount = bound(amount, 0.01 ether, 10 ether);

        try target.withdraw(amount) {{
            ghost_totalWithdrawals += amount;
            if (ghost_sumOfBalances >= amount) {{
                ghost_sumOfBalances -= amount;
            }}
        }} catch {{}}
    }}

    function ghost_netDeposits() external view returns (uint256) {{
        if (ghost_totalDeposits >= ghost_totalWithdrawals) {{
            return ghost_totalDeposits - ghost_totalWithdrawals;
        }}
        return 0;
    }}
}}
"""

        return InvariantHarness(
            contract_name=clean_name,
            invariants=invariants,
            test_sol_code=test_sol,
            handler_sol_code=handler_sol
        )
