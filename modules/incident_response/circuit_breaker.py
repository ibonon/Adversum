#!/usr/bin/env python3
"""
Adversum Autonomous Circuit Breaker Synthesizer
Phase 4 — Generates tailor-made on-chain circuit breakers, rate limiters,
and automated monitoring policies for smart contracts.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional


@dataclass
class CircuitBreakerConfig:
    protocol_name: str = "DeFiProtocol"
    target_token: str = "USDC"
    max_tvl_outflow_pct_per_window: float = 5.0     # Max 5% drain per window
    window_blocks: int = 10                         # Rolling window (approx 2 minutes)
    max_oracle_divergence_pct: float = 3.5          # Freeze if spot vs TWAP > 3.5%
    enable_flash_loan_guard: bool = True            # Block multiple large calls in same tx/block
    emergency_multisig: str = "0x000000000000000000000000000000000000dEaD"
    timelock_delay_seconds: int = 86400             # 24h timelock for parameter changes


@dataclass
class SynthesizedCircuitBreaker:
    protocol_name: str
    solidity_code: str
    watcher_policy_json: Dict[str, Any]
    active_protections: List[str]
    estimated_gas_overhead: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol_name": self.protocol_name,
            "solidity_code": self.solidity_code,
            "watcher_policy_json": self.watcher_policy_json,
            "active_protections": self.active_protections,
            "estimated_gas_overhead": self.estimated_gas_overhead,
        }


class CircuitBreakerSynthesizer:
    """Synthesizes on-chain Solidity guards and automated incident response policies."""

    def synthesize(self, config: Optional[CircuitBreakerConfig] = None) -> SynthesizedCircuitBreaker:
        cfg = config or CircuitBreakerConfig()

        active_protections = [
            f"TVL Outflow Cap ({cfg.max_tvl_outflow_pct_per_window}% / {cfg.window_blocks} blocks)",
            f"Oracle Divergence Circuit Breaker (Threshold: {cfg.max_oracle_divergence_pct}%)",
        ]
        if cfg.enable_flash_loan_guard:
            active_protections.append("Flash Loan Interaction & Same-Block Reentrancy Guard")
        active_protections.append(f"Emergency Pause Hook (Controller: {cfg.emergency_multisig[:10]}...)")

        solidity_code = self._generate_solidity(cfg)
        policy_json = self._generate_watcher_policy(cfg)

        # Base gas overhead estimation: storage reads + check logic
        gas_overhead = 12500 if cfg.enable_flash_loan_guard else 8200

        return SynthesizedCircuitBreaker(
            protocol_name=cfg.protocol_name,
            solidity_code=solidity_code,
            watcher_policy_json=policy_json,
            active_protections=active_protections,
            estimated_gas_overhead=gas_overhead,
        )

    def _generate_solidity(self, cfg: CircuitBreakerConfig) -> str:
        code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title {cfg.protocol_name} Circuit Breaker & Emergency Guard
 * @notice Generated automatically by Adversum Autonomous Incident Response Suite
 * @dev Protects against flash loan drain cascades, oracle divergence, and rapid pool depletion.
 */

interface IERC20Minimal {{
    function balanceOf(address account) external view returns (uint256);
}}

interface IAggregatorV3 {{
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}}

abstract contract Context {{
    function _msgSender() internal view virtual returns (address) {{
        return msg.sender;
    }}
}}

abstract contract Ownable is Context {{
    address private _owner;
    error OwnableUnauthorizedAccount(address account);
    error OwnableInvalidOwner(address owner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor(address initialOwner) {{
        if (initialOwner == address(0)) revert OwnableInvalidOwner(address(0));
        _transferOwnership(initialOwner);
    }}

    modifier onlyOwner() {{
        _checkOwner();
        _;
    }}

    function owner() public view virtual returns (address) {{
        return _owner;
    }}

    function _checkOwner() internal view virtual {{
        if (owner() != _msgSender()) revert OwnableUnauthorizedAccount(_msgSender());
    }}

    function _transferOwnership(address newOwner) internal virtual {{
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }}
}}

contract {cfg.protocol_name.replace(' ', '')}CircuitBreaker is Ownable {{
    // --- Events ---
    event CircuitBreakerTripped(string reason, uint256 metricValue, uint256 blockNumber);
    event EmergencyPaused(address indexed triggeredBy, uint256 blockNumber);
    event EmergencyUnpaused(address indexed triggeredBy, uint256 blockNumber);
    event ThresholdUpdated(string parameter, uint256 newValue);

    // --- State ---
    bool public isPaused;
    address public emergencyGuardian;
    uint256 public immutable maxOutflowBps = {int(cfg.max_tvl_outflow_pct_per_window * 100)}; // {cfg.max_tvl_outflow_pct_per_window}% in bps
    uint256 public immutable windowBlocks = {cfg.window_blocks};
    uint256 public immutable maxOracleDivergenceBps = {int(cfg.max_oracle_divergence_pct * 100)}; // {cfg.max_oracle_divergence_pct}% in bps

    uint256 public currentWindowStartBlock;
    uint256 public cumulativeWindowOutflow;
    uint256 public referenceTotalSupply;

    // Flash loan guard: record last interaction block per account
    mapping(address => uint256) private _lastInteractionBlock;

    modifier whenNotPaused() {{
        require(!isPaused, "CircuitBreaker: Protocol paused due to security alert");
        _;
    }}

    modifier onlyGuardianOrOwner() {{
        require(msg.sender == owner() || msg.sender == emergencyGuardian, "!guardian");
        _;
    }}

    constructor(address _guardian) Ownable(msg.sender) {{
        emergencyGuardian = _guardian != address(0) ? _guardian : {cfg.emergency_multisig};
        currentWindowStartBlock = block.number;
    }}

    function triggerEmergencyPause(string calldata reason) external onlyGuardianOrOwner {{
        isPaused = true;
        emit EmergencyPaused(msg.sender, block.number);
        emit CircuitBreakerTripped(reason, 0, block.number);
    }}

    function unpause() external onlyOwner {{
        isPaused = false;
        emit EmergencyUnpaused(msg.sender, block.number);
    }}

    /**
     * @notice Enforces outflow limits over a rolling block window.
     * @param outflowAmount USD notional or token units exiting protocol.
     * @param totalReserves Current total reserve or TVL baseline.
     */
    function recordOutflow(uint256 outflowAmount, uint256 totalReserves) external whenNotPaused {{
        if (block.number > currentWindowStartBlock + windowBlocks) {{
            currentWindowStartBlock = block.number;
            cumulativeWindowOutflow = 0;
            referenceTotalSupply = totalReserves;
        }}

        cumulativeWindowOutflow += outflowAmount;

        if (referenceTotalSupply > 0) {{
            uint256 outflowBps = (cumulativeWindowOutflow * 10000) / referenceTotalSupply;
            if (outflowBps > maxOutflowBps) {{
                isPaused = true;
                emit CircuitBreakerTripped("OUTFLOW_RATE_LIMIT_EXCEEDED", outflowBps, block.number);
            }}
        }}
    }}

    /**
     * @notice Checks oracle spot price against TWAP / anchor feed.
     */
    function verifyOracleBounds(uint256 spotPrice, uint256 anchorPrice) external whenNotPaused returns (bool) {{
        if (anchorPrice == 0) return true;
        uint256 delta = spotPrice > anchorPrice ? spotPrice - anchorPrice : anchorPrice - spotPrice;
        uint256 divergenceBps = (delta * 10000) / anchorPrice;

        if (divergenceBps > maxOracleDivergenceBps) {{
            isPaused = true;
            emit CircuitBreakerTripped("ORACLE_DIVERGENCE_EXCEEDED", divergenceBps, block.number);
            return false;
        }}
        return true;
    }}

    /**
     * @notice Prevents same-block flash-loan manipulation re-entrancy.
     */
    function checkFlashLoanConstraint(address caller) external whenNotPaused {{
        if ({str(cfg.enable_flash_loan_guard).lower()}) {{
            require(_lastInteractionBlock[caller] != block.number, "CircuitBreaker: Multiple interactions in same block prohibited");
            _lastInteractionBlock[caller] = block.number;
        }}
    }}
}}
"""
        return code

    def _generate_watcher_policy(self, cfg: CircuitBreakerConfig) -> Dict[str, Any]:
        return {
            "name": f"{cfg.protocol_name} Defensive Monitoring Policy",
            "version": "1.0.0",
            "protocol": cfg.protocol_name,
            "target_token": cfg.target_token,
            "rules": [
                {
                    "rule_id": "RATE_LIMIT_RULE",
                    "type": "outflow_spike",
                    "threshold_pct": cfg.max_tvl_outflow_pct_per_window,
                    "window_blocks": cfg.window_blocks,
                    "action": "triggerEmergencyPause('EXCESSIVE_OUTFLOW')",
                    "severity": "CRITICAL",
                },
                {
                    "rule_id": "ORACLE_DEVIATION_RULE",
                    "type": "price_divergence",
                    "threshold_pct": cfg.max_oracle_divergence_pct,
                    "action": "triggerEmergencyPause('ORACLE_DIVERGENCE')",
                    "severity": "HIGH",
                },
                {
                    "rule_id": "FLASH_LOAN_INTERACTION_RULE",
                    "type": "same_block_high_frequency",
                    "enabled": cfg.enable_flash_loan_guard,
                    "action": "revert('SAME_BLOCK_LIMIT')",
                    "severity": "HIGH",
                },
            ],
            "incident_response_contacts": {
                "guardian_multisig": cfg.emergency_multisig,
                "timelock_delay_seconds": cfg.timelock_delay_seconds,
            },
        }
