#!/usr/bin/env python3
"""
Adversum Threat Hunter — Bytecode & Transaction Heuristics
Phase 5 — Rapid detection of honeypots, delegatecall proxies, selfdestruct,
and unverified contract exploit patterns.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional


@dataclass
class HunterFinding:
    detector_id: str
    severity: str             # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    target_address: str
    block_number: int
    tx_hash: str
    estimated_impact_usd: float
    confidence: float
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BytecodeHeuristicsEngine:
    """Performs rapid static triage on EVM contract creation bytecode."""

    # EVM Opcodes
    OP_DELEGATECALL = "f4"
    OP_SELFDESTRUCT = "ff"
    OP_CREATE2 = "f5"
    OP_ORIGIN = "32"

    def analyze_bytecode(
        self,
        bytecode_hex: str,
        contract_address: str,
        block_number: int,
        tx_hash: str,
    ) -> List[HunterFinding]:
        findings: List[HunterFinding] = []
        code = bytecode_hex.lower().replace("0x", "")

        if not code or len(code) < 10:
            return findings

        # 1. Unbounded / Unchecked Delegatecall
        if self.OP_DELEGATECALL in code:
            findings.append(HunterFinding(
                detector_id="HUNT-001",
                severity="HIGH",
                title="Delegatecall Proxy Pattern Detected in Unverified Contract",
                description=(
                    f"Contract at {contract_address} incorporates DELEGATECALL opcode (0xF4). "
                    "If unverified or pointing to mutable storage slot, attacker can execute arbitrary state takeover."
                ),
                target_address=contract_address,
                block_number=block_number,
                tx_hash=tx_hash,
                estimated_impact_usd=150_000.0,
                confidence=0.88,
                remediation="Ensure implementation slot is ERC-1967 compliant and storage collision tests pass.",
            ))

        # 2. Selfdestruct Opcode
        if self.OP_SELFDESTRUCT in code:
            findings.append(HunterFinding(
                detector_id="HUNT-002",
                severity="CRITICAL",
                title="Selfdestruct Opcode Present in Deployed Bytecode",
                description=(
                    f"Contract at {contract_address} contains SELFDESTRUCT opcode (0xFF). "
                    "Can be triggered to wipe contract storage or force-send ether to bypass invariants."
                ),
                target_address=contract_address,
                block_number=block_number,
                tx_hash=tx_hash,
                estimated_impact_usd=500_000.0,
                confidence=0.95,
                remediation="Eliminate selfdestruct in line with EIP-6780 / Dencun EVM behavior.",
            ))

        # 3. Phishing Auth via tx.origin
        if self.OP_ORIGIN in code:
            findings.append(HunterFinding(
                detector_id="HUNT-003",
                severity="MEDIUM",
                title="Potential tx.origin Authentication Check",
                description=(
                    f"Contract at {contract_address} reads ORIGIN (0x32). "
                    "Susceptible to phishing attacks where user calling intermediate contract loses authority."
                ),
                target_address=contract_address,
                block_number=block_number,
                tx_hash=tx_hash,
                estimated_impact_usd=75_000.0,
                confidence=0.82,
                remediation="Replace tx.origin with msg.sender.",
            ))

        # 4. Metamorphic / CREATE2 Factory
        if self.OP_CREATE2 in code:
            findings.append(HunterFinding(
                detector_id="HUNT-004",
                severity="MEDIUM",
                title="CREATE2 Metamorphic Deployment Factory",
                description=(
                    f"Contract at {contract_address} employs CREATE2 (0xF5) for deterministic deployment. "
                    "Enables metamorphic contract code replacement if paired with selfdestruct."
                ),
                target_address=contract_address,
                block_number=block_number,
                tx_hash=tx_hash,
                estimated_impact_usd=250_000.0,
                confidence=0.85,
                remediation="Verify initialization parameters and audit salt entropy generation.",
            ))

        return findings
