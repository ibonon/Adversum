"""
Adversum Heuristics Engine v2 — 15+ new bytecode/source rules for EVM smart contracts.
Covers: CREATE2 salt abuse, delegatecall chains, proxy patterns, selfdestruct,
         reentrancy cross-function, flash-loan gate bypass, and more.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List


class HeuristicSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class HeuristicMatch:
    rule_id: str
    severity: HeuristicSeverity
    title: str
    description: str
    recommendation: str
    line: int = 0
    snippet: str = ""
    confidence: float = 0.9


# ── Rule definitions ──────────────────────────────────────────────────────────

_RULES: List[dict] = [
    # ── CRITICAL ─────────────────────────────────────────────────────────────
    {
        "rule_id": "HEU-001",
        "severity": HeuristicSeverity.CRITICAL,
        "pattern": r"selfdestruct\s*\(|suicide\s*\(",
        "title": "Selfdestruct / Suicide Detected",
        "description": "Contract can be destroyed via selfdestruct/suicide. If access is not properly restricted, an attacker can permanently destroy the contract and steal all Ether.",
        "recommendation": "Remove selfdestruct or add strict multi-sig / timelock access control with a 48h delay.",
        "confidence": 0.95,
    },
    {
        "rule_id": "HEU-002",
        "severity": HeuristicSeverity.CRITICAL,
        "pattern": r"\.delegatecall\s*\(",
        "title": "Unguarded delegatecall",
        "description": "delegatecall executes code from an arbitrary address in the caller's storage context. A malicious implementation contract can overwrite critical storage slots.",
        "recommendation": "Validate the target address against an allowlist. Use OpenZeppelin's TransparentUpgradeableProxy pattern.",
        "confidence": 0.92,
    },
    {
        "rule_id": "HEU-003",
        "severity": HeuristicSeverity.CRITICAL,
        "pattern": r"tx\.origin\s*==|tx\.origin\s*!=",
        "title": "tx.origin Authentication Bypass",
        "description": "Using tx.origin for authorization allows phishing attacks: a malicious contract can call your contract on behalf of the victim.",
        "recommendation": "Replace tx.origin with msg.sender for all authentication checks.",
        "confidence": 0.98,
    },
    {
        "rule_id": "HEU-004",
        "severity": HeuristicSeverity.CRITICAL,
        "pattern": r"call\s*\{[^}]*value\s*:\s*[^}]*\}\s*\([^)]*\).*?\n.*?(?:balances|balance|amount)",
        "title": "Reentrancy: CEI Pattern Violation",
        "description": "External call made before state update (Checks-Effects-Interactions violation). Classic reentrancy attack vector.",
        "recommendation": "Reorder code to follow CEI: update all state before making external calls. Add nonReentrant modifier.",
        "confidence": 0.85,
    },
    {
        "rule_id": "HEU-005",
        "severity": HeuristicSeverity.CRITICAL,
        "pattern": r"CREATE2\s*\(",
        "title": "CREATE2 — Deterministic Address Risk",
        "description": "CREATE2 allows predicting contract addresses. If the salt is user-controlled, attackers can pre-deploy malicious contracts to predicted addresses.",
        "recommendation": "Ensure salt includes msg.sender and block.timestamp. Validate deployed bytecode hash matches expected.",
        "confidence": 0.80,
    },

    # ── HIGH ──────────────────────────────────────────────────────────────────
    {
        "rule_id": "HEU-006",
        "severity": HeuristicSeverity.HIGH,
        "pattern": r"block\.timestamp|block\.number|now\b",
        "title": "Block Timestamp / Number Manipulation",
        "description": "Miners can manipulate block.timestamp by up to ~15 seconds. Using it for randomness or time-locked conditions is insecure.",
        "recommendation": "Use Chainlink VRF for randomness. For time locks, prefer block numbers with conservative estimates.",
        "confidence": 0.90,
    },
    {
        "rule_id": "HEU-007",
        "severity": HeuristicSeverity.HIGH,
        "pattern": r"assembly\s*\{",
        "title": "Inline Assembly Usage",
        "description": "Inline assembly bypasses Solidity's safety checks. Memory corruption, stack underflow, and type confusion are possible.",
        "recommendation": "Document each assembly block. Prefer high-level Solidity equivalents where possible. Audit all assembly paths.",
        "confidence": 0.75,
    },
    {
        "rule_id": "HEU-008",
        "severity": HeuristicSeverity.HIGH,
        "pattern": r"unchecked\s*\{",
        "title": "Unchecked Arithmetic Block",
        "description": "Solidity 0.8+ protects against overflow/underflow by default. The unchecked block disables this protection — integer overflow could lead to draining funds.",
        "recommendation": "Verify each arithmetic operation inside unchecked blocks cannot overflow. Document why unchecked is safe.",
        "confidence": 0.88,
    },
    {
        "rule_id": "HEU-009",
        "severity": HeuristicSeverity.HIGH,
        "pattern": r"flashloan|flash_loan|FlashLoan",
        "title": "Flash Loan Attack Vector",
        "description": "Flash loans allow borrowing unlimited liquidity in a single transaction. Price oracle manipulation and governance attacks are common vectors.",
        "recommendation": "Use TWAP oracles (Uniswap v3) not spot prices. Add flash-loan protection: check contract balance hasn't changed.",
        "confidence": 0.82,
    },
    {
        "rule_id": "HEU-010",
        "severity": HeuristicSeverity.HIGH,
        "pattern": r"\.call\s*\{[^}]*\}\s*\(",
        "title": "Low-Level call() — Return Value Unchecked Risk",
        "description": "Low-level call() does not revert on failure. If the return value is ignored, failed transfers silently pass.",
        "recommendation": "Always check bool success = address.call{...}(...); require(success, 'call failed');",
        "confidence": 0.87,
    },

    # ── MEDIUM ────────────────────────────────────────────────────────────────
    {
        "rule_id": "HEU-011",
        "severity": HeuristicSeverity.MEDIUM,
        "pattern": r"price.*oracle|oracle.*price|getPrice\s*\(",
        "title": "Price Oracle — Manipulation Risk",
        "description": "Single-source price oracles can be manipulated within a block using flash loans or large trades.",
        "recommendation": "Use multi-source TWAP oracles. Implement circuit breakers for >5% price deviation.",
        "confidence": 0.78,
    },
    {
        "rule_id": "HEU-012",
        "severity": HeuristicSeverity.MEDIUM,
        "pattern": r"delegatecall|callcode",
        "title": "Proxy Pattern — Storage Collision Risk",
        "description": "Proxy contracts using delegatecall can have storage slot collisions between proxy and implementation. Can lead to admin slot overwrite.",
        "recommendation": "Use EIP-1967 standardized storage slots. Use OpenZeppelin's upgradeable contracts.",
        "confidence": 0.80,
    },
    {
        "rule_id": "HEU-013",
        "severity": HeuristicSeverity.MEDIUM,
        "pattern": r"ecrecover\s*\(",
        "title": "ecrecover — Signature Malleability",
        "description": "ecrecover returns address(0) for invalid signatures instead of reverting. Signature malleability allows replay attacks.",
        "recommendation": "Use OpenZeppelin ECDSA.recover() which validates s < secp256k1n/2 and v in {27,28}.",
        "confidence": 0.85,
    },
    {
        "rule_id": "HEU-014",
        "severity": HeuristicSeverity.MEDIUM,
        "pattern": r"transfer\s*\(\s*\d+\s*\)|transfer\s*\(\s*amount",
        "title": "ERC20 transfer() — No Return Value Check",
        "description": "Some ERC20 tokens (USDT, BNB) do not revert on failed transfer. Calling transfer() without checking the return value silently fails.",
        "recommendation": "Use OpenZeppelin SafeERC20.safeTransfer() for all token transfers.",
        "confidence": 0.82,
    },
    {
        "rule_id": "HEU-015",
        "severity": HeuristicSeverity.MEDIUM,
        "pattern": r"receive\s*\(\s*\)\s*external\s*payable|fallback\s*\(\s*\)\s*external",
        "title": "Unrestricted Fallback / Receive Function",
        "description": "Fallback and receive functions without proper guards can be exploited to force Ether into contracts that don't expect it.",
        "recommendation": "Add explicit logic or emit events in fallback/receive. Validate msg.value > 0.",
        "confidence": 0.72,
    },

    # ── LOW ───────────────────────────────────────────────────────────────────
    {
        "rule_id": "HEU-016",
        "severity": HeuristicSeverity.LOW,
        "pattern": r"^\s*//\s*(TODO|FIXME|HACK|XXX|BUG)",
        "title": "Unresolved TODO/FIXME Comment",
        "description": "Code comments indicate unresolved issues that may represent security gaps or incomplete implementations.",
        "recommendation": "Resolve all TODO/FIXME comments before deployment. Track them in issue tracker.",
        "confidence": 0.60,
    },
    {
        "rule_id": "HEU-017",
        "severity": HeuristicSeverity.LOW,
        "pattern": r"console\.log|hardhat/console",
        "title": "Debug Statements Left in Code",
        "description": "console.log from Hardhat leaks internal state and increases gas consumption.",
        "recommendation": "Remove all console.log statements before production deployment.",
        "confidence": 0.99,
    },
]


# ── Engine ────────────────────────────────────────────────────────────────────

class HeuristicsEngineV2:
    """
    Stateless multi-rule scanner.
    Applies all 17 rules to source text and returns all matches.
    """

    def __init__(self):
        self._rules = _RULES
        self._compiled = [
            (r, re.compile(r["pattern"], re.IGNORECASE | re.MULTILINE))
            for r in self._rules
        ]

    def scan(self, source: str, filename: str = "") -> List[HeuristicMatch]:
        """Scan source text against all rules. Returns sorted findings (CRITICAL first)."""
        results: List[HeuristicMatch] = []
        lines = source.splitlines()

        for rule, compiled in self._compiled:
            for m in compiled.finditer(source):
                # Compute line number
                line_no = source[: m.start()].count("\n") + 1
                snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""

                results.append(HeuristicMatch(
                    rule_id=rule["rule_id"],
                    severity=rule["severity"],
                    title=rule["title"],
                    description=rule["description"],
                    recommendation=rule["recommendation"],
                    line=line_no,
                    snippet=snippet,
                    confidence=rule["confidence"],
                ))

        # Sort: CRITICAL > HIGH > MEDIUM > LOW > INFO
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        results.sort(key=lambda r: sev_order.get(r.severity.value, 9))
        return results

    def scan_files(self, files: List[dict]) -> List[dict]:
        """
        Scan a list of {'path': str, 'content': str} dicts.
        Returns a flat list of finding dicts.
        """
        findings = []
        for f in files:
            matches = self.scan(f.get("content", ""), filename=f.get("path", ""))
            for m in matches:
                findings.append({
                    "rule_id": m.rule_id,
                    "file": f.get("path", ""),
                    "line": m.line,
                    "severity": m.severity.value,
                    "title": m.title,
                    "description": m.description,
                    "recommendation": m.recommendation,
                    "snippet": m.snippet,
                    "confidence": m.confidence,
                })
        return findings

    @property
    def rule_count(self) -> int:
        return len(self._rules)


# Singleton
heuristics_v2 = HeuristicsEngineV2()
