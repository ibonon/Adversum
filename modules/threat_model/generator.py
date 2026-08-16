#!/usr/bin/env python3
"""
Adversum CEX Threat Modeling Generator (STRIDE-Financial v2.0)
Generates comprehensive risk matrices, DREAD scoring, and Attack Trees
for Centralized Cryptocurrency Exchanges and DeFi Gateways.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class ThreatScenario:
    id: str
    category: str              # Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege, Financial
    title: str
    target_asset: str
    attack_vector: str
    impact_description: str
    dread_score: float         # 0.0 - 10.0
    risk_level: str            # CRITICAL, HIGH, MEDIUM, LOW
    mitigation_controls: List[str]

@dataclass
class CEXThreatModelReport:
    total_scenarios: int
    risk_summary: Dict[str, int]
    scenarios: List[ThreatScenario]
    key_assets_mapped: List[str]

class CEXThreatModelGenerator:
    def __init__(self):
        self.standard_scenarios = [
            ThreatScenario(
                id="THREAT-CEX-01",
                category="Elevation of Privilege",
                title="Hot Wallet Signer Node Compromise",
                target_asset="Hot Wallet Private Keys / MPC Key Shares",
                attack_vector="RCE or supply-chain compromise of hot-wallet daemon node triggering unauthorized automated sweeps.",
                impact_description="Direct theft of all liquid hot wallet cryptocurrency reserves (<5% of total AUM).",
                dread_score=9.6,
                risk_level="CRITICAL",
                mitigation_controls=[
                    "FIPS 140-2/3 Level 3 Cloud HSM / MPC with 2-of-3 quorum requirement.",
                    "Strict hourly and daily velocity caps enforced independently at the HSM policy layer.",
                    "Automated circuit-breaker freezing all hot wallet transfers on anomaly detection."
                ]
            ),
            ThreatScenario(
                id="THREAT-CEX-02",
                category="Tampering",
                title="Concurrent Race Condition on Withdrawal Ledger (Double Spend)",
                target_asset="Exchange User Account Balances",
                attack_vector="Rapid multi-threaded withdrawal requests exploiting un-isolated SQL transactions before balance decrement.",
                impact_description="Over-withdrawal of customer deposits resulting in platform balance deficit.",
                dread_score=9.2,
                risk_level="CRITICAL",
                mitigation_controls=[
                    "Row-level locking ('SELECT ... FOR UPDATE') on balance ledger rows.",
                    "Deterministic single-threaded order/withdrawal queue sequencer.",
                    "Idempotency keys and monotonic nonce validation on all financial requests."
                ]
            ),
            ThreatScenario(
                id="THREAT-CEX-03",
                category="Spoofing",
                title="API Key Exfiltration & Unauthorized Trade Execution",
                target_asset="Customer Trading Accounts & API Keys",
                attack_vector="Phishing, XSS, or developer environment leak of HMAC API secret keys allowing attacker to place market orders.",
                impact_description="Account takeover, wash trading, and intentional slippage exploitation to drain user balances.",
                dread_score=8.7,
                risk_level="HIGH",
                mitigation_controls=[
                    "Mandatory IP address whitelisting for all automated trading API keys.",
                    "Separate permission flags (Read-Only vs Trade vs Withdrawal).",
                    "Withdrawal permission requires FIDO2/Hardware 2FA re-authentication and 24h address time-lock."
                ]
            ),
            ThreatScenario(
                id="THREAT-CEX-04",
                category="Denial of Service",
                title="Matching Engine Order Book Flooding (L2/L3 Starvation)",
                target_asset="Central Limit Order Book (CLOB) Matching Engine",
                attack_vector="Submitting millions of microscopic limit orders at unfillable price points to saturate matching engine memory.",
                impact_description="Order execution latency spikes (>500ms), liquidation cascades failure, and market maker disconnection.",
                dread_score=8.2,
                risk_level="HIGH",
                mitigation_controls=[
                    "Order-to-Trade Ratio (OTR) penalties and dynamic cancellation fees.",
                    "Tiered WebSocket/REST token-bucket rate limiters per user tier.",
                    "Minimum notional order value thresholds (e.g. $5 minimum order size)."
                ]
            ),
            ThreatScenario(
                id="THREAT-CEX-05",
                category="Financial & Oracle",
                title="Low-Liquidity Spot Pair Price Manipulation & Collateral Over-Borrowing",
                target_asset="Margin & Futures Lending Pool",
                attack_vector="Manipulating spot order book on illiquid pair to inflate collateral valuation in margin lending system.",
                impact_description="Unbacked borrowing of major assets (BTC, ETH, USDC) leading to bad debt for the exchange pool.",
                dread_score=8.8,
                risk_level="HIGH",
                mitigation_controls=[
                    "Use Volume-Weighted Average Price (VWAP) / TWAP aggregated across multiple external exchanges (Binance, Coinbase).",
                    "Integration with decentralized Chainlink price feeds for index calculation.",
                    "Dynamic borrow caps on low-liquidity collateral assets."
                ]
            ),
            ThreatScenario(
                id="THREAT-CEX-06",
                category="Information Disclosure",
                title="Order Flow Front-Running & Internal Trading Leak",
                target_asset="Internal Order Queue & Customer Pending Trades",
                attack_vector="Malicious insider or unauthenticated internal WebSocket topic leaking pending large market orders.",
                impact_description="Front-running and sandwich attacks against retail customer orders causing reputational damage.",
                dread_score=7.4,
                risk_level="MEDIUM",
                mitigation_controls=[
                    "End-to-end mTLS encryption for all microservice communications.",
                    "Strict role-based access control (RBAC) and audit logging for internal state inspection.",
                    "Sub-millisecond FIFO order matching with zero-knowledge trade sequencing."
                ]
            )
        ]

    def generate_model(self, target_dir: str = "") -> CEXThreatModelReport:
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for s in self.standard_scenarios:
            summary[s.risk_level] = summary.get(s.risk_level, 0) + 1

        assets = [
            "Hot & Cold Wallet Cryptographic Keys (MPC / HSM)",
            "Exchange Off-Chain Account Ledger Database",
            "Central Limit Order Book (CLOB) Matching Engine",
            "Customer Financial Assets (Crypto & Fiat Balances)",
            "External Blockchain RPC & Bridge Gateways",
            "REST / WebSocket Public & Private Trading APIs"
        ]

        return CEXThreatModelReport(
            total_scenarios=len(self.standard_scenarios),
            risk_summary=summary,
            scenarios=self.standard_scenarios,
            key_assets_mapped=assets
        )
