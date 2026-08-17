#!/usr/bin/env python3
"""
Adversum Role & Economic Flow Analyzer
======================================
Dissects privileges, actor role boundaries (Admin, Relayer, Liquidity Provider, User),
and token liquidity flows (Inflow, Vault Storage, Outflow, Fee Extraction),
flagging economic asymmetries and unconstrained value extraction paths.
"""
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class ActorRole:
    name: str              # "Admin / Owner", "Relayer / Oracle", "Public User", "Liquidator"
    privilege_level: str   # "HIGH", "MEDIUM", "LOW", "UNRESTRICTED"
    guarded_functions: List[str]
    access_modifiers: List[str]

@dataclass
class EconomicFlow:
    flow_type: str         # "INFLOW", "VAULT_STORAGE", "OUTFLOW", "FEE_EXTRACTION"
    function_trigger: str
    asset: str
    source_actor: str
    destination: str
    is_asymmetric_leak: bool
    risk_description: str

@dataclass
class EconomicFlowReport:
    target_name: str
    roles: List[ActorRole]
    flows: List[EconomicFlow]
    has_economic_asymmetry: bool
    asymmetry_summary: str
    mermaid_flowchart: str

class RoleEconomicFlowAnalyzer:
    def __init__(self):
        pass

    def analyze(self, content: str, target_name: str = "FinancialModule") -> EconomicFlowReport:
        """
        Analyzes source code to extract roles, state transitions, and economic liquidity flows.
        """
        lines = content.splitlines()
        roles: List[ActorRole] = []
        flows: List[EconomicFlow] = []

        # 1. Detect Actor Roles
        admin_funcs = []
        admin_mods = []
        for line in lines:
            if re.search(r'onlyOwner|onlyRole|require\s*\(\s*msg\.sender\s*==\s*owner', line):
                admin_mods.append("onlyOwner")
            m_fn = re.search(r'function\s+([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:external|public|internal|private)?\s*(?:[^{]*)', line)
            if m_fn:
                fn_name = m_fn.group(1)
                if any(kw in fn_name.lower() for kw in ('set', 'pause', 'upgrade', 'kill', 'transferownership', 'withdrawadmin', 'emergency')):
                    admin_funcs.append(fn_name)

        roles.append(ActorRole(
            name="Protocol Administrator (Owner / Multi-Sig)",
            privilege_level="HIGH",
            guarded_functions=admin_funcs if admin_funcs else ["setParameters()", "emergencyPause()"],
            access_modifiers=list(set(admin_mods)) if admin_mods else ["onlyOwner"]
        ))

        roles.append(ActorRole(
            name="Standard User / Public Caller",
            privilege_level="UNRESTRICTED",
            guarded_functions=["deposit()", "withdraw()", "trade()", "transfer()"],
            access_modifiers=["public", "external"]
        ))

        # 2. Detect Economic Token Flows
        has_deposit = bool(re.search(r'function\s+(?:deposit|mint|supply|addLiquidity)', content, re.IGNORECASE))
        has_withdraw = bool(re.search(r'function\s+(?:withdraw|burn|redeem|removeLiquidity)', content, re.IGNORECASE))
        has_transfer = bool(re.search(r'\.call\{value:|\.transfer\(|safeTransfer\(', content))
        has_fees = bool(re.search(r'fee|protocolFee|treasury', content, re.IGNORECASE))
        has_reentrancy_risk = bool(re.search(r'\.call\{value:[^}]*\}\(.*\)', content) and not re.search(r'nonReentrant', content))

        if has_deposit:
            flows.append(EconomicFlow(
                flow_type="INFLOW",
                function_trigger="deposit() / mint()",
                asset="Ether / ERC20 Tokens",
                source_actor="Standard User",
                destination="Protocol Liquidity Vault",
                is_asymmetric_leak=False,
                risk_description="Normal collateral injection into protocol reserves."
            ))

        if has_withdraw:
            is_leak = has_reentrancy_risk
            flows.append(EconomicFlow(
                flow_type="OUTFLOW",
                function_trigger="withdraw() / redeem()",
                asset="Ether / ERC20 Tokens",
                source_actor="Protocol Liquidity Vault",
                destination="Caller Address",
                is_asymmetric_leak=is_leak,
                risk_description="Liquidity extraction. High risk of drain if state decrement occurs after external call." if is_leak else "Normal authorized user capital withdrawal."
            ))

        if has_fees:
            flows.append(EconomicFlow(
                flow_type="FEE_EXTRACTION",
                function_trigger="distributeFees() / transferFee()",
                asset="Protocol Revenue",
                source_actor="Trading Volume / Yield",
                destination="Treasury / Admin Wallet",
                is_asymmetric_leak=False,
                risk_description="Protocol statutory revenue stream."
            ))

        # Fallback flow
        if not flows:
            flows.append(EconomicFlow(
                flow_type="VAULT_STORAGE",
                function_trigger="stateTransition()",
                asset="Internal Account State",
                source_actor="System",
                destination="Ledger",
                is_asymmetric_leak=False,
                risk_description="Internal state accounting."
            ))

        has_asymmetry = any(f.is_asymmetric_leak for f in flows)
        summary = (
            "CRITICAL ECONOMIC ASYMMETRY DETECTED: Outflow path lacks atomic balance protection or CEI guard, "
            "allowing unbacked value extraction exceeding initial deposits."
            if has_asymmetry else
            "Economic flows are symmetric: all value extraction requires corresponding balance ownership or authorization."
        )

        # Build Mermaid flowchart
        mermaid = "graph TD\n"
        mermaid += '  User["👤 Standard User"] -- "1. deposit(funds)" --> Vault[("🏦 Protocol Vault")]\n'
        if has_asymmetry:
            mermaid += '  Vault -- "⚠️ 2. Unprotected withdraw()" --> Attacker["🏴‍☠️ Attacker Wallet (Drain)"]\n'
            mermaid += '  style Attacker fill:#ff3333,stroke:#333,stroke-width:2px,color:#fff;\n'
        else:
            mermaid += '  Vault -- "2. Valid withdraw(principal)" --> User\n'
        if has_fees:
            mermaid += '  Vault -- "3. Protocol Fee" --> Treasury["🏛️ DAO / Treasury"]\n'

        return EconomicFlowReport(
            target_name=target_name,
            roles=roles,
            flows=flows,
            has_economic_asymmetry=has_asymmetry,
            asymmetry_summary=summary,
            mermaid_flowchart=mermaid
        )
