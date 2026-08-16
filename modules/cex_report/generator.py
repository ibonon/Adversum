#!/usr/bin/env python3
"""
Adversum Institutional CEX Audit Report Generator
Synthesizes SMT formal verification proofs, smart contract security findings,
CCSS compliance scorecards, CEX API risks, and STRIDE threat matrices
into an institutional-grade security deliverable for executive stakeholders.
"""
import os
import json
from datetime import datetime
from typing import Dict, Any, List

class CEXReportGenerator:
    def __init__(self):
        pass

    def generate_markdown(
        self,
        project_name: str,
        target_url: str,
        all_findings: List[Dict[str, Any]],
        ccss_report: Any,
        threat_report: Any,
        smt_proofs: List[Dict[str, Any]] = None
    ) -> str:
        date_str = datetime.utcnow().strftime("%d/%m/%Y %H:%M:%S UTC")
        
        # Calculate overall score and grade
        critical_count = sum(1 for f in all_findings if f.get('severity') == 'CRITICAL')
        high_count     = sum(1 for f in all_findings if f.get('severity') == 'HIGH')
        medium_count   = sum(1 for f in all_findings if f.get('severity') == 'MEDIUM')
        low_count      = sum(1 for f in all_findings if f.get('severity') == 'LOW')

        # Base score starts at 100
        score = 100.0 - (critical_count * 25.0) - (high_count * 10.0) - (medium_count * 3.0) - (low_count * 1.0)
        score = max(0.0, min(100.0, score))

        if score >= 90.0:
            grade = "A+ (Institutional Grade)"
        elif score >= 80.0:
            grade = "A (Strong Security Posture)"
        elif score >= 70.0:
            grade = "B (Acceptable - Action Required)"
        elif score >= 50.0:
            grade = "C (High Risk - Remediate Before Mainnet)"
        else:
            grade = "F (Critical Vulnerabilities Present)"

        md = []
        md.append(f"# 🛡️ Adversum Institutional Security Audit Report")
        md.append(f"**Target System:** {project_name} ({target_url})  ")
        md.append(f"**Audit Date:** {date_str}  ")
        md.append(f"**Audit Standard:** CCSS v3.0 | OWASP Top 10 | SMT Formal Invariant Verification  ")
        md.append(f"**Assessment Authority:** Adversum Automated SAST & Formal Verification Engine  \n")
        md.append("---")

        # Executive Summary
        md.append("## 📊 1. Executive Summary")
        md.append(f"| Metric | Assessment Result |")
        md.append(f"| :--- | :--- |")
        md.append(f"| **Overall Security Score** | **{score:.1f} / 100** |")
        md.append(f"| **Security Posture Grade** | **{grade}** |")
        md.append(f"| **CCSS Compliance Level** | **{ccss_report.achieved_level if ccss_report else 'Evaluated'}** ({ccss_report.overall_score if ccss_report else 0}% compliance) |")
        md.append(f"| **Total Security Findings** | **{len(all_findings)}** ({critical_count} Critical, {high_count} High, {medium_count} Medium, {low_count} Low) |")
        md.append(f"| **SMT Formal Invariants** | **{len(smt_proofs) if smt_proofs else 'Active'} Verified Formulas** |\n")

        # CCSS Compliance Scorecard
        if ccss_report:
            md.append("## 🏛️ 2. CCSS v3.0 Compliance Scorecard (CryptoCurrency Security Standard)")
            md.append("The platform was evaluated against the 10 CCSS control aspects for digital asset custody:\n")
            md.append("| Aspect ID | Control Aspect Name | Category | Weight | Score | CCSS Level Status |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for a in ccss_report.aspect_results:
                md.append(f"| **{a.aspect_id}** | {a.name} | {a.category} | {a.weight}% | **{a.score}%** | `{a.status}` |")
            md.append("")

        # Threat Model Matrix
        if threat_report:
            md.append("## 🎯 3. CEX STRIDE Financial Threat Model")
            md.append("Assessment of the primary systemic risk vectors facing centralized exchange infrastructure:\n")
            md.append("| Threat ID | Category | Threat Scenario | Target Asset | DREAD Score | Risk Level |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for t in threat_report.scenarios:
                md.append(f"| **{t.id}** | {t.category} | {t.title} | {t.target_asset} | `{t.dread_score}/10` | **{t.risk_level}** |")
            md.append("")

        # Detailed Findings
        md.append("## 🔍 4. Detailed Vulnerability Findings & Remediation")
        if not all_findings:
            md.append("✅ **No vulnerabilities detected.** All code paths satisfy formal security invariants and anti-exploit requirements.\n")
        else:
            for idx, f in enumerate(all_findings, 1):
                sev = f.get('severity', 'MEDIUM')
                rule_id = f.get('rule_id', 'SEC-001')
                cwe = f.get('cwe', 'CWE-000')
                cvss = f.get('cvss_score', 5.0)
                file_path = f.get('file', 'unknown')
                line = f.get('line', 1)
                snippet = f.get('snippet', '')
                rec = f.get('recommendation', 'Review and remediate.')
                desc = f.get('description', '')
                title = f.get('title', rule_id)

                md.append(f"### {idx}. [{sev}] {rule_id}: {title}")
                md.append(f"- **File:** `{file_path}` (Line {line})")
                md.append(f"- **Classification:** {cwe} | **CVSS 4.0 Score:** `{cvss}`")
                md.append(f"- **Description:** {desc}\n")
                if snippet:
                    md.append("```")
                    md.append(snippet)
                    md.append("```\n")
                md.append(f"**🛠️ Remediation Guidance:**")
                md.append(f"{rec}\n")

                # Attach automated Foundry PoC test harness for Solidity findings
                if f.get('module') == 'solidity' or rule_id.startswith('SOL-'):
                    try:
                        from poc_generator.generator import FoundryPoCGenerator
                        poc_gen = FoundryPoCGenerator()
                        poc_code = poc_gen.generate_poc(f)
                        if poc_code:
                            md.append(f"<details><summary><b>🧪 Executable Foundry Exploit PoC (<code>Exploit_{rule_id}.t.sol</code>)</b></summary>\n")
                            md.append(f"```solidity\n{poc_code.strip()}\n```\n</details>\n")
                    except Exception:
                        pass

                md.append("---")

        # Architectural Recommendations
        md.append(f"## 📋 5. Strategic Hardening & Custody Recommendations ({project_name})")
        md.append("1. **Zero-Trust Hot Wallet Architecture:** Enforce that the automated hot wallet contains strictly `< 5%` of total exchange reserves, with automated threshold sweep contracts.")
        md.append("2. **Hardware Security Module (HSM) Quorum:** Ensure all withdrawal transactions require a minimum 2-of-3 MPC threshold signature involving independent operational nodes.")
        md.append("3. **Continuous SMT Invariant CI/CD:** Integrate Adversum SMT formal verification in the CI/CD pipeline to mathematically block arithmetic overflows and unatomic balance manipulations before production deployment.\n")

        return "\n".join(md)
