"""
Adversum Universal Multi-Engine Consensus & Correlation Matrix
=============================================================
Unifies findings across Adversum Core, Semgrep, Slither, Aderyn, Trivy, and AST scanners.
Provides:
  1. Semantic Finding Deduplication & Clustering
  2. Multi-Engine Quorum Consensus Confidence (0-100%)
  3. Universal Compliance Mapping (CWE, OWASP, MITRE ATT&CK, CCSS, STRIDE)
"""

import os
import re
from typing import List, Dict, Any, Optional
from collections import defaultdict

# ── Compliance Standards Knowledge Base ──────────────────────────────────────

CWE_MAPPING = {
    "reentrancy": {"cwe_id": "CWE-841", "name": "Improper Enforcement of Behavioral Workflow", "url": "https://cwe.mitre.org/data/definitions/841.html"},
    "tx.origin": {"cwe_id": "CWE-302", "name": "Authentication Bypass by Assumed-Immutable Data", "url": "https://cwe.mitre.org/data/definitions/302.html"},
    "overflow": {"cwe_id": "CWE-190", "name": "Integer Overflow or Wraparound", "url": "https://cwe.mitre.org/data/definitions/190.html"},
    "delegatecall": {"cwe_id": "CWE-829", "name": "Inclusion of Functionality from Untrusted Control Sphere", "url": "https://cwe.mitre.org/data/definitions/829.html"},
    "flash_loan": {"cwe_id": "CWE-682", "name": "Incorrect Calculation (Price Oracle Manipulation)", "url": "https://cwe.mitre.org/data/definitions/682.html"},
    "oracle": {"cwe_id": "CWE-682", "name": "Incorrect Calculation (Stale/Manipulated Oracle)", "url": "https://cwe.mitre.org/data/definitions/682.html"},
    "md5": {"cwe_id": "CWE-328", "name": "Use of Weak Hash", "url": "https://cwe.mitre.org/data/definitions/328.html"},
    "ecb": {"cwe_id": "CWE-327", "name": "Use of Broken/Risky Cryptographic Algorithm", "url": "https://cwe.mitre.org/data/definitions/327.html"},
    "eval": {"cwe_id": "CWE-95", "name": "Improper Neutralization of Directives in Dynamically Evaluated Code", "url": "https://cwe.mitre.org/data/definitions/95.html"},
    "system": {"cwe_id": "CWE-78", "name": "OS Command Injection", "url": "https://cwe.mitre.org/data/definitions/78.html"},
    "open": {"cwe_id": "CWE-22", "name": "Improper Limitation of a Pathname (Path Traversal)", "url": "https://cwe.mitre.org/data/definitions/22.html"},
    "hardcoded_key": {"cwe_id": "CWE-798", "name": "Use of Hard-coded Credentials", "url": "https://cwe.mitre.org/data/definitions/798.html"},
    "jwt": {"cwe_id": "CWE-347", "name": "Improper Verification of Cryptographic Signature", "url": "https://cwe.mitre.org/data/definitions/347.html"},
    "bridge": {"cwe_id": "CWE-345", "name": "Insufficient Verification of Data Authenticity (Cross-Chain)", "url": "https://cwe.mitre.org/data/definitions/345.html"},
    "por": {"cwe_id": "CWE-354", "name": "Improper Validation of Integrity Check Value (Merkle Proof)", "url": "https://cwe.mitre.org/data/definitions/354.html"},
    "cex_api": {"cwe_id": "CWE-362", "name": "Concurrent Execution using Shared Resource (Race Condition)", "url": "https://cwe.mitre.org/data/definitions/362.html"},
    "privileged": {"cwe_id": "CWE-250", "name": "Execution with Unnecessary Privileges", "url": "https://cwe.mitre.org/data/definitions/250.html"},
    "default": {"cwe_id": "CWE-699", "name": "General Software Security Weakness", "url": "https://cwe.mitre.org/data/definitions/699.html"},
}

OWASP_MAPPING = {
    "reentrancy": "SC01:2026-Reentrancy & State Machine Flaws",
    "tx.origin": "SC02:2026-Access Control & Identification Flaws",
    "overflow": "SC03:2026-Arithmetic & Invariant Bounds",
    "delegatecall": "SC04:2026-Arbitrary Logic Injection",
    "flash_loan": "SC05:2026-Economic & Oracle Manipulation",
    "oracle": "SC05:2026-Economic & Oracle Manipulation",
    "eval": "A03:2021-Injection",
    "system": "A03:2021-Injection",
    "open": "A01:2021-Broken Access Control",
    "hardcoded_key": "A07:2021-Identification and Authentication Failures",
    "ecb": "A02:2021-Cryptographic Failures",
    "md5": "A02:2021-Cryptographic Failures",
    "jwt": "A02:2021-Cryptographic Failures",
    "bridge": "SC08:2026-Cross-Chain Bridge Verification Failure",
    "por": "SC09:2026-Proof of Solvency & Reserves Manipulation",
    "cex_api": "API08:2023-Lack of Protection from Automated Threats / Race Conditions",
    "privileged": "A05:2021-Security Misconfiguration",
    "default": "A05:2021-Security Misconfiguration",
}

MITRE_MAPPING = {
    "reentrancy": {"technique_id": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
    "tx.origin": {"technique_id": "T1078", "tactic": "Defense Evasion", "name": "Valid Accounts / Impersonation"},
    "overflow": {"technique_id": "T1499", "tactic": "Impact", "name": "Endpoint Denial of Service"},
    "delegatecall": {"technique_id": "T1055", "tactic": "Privilege Escalation", "name": "Process Injection / Arbitrary Execution"},
    "flash_loan": {"technique_id": "T1496", "tactic": "Impact", "name": "Resource Hijacking / Financial Extraction"},
    "eval": {"technique_id": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter"},
    "system": {"technique_id": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter"},
    "hardcoded_key": {"technique_id": "T1552", "tactic": "Credential Access", "name": "Unsecured Credentials"},
    "bridge": {"technique_id": "T1565", "tactic": "Impact", "name": "Data Manipulation (Replay/Unbacked Mint)"},
    "default": {"technique_id": "T1005", "tactic": "Collection", "name": "Data from Local System"},
}

CCSS_MAPPING = {
    "reentrancy": {"aspect": "Smart Contract Logic", "level": "Level 3", "req": "Formal Verification / Reentrancy Protection"},
    "tx.origin": {"aspect": "Authentication", "level": "Level 2", "req": "Strict Call Origin Validation"},
    "hardcoded_key": {"aspect": "Key Management", "level": "Level 1", "req": "Hardware Storage / Environment Secrets"},
    "ecb": {"aspect": "Data Encryption", "level": "Level 2", "req": "Authenticated Encryption (GCM/ChaCha20)"},
    "jwt": {"aspect": "API Session Security", "level": "Level 2", "req": "Signature Enforcement"},
    "bridge": {"aspect": "Cross-Chain Escrow", "level": "Level 3", "req": "Multi-Validator Quorum & Replay Defense"},
    "por": {"aspect": "Solvency & Reserve Proof", "level": "Level 3", "req": "Cryptographic Merkle Sum Tree Proof"},
    "cex_api": {"aspect": "Order Execution", "level": "Level 2", "req": "Atomic Nonce & Rate Limiting"},
    "default": {"aspect": "General Operational Security", "level": "Level 1", "req": "Baseline Controls"},
}


class CorrelationEngine:
    """
    Orchestrates finding deduplication, multi-engine consensus, and regulatory mapping.
    """

    def __init__(self):
        pass

    def correlate_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicates raw findings across multiple engines and enriches them
        with consensus scoring and compliance cross-references.
        """
        if not raw_findings:
            return []

        # 1. Cluster findings by (file, line_range, normalized_category)
        clusters = self._cluster_findings(raw_findings)

        # 2. Build consensus findings
        correlated = []
        for cluster in clusters:
            primary = self._synthesize_cluster(cluster)
            correlated.append(primary)

        # Sort by severity
        severity_weights = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        correlated.sort(key=lambda x: (severity_weights.get(x.get("severity", "INFO"), 5), -x.get("consensus_score", 0)))
        return correlated

    def _cluster_findings(self, findings: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Group findings that represent the same underlying security flaw."""
        clusters = []

        for f in findings:
            file_path = f.get("file", f.get("file_path", ""))
            line = f.get("line", f.get("line_number", 0))
            category = self._categorize_finding(f)

            matched = False
            for cluster in clusters:
                rep = cluster[0]
                rep_file = rep.get("file", rep.get("file_path", ""))
                rep_line = rep.get("line", rep.get("line_number", 0))
                rep_cat = self._categorize_finding(rep)

                # Same file + close line proximity (within 5 lines) + matching category
                if file_path == rep_file and abs(line - rep_line) <= 5 and (category == rep_cat or category == "default" or rep_cat == "default"):
                    cluster.append(f)
                    matched = True
                    break

            if not matched:
                clusters.append([f])

        return clusters

    def _categorize_finding(self, finding: Dict[str, Any]) -> str:
        """Extract a canonical category token from a finding."""
        rule_id = str(finding.get("rule_id", "")).lower()
        msg = str(finding.get("message", finding.get("description", ""))).lower()
        snippet = str(finding.get("snippet", "")).lower()
        combined = f"{rule_id} {msg} {snippet}"

        for key in CWE_MAPPING.keys():
            if key != "default" and key in combined:
                return key

        if "origin" in combined:
            return "tx.origin"
        if "reentrant" in combined or "call{" in combined:
            return "reentrancy"
        if "secret" in combined or "key" in combined or "token" in combined:
            return "hardcoded_key"
        if "sql" in combined or "query" in combined:
            return "eval"
        if "subprocess" in combined or "popen" in combined:
            return "system"

        return "default"

    def _synthesize_cluster(self, cluster: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Synthesize a unified finding from a cluster of raw findings."""
        # Pick the finding with highest severity as representative
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        cluster.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 5))
        rep = cluster[0].copy()

        category = self._categorize_finding(rep)

        # Collect all reporting engines
        engines = set()
        for f in cluster:
            eng = f.get("engine", f.get("source", f.get("module", "native")))
            engines.add(eng)

        # Compute Consensus Score
        # 1 engine = 75%, 2 engines = 92%, 3+ engines = 99%
        engine_count = len(engines)
        if engine_count >= 3:
            consensus_score = 0.99
            confidence_level = "VERY HIGH (Quorum 3+ Engines)"
        elif engine_count == 2:
            consensus_score = 0.92
            confidence_level = "HIGH (Corroborated by 2 Engines)"
        else:
            consensus_score = 0.78
            confidence_level = "MEDIUM (Single Engine Detection)"

        # Boost score if formal SMT or proof exists
        if rep.get("proof") or rep.get("smt_verified"):
            consensus_score = 1.0
            confidence_level = "MATHEMATICALLY PROVEN (SMT Invariant)"

        # Attach Standards Mapping
        rep["consensus_score"] = round(consensus_score, 2)
        rep["confidence_level"] = confidence_level
        rep["engines_confirmed"] = list(engines)
        rep["cluster_size"] = len(cluster)

        rep["cwe"] = CWE_MAPPING.get(category, CWE_MAPPING["default"])
        rep["owasp"] = OWASP_MAPPING.get(category, OWASP_MAPPING["default"])
        rep["mitre_attack"] = MITRE_MAPPING.get(category, MITRE_MAPPING["default"])
        rep["ccss"] = CCSS_MAPPING.get(category, CCSS_MAPPING["default"])

        return rep

    def compute_executive_scorecard(self, correlated_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Computes executive security score, grade (AAA to F), and posture breakdown."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in correlated_findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

        # Penalty score: Critical (-25), High (-10), Medium (-3), Low (-1)
        penalty = (counts["CRITICAL"] * 25) + (counts["HIGH"] * 10) + (counts["MEDIUM"] * 3) + (counts["LOW"] * 1)
        raw_score = max(0, 100 - penalty)

        if raw_score >= 95:
            grade = "AAA"
            status = "INSTITUTIONAL SAFE"
        elif raw_score >= 85:
            grade = "AA"
            status = "STRONG POSTURE"
        elif raw_score >= 75:
            grade = "A"
            status = "SECURE (Minor Advisory)"
        elif raw_score >= 60:
            grade = "BBB"
            status = "MODERATE RISK"
        elif raw_score >= 45:
            grade = "BB"
            status = "ELEVATED RISK"
        elif raw_score >= 30:
            grade = "B"
            status = "HIGH VULNERABILITY EXPOSURE"
        else:
            grade = "F"
            status = "CRITICAL BREACH HAZARD"

        return {
            "security_score": raw_score,
            "security_grade": grade,
            "posture_status": status,
            "finding_counts": counts,
            "total_findings": len(correlated_findings),
            "multi_engine_quorums": sum(1 for f in correlated_findings if len(f.get("engines_confirmed", [])) > 1),
            "ccss_ready": counts["CRITICAL"] == 0 and counts["HIGH"] == 0
        }
