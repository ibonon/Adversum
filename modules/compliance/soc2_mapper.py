"""
Adversum SOC2 Type II Compliance Mapper
=========================================
Maps Adversum security findings to SOC2 Trust Service Criteria (TSC)
controls, enabling automatic compliance evidence generation for SOC2 audits.

SOC2 Trust Service Categories:
    CC6  — Logical and Physical Access Controls
    CC7  — System Operations
    CC8  — Change Management
    CC9  — Risk Mitigation
    A1   — Availability
    PI1  — Processing Integrity

Output: SOC2ComplianceReport with control coverage, evidence artifacts,
        and audit-ready remediation status per control.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# SOC2 Control Catalog
# ---------------------------------------------------------------------------

@dataclass
class SOC2Control:
    control_id:   str        # e.g. CC6.1
    category:     str        # Logical Access, System Ops, etc.
    description:  str
    adversum_rules: List[str]  # Which Adversum rule IDs map to this control
    status:        str = "NOT_EVALUATED"  # PASS / FAIL / PARTIAL / NOT_EVALUATED
    evidence:      List[str] = field(default_factory=list)
    findings:      List[dict] = field(default_factory=list)
    remediation:   Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "control_id":   self.control_id,
            "category":     self.category,
            "description":  self.description,
            "status":       self.status,
            "evidence":     self.evidence,
            "findings_count": len(self.findings),
            "remediation":  self.remediation,
        }


@dataclass
class SOC2ComplianceReport:
    report_id:        str
    target:           str
    generated_at:     str
    controls:         List[SOC2Control]
    overall_status:   str    # COMPLIANT / NON_COMPLIANT / PARTIAL
    compliance_score: float  # 0–100
    failing_controls: List[str]
    passing_controls: List[str]
    recommendations:  List[str]

    def to_dict(self) -> dict:
        return {
            "report_id":        self.report_id,
            "target":           self.target,
            "generated_at":     self.generated_at,
            "overall_status":   self.overall_status,
            "compliance_score": round(self.compliance_score, 1),
            "failing_controls": self.failing_controls,
            "passing_controls": self.passing_controls,
            "recommendations":  self.recommendations,
            "controls":         [c.to_dict() for c in self.controls],
            "summary": {
                "total_controls":   len(self.controls),
                "passing":          len(self.passing_controls),
                "failing":          len(self.failing_controls),
                "partial":          len([c for c in self.controls if c.status == "PARTIAL"]),
                "not_evaluated":    len([c for c in self.controls if c.status == "NOT_EVALUATED"]),
            }
        }


# ---------------------------------------------------------------------------
# SOC2 Mapper
# ---------------------------------------------------------------------------

# Full SOC2 TSC control catalog relevant to software security
_SOC2_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "CC6.1",
        "category": "Logical and Physical Access Controls",
        "description": "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
        "rules": ["SOL-001", "SOL-003", "SOL-AC-001", "STR-ELE", "ACCESS_CONTROL", "PRIV_ESC"],
    },
    {
        "id": "CC6.2",
        "category": "Logical and Physical Access Controls",
        "description": "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.",
        "rules": ["AUTH_BYPASS", "TX_ORIGIN", "SPOOFING", "ECRECOVER"],
    },
    {
        "id": "CC6.3",
        "category": "Logical and Physical Access Controls",
        "description": "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on approved authorization.",
        "rules": ["UNAUTH_TRANSFER", "PRIVILEGE_ESCALATION", "OWNER_TRANSFER"],
    },
    {
        "id": "CC6.6",
        "category": "Logical and Physical Access Controls",
        "description": "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
        "rules": ["REENTRANCY", "FLASH_LOAN", "MEV-FLASHLOAN", "EXTERNAL_CALL", "SOL-001", "SOL-002"],
    },
    {
        "id": "CC7.1",
        "category": "System Operations",
        "description": "The entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.",
        "rules": ["ORACLE_MANIP", "TIMESTAMP_DEPENDENCE", "SELFDESTRUCT"],
    },
    {
        "id": "CC7.2",
        "category": "System Operations",
        "description": "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors.",
        "rules": ["MEV-SANDWICH", "MEV-RUGPULL", "ANOMALY_DETECTED", "CVE_CORRELATION"],
    },
    {
        "id": "CC7.3",
        "category": "System Operations",
        "description": "The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives.",
        "rules": ["EXPLOIT_CONFIRMED", "POE_CERTIFICATE", "DRAIN_DETECTED"],
    },
    {
        "id": "CC8.1",
        "category": "Change Management",
        "description": "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.",
        "rules": ["PATCH_GENERATED", "PR_OPENED", "SELF_HEALING"],
    },
    {
        "id": "CC9.1",
        "category": "Risk Mitigation",
        "description": "The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.",
        "rules": ["DOS_VULNERABILITY", "GAS_LIMIT", "UNBOUNDED_LOOP"],
    },
    {
        "id": "CC9.2",
        "category": "Risk Mitigation",
        "description": "The entity assesses and manages risks associated with vendors and business partners.",
        "rules": ["THIRD_PARTY_DEPS", "DELEGATECALL", "PROXY_PATTERN"],
    },
    {
        "id": "A1.1",
        "category": "Availability",
        "description": "The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand.",
        "rules": ["GAS_EXHAUSTION", "STORAGE_OVERFLOW", "BLOCK_STUFFING"],
    },
    {
        "id": "PI1.1",
        "category": "Processing Integrity",
        "description": "The entity obtains or generates, uses, and communicates relevant, quality information regarding the objectives related to processing.",
        "rules": ["ARITHMETIC_OVERFLOW", "INTEGER_UNDERFLOW", "PRECISION_LOSS"],
    },
]


class SOC2Mapper:
    """
    Maps Adversum findings to SOC2 Type II Trust Service Criteria.

    Usage:
        mapper = SOC2Mapper()
        report = mapper.generate_report(findings, target="MyProtocol")
    """

    def generate_report(
        self,
        findings: List[dict],
        target: str = "Unknown System",
    ) -> SOC2ComplianceReport:
        """Generate a full SOC2 Type II compliance report from Adversum findings."""
        controls = self._build_controls(findings)
        failing  = [c.control_id for c in controls if c.status == "FAIL"]
        passing  = [c.control_id for c in controls if c.status == "PASS"]

        evaluated = [c for c in controls if c.status != "NOT_EVALUATED"]
        score = (len(passing) / len(evaluated) * 100) if evaluated else 100.0

        if score >= 90:
            status = "COMPLIANT"
        elif score >= 60:
            status = "PARTIAL"
        else:
            status = "NON_COMPLIANT"

        recommendations = self._build_recommendations(controls)

        return SOC2ComplianceReport(
            report_id        = str(uuid.uuid4()),
            target           = target,
            generated_at     = datetime.now(timezone.utc).isoformat(),
            controls         = controls,
            overall_status   = status,
            compliance_score = score,
            failing_controls = failing,
            passing_controls = passing,
            recommendations  = recommendations,
        )

    def _build_controls(self, findings: List[dict]) -> List[SOC2Control]:
        # Index findings by rule_id for fast lookup
        findings_by_rule: Dict[str, List[dict]] = {}
        for f in findings:
            raw = f.get("raw", f)
            rule = raw.get("rule_id") or f.get("rule_id") or ""
            findings_by_rule.setdefault(rule, []).append(f)

        controls: List[SOC2Control] = []
        for catalog_entry in _SOC2_CATALOG:
            matched_findings: List[dict] = []
            for rule in catalog_entry["rules"]:
                matched_findings += findings_by_rule.get(rule, [])

            if not matched_findings:
                # No findings for this control — assume passing (no evidence of violation)
                status   = "PASS"
                evidence = ["No violations detected by Adversum scan"]
            else:
                # Findings exist — classify severity
                severities = [
                    (f.get("raw", f).get("severity") or f.get("severity") or "MEDIUM").upper()
                    for f in matched_findings
                ]
                if "CRITICAL" in severities or "HIGH" in severities:
                    status = "FAIL"
                else:
                    status = "PARTIAL"
                evidence = [
                    f"Adversum detected {len(matched_findings)} finding(s) affecting this control"
                ]

            control = SOC2Control(
                control_id    = catalog_entry["id"],
                category      = catalog_entry["category"],
                description   = catalog_entry["description"],
                adversum_rules = catalog_entry["rules"],
                status        = status,
                evidence      = evidence,
                findings      = matched_findings,
                remediation   = self._get_remediation(catalog_entry["id"], matched_findings),
            )
            controls.append(control)

        return controls

    def _get_remediation(self, control_id: str, findings: List[dict]) -> Optional[str]:
        if not findings:
            return None
        remediations = {
            "CC6.1": "Implement role-based access control with multisig governance",
            "CC6.2": "Replace tx.origin with msg.sender and implement signature verification",
            "CC6.3": "Add timelocked ownership transfer with multi-party approval",
            "CC6.6": "Add ReentrancyGuard and validate all external call return values",
            "CC7.1": "Implement event-driven monitoring with Adversum Live Threat Stream",
            "CC7.2": "Enable MEV Intelligence Engine for real-time mempool monitoring",
            "CC7.3": "Deploy Adversum Live Fork PoE for continuous exploit validation",
            "CC8.1": "Enable Adversum Self-Healing Bot for automated patch deployment",
            "CC9.1": "Add gas limit caps and pagination to all unbounded loops",
            "CC9.2": "Audit and whitelist all delegatecall targets; use immutable proxies",
            "A1.1":  "Implement gas budgets and circuit breakers for DoS protection",
            "PI1.1": "Use SafeMath / Solidity 0.8+ checked arithmetic throughout",
        }
        return remediations.get(control_id)

    def _build_recommendations(self, controls: List[SOC2Control]) -> List[str]:
        recs = []
        for c in controls:
            if c.status == "FAIL" and c.remediation:
                recs.append(f"[{c.control_id}] IMMEDIATE: {c.remediation}")
        for c in controls:
            if c.status == "PARTIAL" and c.remediation:
                recs.append(f"[{c.control_id}] REVIEW: {c.remediation}")
        return recs[:10]
