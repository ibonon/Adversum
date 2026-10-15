"""
Adversum ISO 27001:2022 Compliance Mapper
==========================================
Maps Adversum findings to ISO/IEC 27001:2022 Annex A controls,
enabling automatic compliance evidence generation.

Key Annex A domains covered:
    A.5  — Organizational controls
    A.8  — Technological controls
    A.12 — Operations security
    A.14 — System acquisition, development and maintenance
    A.16 — Information security incident management
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class ISO27001Control:
    control_id:    str       # e.g. A.8.2
    annex:         str       # A.5, A.8, etc.
    title:         str
    description:   str
    adversum_rules: List[str]
    status:         str = "NOT_EVALUATED"
    evidence:       List[str] = field(default_factory=list)
    findings:       List[dict] = field(default_factory=list)
    remediation:    Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "control_id":     self.control_id,
            "annex":          self.annex,
            "title":          self.title,
            "description":    self.description,
            "status":         self.status,
            "evidence":       self.evidence,
            "findings_count": len(self.findings),
            "remediation":    self.remediation,
        }


@dataclass
class ISO27001ComplianceReport:
    report_id:        str
    target:           str
    generated_at:     str
    controls:         List[ISO27001Control]
    overall_status:   str
    compliance_score: float
    failing_controls: List[str]
    passing_controls: List[str]
    recommendations:  List[str]
    iso_version:      str = "ISO/IEC 27001:2022"

    def to_dict(self) -> dict:
        return {
            "report_id":        self.report_id,
            "target":           self.target,
            "generated_at":     self.generated_at,
            "iso_version":      self.iso_version,
            "overall_status":   self.overall_status,
            "compliance_score": round(self.compliance_score, 1),
            "failing_controls": self.failing_controls,
            "passing_controls": self.passing_controls,
            "recommendations":  self.recommendations,
            "controls":         [c.to_dict() for c in self.controls],
            "summary": {
                "total_controls": len(self.controls),
                "passing":        len(self.passing_controls),
                "failing":        len(self.failing_controls),
            }
        }


_ISO27001_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "A.5.7",   "annex": "A.5",
        "title": "Threat intelligence",
        "description": "Information relating to information security threats shall be collected and analysed to produce threat intelligence.",
        "rules": ["CVE_CORRELATION", "THREAT_INTEL", "MEV_DETECTED", "THREAT_MODEL"],
    },
    {
        "id": "A.5.23",  "annex": "A.5",
        "title": "Information security for use of cloud services",
        "description": "Processes for acquisition, use, management and exit from cloud services shall be established.",
        "rules": ["CLOUD_MISCONFIG", "IAC_K8S", "DOCKER_PRIVESC", "TERRAFORM_OPEN"],
    },
    {
        "id": "A.8.2",   "annex": "A.8",
        "title": "Privileged access rights",
        "description": "The allocation and use of privileged access rights shall be restricted and managed.",
        "rules": ["PRIV_ESC", "OWNER_TRANSFER", "UNAUTH_ADMIN", "TX_ORIGIN", "STR-ELE"],
    },
    {
        "id": "A.8.9",   "annex": "A.8",
        "title": "Configuration management",
        "description": "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.",
        "rules": ["IAC_MISCONFIGURATION", "K8S_PRIVILEGED", "DOCKER_ROOT"],
    },
    {
        "id": "A.8.16",  "annex": "A.8",
        "title": "Monitoring activities",
        "description": "Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.",
        "rules": ["MEV-SANDWICH", "MEV-RUGPULL", "EXPLOIT_CONFIRMED", "ANOMALY"],
    },
    {
        "id": "A.8.25",  "annex": "A.8",
        "title": "Secure development life cycle",
        "description": "Rules for the secure development of software and systems shall be established and applied.",
        "rules": ["REENTRANCY", "INTEGER_OVERFLOW", "ARBITRARY_JUMP", "DELEGATECALL"],
    },
    {
        "id": "A.8.26",  "annex": "A.8",
        "title": "Application security requirements",
        "description": "Information security requirements shall be identified, specified and approved when developing or acquiring applications.",
        "rules": ["FLASH_LOAN", "ORACLE_MANIP", "SANDWICH_ATTACK", "ACCESS_CONTROL"],
    },
    {
        "id": "A.8.27",  "annex": "A.8",
        "title": "Secure system architecture and engineering principles",
        "description": "Principles for engineering secure systems shall be established, documented, maintained and applied.",
        "rules": ["SELFDESTRUCT", "ARBITRARY_SEND", "UNCHECKED_RETURN"],
    },
    {
        "id": "A.8.29",  "annex": "A.8",
        "title": "Security testing in development and acceptance",
        "description": "Security testing processes shall be defined and implemented in the development life cycle.",
        "rules": ["PATCH_GENERATED", "SELF_HEALING", "PR_OPENED", "POE_CERTIFICATE"],
    },
    {
        "id": "A.8.33",  "annex": "A.8",
        "title": "Test information",
        "description": "Test information shall be appropriately selected, protected and managed.",
        "rules": ["HARDCODED_KEY", "WEAK_RANDOM", "JWT_MISUSE"],
    },
    {
        "id": "A.12.6",  "annex": "A.12",
        "title": "Management of technical vulnerabilities",
        "description": "Information about technical vulnerabilities of information systems in use shall be obtained in a timely fashion.",
        "rules": ["SOL-001", "SOL-002", "SOL-003", "HIGH_CVE", "CRITICAL_CVE"],
    },
    {
        "id": "A.16.1",  "annex": "A.16",
        "title": "Management of information security incidents and improvements",
        "description": "Responsibilities and procedures shall be established to ensure a quick, effective and orderly response to information security incidents.",
        "rules": ["INCIDENT_RESPONSE", "EXPLOIT_CONFIRMED", "DRAIN_DETECTED", "AUDIT_LOG"],
    },
]


class ISO27001Mapper:
    """
    Maps Adversum findings to ISO/IEC 27001:2022 Annex A controls.

    Usage:
        mapper = ISO27001Mapper()
        report = mapper.generate_report(findings, target="MySystem")
    """

    _REMEDIATIONS = {
        "A.5.7":  "Enable Adversum Threat Intelligence + MEV Intelligence continuous monitoring",
        "A.5.23": "Scan IaC configs with Adversum Trivy/IaC modules; enforce CIS benchmarks",
        "A.8.2":  "Replace single-owner pattern with multisig governance (Gnosis Safe + 48h timelock)",
        "A.8.9":  "Implement IaC scanning in CI/CD pipeline; enforce Adversum baseline configs",
        "A.8.16": "Enable Adversum WebSocket Threat Stream for real-time anomaly alerting",
        "A.8.25": "Add Adversum SAST scan to pre-commit hooks and CI/CD pipeline gates",
        "A.8.26": "Define security requirements checklist per Adversum STRIDE threat model",
        "A.8.27": "Follow Adversum secure architecture recommendations from threat model report",
        "A.8.29": "Require green Adversum scan + Live Fork PoE as deployment gate criteria",
        "A.8.33": "Rotate all secrets; use vault-backed secrets management; enable crypto scanner",
        "A.12.6": "Subscribe to Adversum CVE correlation feed; patch critical findings in <24h",
        "A.16.1": "Define incident runbook using Adversum PoE certificates as evidence artifacts",
    }

    def generate_report(
        self,
        findings: List[dict],
        target: str = "Unknown System",
    ) -> ISO27001ComplianceReport:
        controls = self._build_controls(findings)
        failing  = [c.control_id for c in controls if c.status == "FAIL"]
        passing  = [c.control_id for c in controls if c.status == "PASS"]

        evaluated = [c for c in controls if c.status != "NOT_EVALUATED"]
        score = (len(passing) / len(evaluated) * 100) if evaluated else 100.0

        overall = "COMPLIANT" if score >= 90 else ("PARTIAL" if score >= 60 else "NON_COMPLIANT")

        return ISO27001ComplianceReport(
            report_id        = str(uuid.uuid4()),
            target           = target,
            generated_at     = datetime.now(timezone.utc).isoformat(),
            controls         = controls,
            overall_status   = overall,
            compliance_score = score,
            failing_controls = failing,
            passing_controls = passing,
            recommendations  = self._build_recommendations(controls),
        )

    def _build_controls(self, findings: List[dict]) -> List[ISO27001Control]:
        by_rule: Dict[str, List[dict]] = {}
        for f in findings:
            raw = f.get("raw", f)
            rule = raw.get("rule_id") or f.get("rule_id") or ""
            by_rule.setdefault(rule, []).append(f)

        controls: List[ISO27001Control] = []
        for entry in _ISO27001_CATALOG:
            matched = [f for r in entry["rules"] for f in by_rule.get(r, [])]
            if not matched:
                status   = "PASS"
                evidence = ["No violations detected"]
            else:
                sevs = [(f.get("raw", f).get("severity") or "MEDIUM").upper() for f in matched]
                status   = "FAIL" if ("CRITICAL" in sevs or "HIGH" in sevs) else "PARTIAL"
                evidence = [f"Adversum found {len(matched)} violation(s) for this control"]

            controls.append(ISO27001Control(
                control_id    = entry["id"],
                annex         = entry["annex"],
                title         = entry["title"],
                description   = entry["description"],
                adversum_rules = entry["rules"],
                status        = status,
                evidence      = evidence,
                findings      = matched,
                remediation   = self._REMEDIATIONS.get(entry["id"]),
            ))
        return controls

    def _build_recommendations(self, controls: List[ISO27001Control]) -> List[str]:
        recs = []
        for c in sorted(controls, key=lambda x: (x.status == "FAIL", x.status == "PARTIAL"), reverse=True):
            if c.status in ("FAIL", "PARTIAL") and c.remediation:
                prefix = "IMMEDIATE" if c.status == "FAIL" else "REVIEW"
                recs.append(f"[{c.control_id}] {prefix}: {c.remediation}")
            if len(recs) >= 8:
                break
        return recs
