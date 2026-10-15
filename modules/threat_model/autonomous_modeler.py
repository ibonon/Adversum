"""
Adversum Autonomous Threat Modeler
====================================
Generates STRIDE threat models, PASTA attack trees, and MITRE ATT&CK for
Web3/ICS mappings autonomously from source code and contract metadata.

Methodology:
    1. STRIDE — Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation
    2. PASTA — Process for Attack Simulation and Threat Analysis (7-stage)
    3. MITRE ATT&CK for ICS — Tactical TTP mapping

Output:
    ThreatModelReport with full STRIDE matrix, PASTA stages, MITRE TTPs,
    risk-scored attack paths, and executive recommendations.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("adversum.threat_model")


# ---------------------------------------------------------------------------
# STRIDE Categories
# ---------------------------------------------------------------------------

class STRIDECategory(str, Enum):
    SPOOFING             = "Spoofing"
    TAMPERING            = "Tampering"
    REPUDIATION          = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE    = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class STRIDEThreat:
    """Single STRIDE threat item."""
    threat_id:    str
    category:     STRIDECategory
    component:    str
    description:  str
    impact:       str
    likelihood:   str                    # High / Medium / Low
    risk_score:   float                  # 0–10 DREAD-inspired score
    countermeasures: List[str]           = field(default_factory=list)
    mitre_technique: Optional[str]       = None
    cwe_id:          Optional[str]       = None

    def to_dict(self) -> dict:
        return {
            "threat_id":       self.threat_id,
            "category":        self.category.value,
            "component":       self.component,
            "description":     self.description,
            "impact":          self.impact,
            "likelihood":      self.likelihood,
            "risk_score":      self.risk_score,
            "countermeasures": self.countermeasures,
            "mitre_technique": self.mitre_technique,
            "cwe_id":          self.cwe_id,
        }


@dataclass
class PASTAStage:
    """Single stage of the PASTA 7-stage process."""
    stage_number: int
    name:         str
    description:  str
    findings:     List[str] = field(default_factory=list)
    artifacts:    Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "stage":       self.stage_number,
            "name":        self.name,
            "description": self.description,
            "findings":    self.findings,
            "artifacts":   self.artifacts,
        }


@dataclass
class AttackPath:
    """A scored attack path through the system."""
    path_id:      str
    name:         str
    steps:        List[str]
    risk_score:   float
    attacker_profile: str
    prerequisites:    List[str] = field(default_factory=list)
    mitre_chain:      List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path_id":          self.path_id,
            "name":             self.name,
            "steps":            self.steps,
            "risk_score":       self.risk_score,
            "attacker_profile": self.attacker_profile,
            "prerequisites":    self.prerequisites,
            "mitre_chain":      self.mitre_chain,
        }


@dataclass
class ThreatModelReport:
    """Complete autonomous threat model output."""
    report_id:         str
    target:            str
    generated_at:      str
    stride_threats:    List[STRIDEThreat]
    pasta_stages:      List[PASTAStage]
    attack_paths:      List[AttackPath]
    overall_risk:      str               # CRITICAL / HIGH / MEDIUM / LOW
    overall_score:     float             # 0–10
    executive_summary: str
    recommendations:   List[str]
    components_analyzed: List[str]
    analysis_time_ms:  int

    def to_dict(self) -> dict:
        return {
            "report_id":           self.report_id,
            "target":              self.target,
            "generated_at":        self.generated_at,
            "overall_risk":        self.overall_risk,
            "overall_score":       self.overall_score,
            "executive_summary":   self.executive_summary,
            "recommendations":     self.recommendations,
            "components_analyzed": self.components_analyzed,
            "analysis_time_ms":    self.analysis_time_ms,
            "stride": {
                "threats":       [t.to_dict() for t in self.stride_threats],
                "by_category":   self._stride_by_category(),
                "total_threats": len(self.stride_threats),
            },
            "pasta": {
                "stages":     [s.to_dict() for s in self.pasta_stages],
                "completed":  len(self.pasta_stages),
            },
            "attack_paths": {
                "paths":     [p.to_dict() for p in self.attack_paths],
                "total":     len(self.attack_paths),
                "max_risk":  max((p.risk_score for p in self.attack_paths), default=0),
            },
        }

    def _stride_by_category(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for t in self.stride_threats:
            counts[t.category.value] = counts.get(t.category.value, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Pattern Library — Code Indicators → STRIDE Threats
# ---------------------------------------------------------------------------

_STRIDE_RULES: List[Dict[str, Any]] = [
    # Spoofing
    {
        "pattern": re.compile(r"tx\.origin", re.IGNORECASE),
        "category": STRIDECategory.SPOOFING,
        "description": "tx.origin used for authentication — phishing bypass possible",
        "impact": "Complete authentication bypass by any contract caller",
        "countermeasures": ["Replace tx.origin with msg.sender", "Use EIP-712 signed messages"],
        "mitre": "T0880 — Exploit Public-Facing Application",
        "cwe": "CWE-290",
        "score": 8.5,
    },
    {
        "pattern": re.compile(r"ecrecover\s*\(", re.IGNORECASE),
        "category": STRIDECategory.SPOOFING,
        "description": "ecrecover without signature malleability protection",
        "impact": "Signature replay attacks enabling unauthorized fund transfers",
        "countermeasures": ["Use OpenZeppelin ECDSA library", "Check s ≤ secp256k1n/2"],
        "mitre": "T0866 — Exploitation of Remote Services",
        "cwe": "CWE-347",
        "score": 7.5,
    },
    # Tampering
    {
        "pattern": re.compile(r"delegatecall\s*\(", re.IGNORECASE),
        "category": STRIDECategory.TAMPERING,
        "description": "delegatecall to untrusted contract — storage layout hijack",
        "impact": "Attacker can rewrite any storage slot, drain funds, upgrade logic",
        "countermeasures": ["Validate target address whitelist", "Use immutable proxy patterns"],
        "mitre": "T0836 — Modify Parameter",
        "cwe": "CWE-470",
        "score": 9.2,
    },
    {
        "pattern": re.compile(r"selfdestruct\s*\(", re.IGNORECASE),
        "category": STRIDECategory.TAMPERING,
        "description": "selfdestruct enables permanent contract destruction",
        "impact": "Contract wiped, all locked funds lost forever",
        "countermeasures": ["Remove selfdestruct", "Restrict to multisig with timelock"],
        "mitre": "T0829 — Loss of View",
        "cwe": "CWE-284",
        "score": 9.0,
    },
    # Repudiation
    {
        "pattern": re.compile(r"emit\s+\w*[Ll]og|event\s+\w+", re.IGNORECASE),
        "category": STRIDECategory.REPUDIATION,
        "description": "Insufficient event logging for sensitive operations",
        "impact": "No audit trail for fund transfers, ownership changes",
        "countermeasures": ["Emit events for all state-changing operations", "Index critical parameters"],
        "mitre": "T0872 — Indicator Removal on Host",
        "cwe": "CWE-223",
        "score": 4.0,
    },
    # Information Disclosure
    {
        "pattern": re.compile(r"private\s+\w+\s+\w+\s*=|internal\s+\w+\s+key", re.IGNORECASE),
        "category": STRIDECategory.INFORMATION_DISCLOSURE,
        "description": "Private state variables accessible via storage slot reads",
        "impact": "Sensitive data (keys, seeds, balances) leaked on-chain",
        "countermeasures": ["Store sensitive data off-chain", "Use commitment schemes"],
        "mitre": "T0882 — Theft of Operational Information",
        "cwe": "CWE-312",
        "score": 6.5,
    },
    # Denial of Service
    {
        "pattern": re.compile(r"for\s*\(\s*uint\s+\w+\s*=\s*0;\s*\w+\s*<\s*\w+\.length", re.IGNORECASE),
        "category": STRIDECategory.DENIAL_OF_SERVICE,
        "description": "Unbounded loop over dynamic array — gas DoS possible",
        "impact": "Contract functions become permanently unexecutable above gas limit",
        "countermeasures": ["Add maximum iteration caps", "Use pull-payment pattern"],
        "mitre": "T0814 — Denial of Service",
        "cwe": "CWE-400",
        "score": 7.0,
    },
    {
        "pattern": re.compile(r"block\.timestamp\s*[<>]=?|now\s*[<>]=?", re.IGNORECASE),
        "category": STRIDECategory.DENIAL_OF_SERVICE,
        "description": "block.timestamp manipulation by miners (±15s)",
        "impact": "Time-based locks or auctions can be griefed by miner timestamp skew",
        "countermeasures": ["Use block numbers instead of timestamps for short windows"],
        "mitre": "T0814 — Denial of Service",
        "cwe": "CWE-362",
        "score": 5.5,
    },
    # Elevation of Privilege
    {
        "pattern": re.compile(r"onlyOwner|Ownable|transferOwnership", re.IGNORECASE),
        "category": STRIDECategory.ELEVATION_OF_PRIVILEGE,
        "description": "Single-owner privilege concentration — key compromise = total loss",
        "impact": "Private key theft grants attacker full protocol control",
        "countermeasures": ["Use multisig (Gnosis Safe)", "Implement timelocked governance"],
        "mitre": "T0858 — Change Credential",
        "cwe": "CWE-732",
        "score": 8.0,
    },
    {
        "pattern": re.compile(r"initialize\s*\(|__init\s*\(", re.IGNORECASE),
        "category": STRIDECategory.ELEVATION_OF_PRIVILEGE,
        "description": "Unprotected initializer — can be front-run by attacker",
        "impact": "Attacker becomes owner, configures malicious parameters",
        "countermeasures": ["Add initializer guard", "Use OpenZeppelin Initializable"],
        "mitre": "T0858 — Change Credential",
        "cwe": "CWE-665",
        "score": 9.5,
    },
]


# ---------------------------------------------------------------------------
# Autonomous Threat Modeler
# ---------------------------------------------------------------------------

class AutonomousThreatModeler:
    """
    Generates STRIDE + PASTA + MITRE ATT&CK threat models from source code.

    Usage:
        modeler = AutonomousThreatModeler()
        report = await modeler.analyze(source_code, target="MyDeFiProtocol")
    """

    def __init__(self):
        logger.info("AutonomousThreatModeler initialized")

    async def analyze(
        self,
        source_code: str,
        target: str = "Unknown Target",
        component_names: Optional[List[str]] = None,
    ) -> ThreatModelReport:
        """
        Fully autonomous STRIDE + PASTA threat model generation.

        Args:
            source_code:      Combined source code string.
            target:           Name of the target system/protocol.
            component_names:  Optional list of component names for PASTA stage 1.

        Returns:
            ThreatModelReport with all findings.
        """
        import time
        start = time.monotonic()

        components = component_names or self._extract_components(source_code)

        # Stage 1: STRIDE Analysis
        stride_threats = self._run_stride_analysis(source_code, components)

        # Stage 2: PASTA 7-Stage Process
        pasta_stages = self._run_pasta_analysis(source_code, stride_threats, target, components)

        # Stage 3: Attack Path Generation
        attack_paths = self._generate_attack_paths(stride_threats)

        # Stage 4: Score & Summarize
        overall_score = self._compute_overall_score(stride_threats)
        overall_risk  = self._score_to_risk(overall_score)
        summary       = self._build_executive_summary(target, stride_threats, attack_paths, overall_risk)
        recommendations = self._build_recommendations(stride_threats)

        elapsed_ms = int((time.monotonic() - start) * 1000)

        report = ThreatModelReport(
            report_id          = str(uuid.uuid4()),
            target             = target,
            generated_at       = datetime.now(timezone.utc).isoformat(),
            stride_threats     = stride_threats,
            pasta_stages       = pasta_stages,
            attack_paths       = attack_paths,
            overall_risk       = overall_risk,
            overall_score      = round(overall_score, 2),
            executive_summary  = summary,
            recommendations    = recommendations,
            components_analyzed = components,
            analysis_time_ms   = elapsed_ms,
        )

        logger.info(
            "Threat model for '%s': %d STRIDE threats | %d attack paths | risk=%s | %dms",
            target, len(stride_threats), len(attack_paths), overall_risk, elapsed_ms,
        )
        return report

    # ── STRIDE Analysis ────────────────────────────────────────────────────

    def _run_stride_analysis(self, code: str, components: List[str]) -> List[STRIDEThreat]:
        threats: List[STRIDEThreat] = []
        seen_patterns: set = set()

        for rule in _STRIDE_RULES:
            if rule["pattern"].search(code):
                key = f"{rule['category']}:{rule['cwe']}"
                if key in seen_patterns:
                    continue
                seen_patterns.add(key)

                component = components[0] if components else "Unknown"
                threat_id = f"STR-{rule['category'].value[:3].upper()}-{hashlib.md5(key.encode()).hexdigest()[:6].upper()}"

                threats.append(STRIDEThreat(
                    threat_id       = threat_id,
                    category        = rule["category"],
                    component       = component,
                    description     = rule["description"],
                    impact          = rule["impact"],
                    likelihood      = "High" if rule["score"] >= 8.0 else ("Medium" if rule["score"] >= 5.5 else "Low"),
                    risk_score      = rule["score"],
                    countermeasures = rule["countermeasures"],
                    mitre_technique = rule["mitre"],
                    cwe_id          = rule["cwe"],
                ))

        # Always add baseline threats for any DeFi protocol
        if any(kw in code.lower() for kw in ["token", "transfer", "balance", "liquidity"]):
            threats.append(STRIDEThreat(
                threat_id       = "STR-DOC-FLASH001",
                category        = STRIDECategory.DENIAL_OF_SERVICE,
                component       = components[0] if components else "TokenContract",
                description     = "Flash loan-amplified reentrancy DoS via state inconsistency",
                impact          = "Protocol permanently locked, $M+ TVL frozen",
                likelihood      = "High",
                risk_score      = 8.8,
                countermeasures = ["ReentrancyGuard on all fund-touching functions", "Use pull-payment"],
                mitre_technique = "T0814 — Denial of Service",
                cwe_id          = "CWE-841",
            ))

        return sorted(threats, key=lambda t: t.risk_score, reverse=True)

    # ── PASTA 7-Stage ──────────────────────────────────────────────────────

    def _run_pasta_analysis(
        self,
        code: str,
        stride_threats: List[STRIDEThreat],
        target: str,
        components: List[str],
    ) -> List[PASTAStage]:
        high_risks   = [t for t in stride_threats if t.risk_score >= 8.0]
        mitre_ttps   = list({t.mitre_technique for t in stride_threats if t.mitre_technique})
        top_threats  = [t.description for t in stride_threats[:3]]
        categories   = list({t.category.value for t in stride_threats})

        return [
            PASTAStage(1, "Define Objectives",
                "Identify business objectives and security requirements",
                findings=[f"Primary asset: {target}", "Objective: Protect TVL and user funds"],
                artifacts={"components": components, "asset_classes": ["Funds", "State", "Access Control"]}),

            PASTAStage(2, "Define Technical Scope",
                "Map technical components and data flows",
                findings=[f"Analyzed {len(components)} components", f"{len(code.splitlines())} lines of code scanned"],
                artifacts={"components": components, "languages_detected": self._detect_languages(code)}),

            PASTAStage(3, "Decompose Application",
                "Break down into trust zones, data flows, and entry points",
                findings=["Entry points: external calls, constructor, admin functions",
                          "Trust boundaries: msg.sender → contract → external contracts"],
                artifacts={"entry_points": self._find_entry_points(code)}),

            PASTAStage(4, "Analyze Threats",
                "Enumerate threats per STRIDE for each component",
                findings=[f"{len(stride_threats)} STRIDE threats identified",
                          f"Categories: {', '.join(categories)}",
                          f"{len(high_risks)} high/critical risk threats"],
                artifacts={"threat_count_by_category": {c: sum(1 for t in stride_threats if t.category.value == c) for c in categories}}),

            PASTAStage(5, "Detect Vulnerabilities",
                "Map threats to exploitable vulnerabilities using MITRE ATT&CK",
                findings=top_threats,
                artifacts={"mitre_techniques": mitre_ttps, "cwe_ids": [t.cwe_id for t in stride_threats if t.cwe_id]}),

            PASTAStage(6, "Enumerate Attacks",
                "Construct concrete attack scenarios with DREAD scoring",
                findings=[f"Attack path analysis: {len(stride_threats)} potential attack surfaces",
                          "Highest risk: " + (top_threats[0] if top_threats else "N/A")],
                artifacts={"top_attack_vectors": [t.category.value for t in stride_threats[:5]]}),

            PASTAStage(7, "Countermeasures",
                "Define and prioritize security controls per risk level",
                findings=[
                    f"{len(high_risks)} critical controls required immediately",
                    "Recommended: multisig governance + timelocks + formal verification",
                ],
                artifacts={"control_categories": ["Access Control", "Input Validation", "Monitoring", "Key Management"]}),
        ]

    # ── Attack Paths ───────────────────────────────────────────────────────

    def _generate_attack_paths(self, threats: List[STRIDEThreat]) -> List[AttackPath]:
        paths: List[AttackPath] = []

        # Build attack paths from correlated STRIDE threats
        if any(t.category == STRIDECategory.ELEVATION_OF_PRIVILEGE for t in threats):
            priv_threats = [t for t in threats if t.category == STRIDECategory.ELEVATION_OF_PRIVILEGE]
            paths.append(AttackPath(
                path_id       = str(uuid.uuid4()),
                name          = "Privilege Escalation → Full Protocol Takeover",
                steps         = [
                    "1. Attacker identifies unprotected initializer or tx.origin auth",
                    "2. Front-run deployment / call initializer with attacker-controlled args",
                    "3. Attacker becomes owner with full admin rights",
                    "4. Drain treasury via privileged transfer functions",
                    "5. Selfdestruct to destroy evidence",
                ],
                risk_score    = max(t.risk_score for t in priv_threats),
                attacker_profile = "Sophisticated DeFi attacker with MEV bot infrastructure",
                prerequisites    = ["Contract deployment visibility", "Mempool access"],
                mitre_chain      = [t.mitre_technique for t in priv_threats if t.mitre_technique],
            ))

        if any(t.category == STRIDECategory.TAMPERING for t in threats):
            tamp_threats = [t for t in threats if t.category == STRIDECategory.TAMPERING]
            paths.append(AttackPath(
                path_id       = str(uuid.uuid4()),
                name          = "Storage Corruption via delegatecall",
                steps         = [
                    "1. Identify delegatecall to upgradeable/external contract",
                    "2. Craft malicious storage layout collision",
                    "3. Override owner slot (slot 0) with attacker address",
                    "4. Call privileged functions as new owner",
                    "5. Execute rug pull via transfer()",
                ],
                risk_score    = max(t.risk_score for t in tamp_threats),
                attacker_profile = "Smart contract security researcher / white-hat turned black-hat",
                prerequisites    = ["Knowledge of proxy storage layout", "Solidity expertise"],
                mitre_chain      = [t.mitre_technique for t in tamp_threats if t.mitre_technique],
            ))

        if any(t.category == STRIDECategory.DENIAL_OF_SERVICE for t in threats):
            dos_threats = [t for t in threats if t.category == STRIDECategory.DENIAL_OF_SERVICE]
            paths.append(AttackPath(
                path_id       = str(uuid.uuid4()),
                name          = "Gas Griefing → Protocol Freeze",
                steps         = [
                    "1. Identify unbounded loop over user-controlled array",
                    "2. Attacker creates large array state (1000+ entries)",
                    "3. Trigger loop function — gas exceeds block limit",
                    "4. Function permanently reverts — protocol frozen",
                    "5. Attacker profits from competing protocol",
                ],
                risk_score    = max(t.risk_score for t in dos_threats),
                attacker_profile = "Competing protocol / market manipulator",
                prerequisites    = ["Protocol TVL > $1M (economic incentive)"],
                mitre_chain      = [t.mitre_technique for t in dos_threats if t.mitre_technique],
            ))

        return sorted(paths, key=lambda p: p.risk_score, reverse=True)

    # ── Scoring & Summary ──────────────────────────────────────────────────

    def _compute_overall_score(self, threats: List[STRIDEThreat]) -> float:
        if not threats:
            return 0.0
        # Weighted average with critical threats counted double
        weighted = sum(t.risk_score * (2.0 if t.risk_score >= 8.5 else 1.0) for t in threats)
        denom    = sum(2.0 if t.risk_score >= 8.5 else 1.0 for t in threats)
        return min(10.0, weighted / denom) if denom else 0.0

    def _score_to_risk(self, score: float) -> str:
        if score >= 8.5: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        return "LOW"

    def _build_executive_summary(
        self,
        target: str,
        threats: List[STRIDEThreat],
        paths: List[AttackPath],
        risk: str,
    ) -> str:
        n = len(threats)
        critical = sum(1 for t in threats if t.risk_score >= 8.5)
        return (
            f"Autonomous threat model for **{target}** identified {n} STRIDE threats "
            f"({critical} critical) across {len({t.category for t in threats})} categories. "
            f"Overall risk: **{risk}**. "
            f"{len(paths)} concrete attack paths constructed. "
            f"Immediate action required on: {', '.join(t.threat_id for t in threats[:3])}."
        )

    def _build_recommendations(self, threats: List[STRIDEThreat]) -> List[str]:
        recs = []
        seen = set()
        for threat in sorted(threats, key=lambda t: t.risk_score, reverse=True):
            for cm in threat.countermeasures:
                if cm not in seen:
                    seen.add(cm)
                    recs.append(f"[{threat.threat_id}] {cm}")
                if len(recs) >= 10:
                    return recs
        return recs

    # ── Code Analysis Utilities ────────────────────────────────────────────

    def _extract_components(self, code: str) -> List[str]:
        patterns = [
            re.compile(r"contract\s+(\w+)", re.IGNORECASE),
            re.compile(r"class\s+(\w+)", re.IGNORECASE),
            re.compile(r"def\s+(\w+)\s*\(", re.IGNORECASE),
        ]
        found = []
        for p in patterns:
            found += p.findall(code)
        return list(dict.fromkeys(found))[:10] or ["UnknownComponent"]

    def _detect_languages(self, code: str) -> List[str]:
        langs = []
        if "pragma solidity" in code.lower(): langs.append("Solidity")
        if "def " in code and "import" in code:      langs.append("Python")
        if "fn " in code and "use " in code:          langs.append("Rust")
        if "function" in code and "const" in code:    langs.append("TypeScript/JavaScript")
        return langs or ["Unknown"]

    def _find_entry_points(self, code: str) -> List[str]:
        patterns = [
            re.compile(r"function\s+(\w+)\s*\([^)]*\)\s+(?:public|external)", re.IGNORECASE),
            re.compile(r"def\s+(handle|process|execute|run|start)\w*\s*\(", re.IGNORECASE),
            re.compile(r"@app\.(get|post|put|delete|patch)\s*\(['\"]([^'\"]+)['\"]", re.IGNORECASE),
        ]
        entries = []
        for p in patterns:
            entries += [m.group(1) if p.groups == 1 or len(m.groups()) < 2 else m.group(2)
                        for m in p.finditer(code)]
        return list(dict.fromkeys(entries))[:15]
