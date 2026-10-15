"""
Adversum SARIF 2.1 Exporter
==============================
Exports Adversum findings to SARIF 2.1.0 format — the industry standard
for static analysis results interoperable with GitHub Advanced Security,
Azure DevOps, VS Code, and enterprise SIEM platforms.

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Output:
    JSON conforming to SARIF 2.1.0 schema, importable by:
    - GitHub Code Scanning
    - Azure DevOps Security tab
    - VS Code SARIF Viewer
    - Splunk / Elastic SIEM (via sarif-to-syslog adapter)
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
ADVERSUM_TOOL_VERSION = "2.0.0-phase2"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class SARIFLocation:
    uri:         str
    start_line:  int = 1
    start_col:   int = 1
    end_line:    int = 1
    end_col:     int = 999

    def to_dict(self) -> dict:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": self.uri, "uriBaseId": "%SRCROOT%"},
                "region": {
                    "startLine":   self.start_line,
                    "startColumn": self.start_col,
                    "endLine":     self.end_line,
                    "endColumn":   self.end_col,
                }
            }
        }


@dataclass
class SARIFRule:
    rule_id:          str
    name:             str
    short_description: str
    full_description:  str
    help_uri:          str = ""
    severity:          str = "error"     # error / warning / note
    tags:              List[str] = field(default_factory=list)
    cwe_ids:           List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d: Dict[str, Any] = {
            "id":   self.rule_id,
            "name": self.name,
            "shortDescription": {"text": self.short_description},
            "fullDescription":  {"text": self.full_description},
            "defaultConfiguration": {"level": self._sarif_level()},
            "properties": {"tags": self.tags},
        }
        if self.help_uri:
            d["helpUri"] = self.help_uri
        if self.cwe_ids:
            d["properties"]["cwe"] = self.cwe_ids
        return d

    def _sarif_level(self) -> str:
        return {"error": "error", "warning": "warning", "note": "note"}.get(self.severity, "warning")


@dataclass
class SARIFResult:
    rule_id:   str
    message:   str
    locations: List[SARIFLocation]
    level:     str = "error"
    fingerprint: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d: Dict[str, Any] = {
            "ruleId":    self.rule_id,
            "level":     self.level,
            "message":   {"text": self.message},
            "locations": [loc.to_dict() for loc in self.locations],
        }
        if self.fingerprint:
            d["fingerprints"] = {"primaryLocationLineHash": self.fingerprint}
        if self.properties:
            d["properties"] = self.properties
        return d


@dataclass
class SARIFReport:
    run_id:     str
    tool_name:  str
    rules:      List[SARIFRule]
    results:    List[SARIFResult]
    timestamp:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    invocation_success: bool = True

    def to_sarif(self) -> dict:
        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name":             self.tool_name,
                        "version":          ADVERSUM_TOOL_VERSION,
                        "informationUri":   "https://github.com/ibonon/Adversum",
                        "rules":            [r.to_dict() for r in self.rules],
                    }
                },
                "invocations": [{
                    "executionSuccessful": self.invocation_success,
                    "startTimeUtc":        self.timestamp,
                }],
                "results":           [r.to_dict() for r in self.results],
                "automationDetails": {"id": f"adversum/{self.run_id}"},
            }]
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_sarif(), indent=indent)


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------

class SARIFv2Exporter:
    """
    Converts Adversum findings (dicts or ValidatedFinding-like objects)
    to SARIF 2.1.0 format.

    Usage:
        exporter = SARIFv2Exporter()
        report   = exporter.export(findings, tool_name="Adversum")
        print(report.to_json())
    """

    # Severity → SARIF level mapping
    _LEVEL_MAP = {
        "CRITICAL": "error",
        "HIGH":     "error",
        "MEDIUM":   "warning",
        "LOW":      "note",
        "INFO":     "note",
    }

    def export(
        self,
        findings: List[dict],
        tool_name: str = "Adversum Security Engine",
        source_root: str = "",
    ) -> SARIFReport:
        """
        Convert a list of Adversum finding dicts to a SARIFReport.

        Each finding dict is expected to have:
            rule_id, description/message, severity, file_path, line_number
        (All fields optional — defaults applied gracefully.)
        """
        rules_by_id: Dict[str, SARIFRule] = {}
        results: List[SARIFResult] = []

        for finding in findings:
            raw = finding.get("raw", finding)
            rule_id   = raw.get("rule_id", finding.get("rule_id", "UNKNOWN"))
            severity  = (finding.get("severity") or raw.get("severity") or "MEDIUM").upper()
            message   = (finding.get("description") or raw.get("description") or
                         finding.get("message") or "Security finding detected.")
            file_path = raw.get("file_path") or finding.get("file_path") or "unknown"
            line_num  = int(raw.get("line_number") or finding.get("line_number") or 1)
            cwe_id    = finding.get("cwe_id") or raw.get("cwe_id") or ""

            # Build rule if first occurrence
            if rule_id not in rules_by_id:
                rules_by_id[rule_id] = SARIFRule(
                    rule_id           = rule_id,
                    name              = rule_id.replace("-", " ").title(),
                    short_description = message[:120],
                    full_description  = message,
                    severity          = self._LEVEL_MAP.get(severity, "warning"),
                    tags              = ["security", "adversum"],
                    cwe_ids           = [cwe_id] if cwe_id else [],
                )

            results.append(SARIFResult(
                rule_id   = rule_id,
                message   = message,
                locations = [SARIFLocation(
                    uri        = file_path.replace("\\", "/"),
                    start_line = line_num,
                    end_line   = line_num,
                )],
                level       = self._LEVEL_MAP.get(severity, "warning"),
                fingerprint = self._fingerprint(rule_id, file_path, line_num),
                properties  = {
                    "severity": severity,
                    "confidence": finding.get("confidence") or "HIGH",
                },
            ))

        return SARIFReport(
            run_id    = str(uuid.uuid4()),
            tool_name = tool_name,
            rules     = list(rules_by_id.values()),
            results   = results,
        )

    @staticmethod
    def _fingerprint(rule_id: str, file_path: str, line: int) -> str:
        import hashlib
        return hashlib.sha256(f"{rule_id}:{file_path}:{line}".encode()).hexdigest()[:16]
