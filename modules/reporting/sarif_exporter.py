#!/usr/bin/env python3
"""
Adversum Universal SARIF 2.1.0 Institutional Exporter
====================================================
Transforms unified correlated findings into fully compliant OASIS SARIF v2.1.0 JSON.
Directly compatible with:
  - GitHub Advanced Security (Code Scanning Alerts & PR Annotations)
  - VS Code SARIF Viewer
  - GitLab SAST Reports
  - SonarQube / DefectDojo
"""

import os
import json
from typing import List, Dict, Any, Optional

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

SEVERITY_TO_CVSS = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.5",
    "LOW": "3.0",
    "INFO": "1.0",
}


class SarifExporter:
    """Exports findings to OASIS SARIF v2.1.0 format with rich metadata and automated fix suggestions."""

    def __init__(self, tool_name: str = "Adversum Security Intelligence", tool_version: str = "5.0.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def export(
        self,
        findings: List[Dict[str, Any]],
        base_path: Optional[str] = None,
        executive_scorecard: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Converts correlated findings into a SARIF 2.1.0 object."""
        rules_dict: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        base_path_abs = os.path.abspath(base_path) if base_path else os.getcwd()

        for f in findings:
            rule_id = str(f.get("rule_id", "ADV-SEC-001"))
            sev = (f.get("severity") or "MEDIUM").upper()
            title = f.get("title") or f.get("message") or rule_id
            desc = f.get("description") or f.get("message") or title
            file_path = f.get("file") or f.get("file_path") or "unknown"
            line = int(f.get("line") or f.get("line_number") or 1)
            snippet = f.get("snippet") or ""

            # Normaliser chemin relatif pour GitHub Code Scanning
            if os.path.isabs(file_path):
                try:
                    rel_file = os.path.relpath(file_path, base_path_abs)
                except ValueError:
                    rel_file = file_path
            else:
                rel_file = file_path
            rel_file = rel_file.replace("\\", "/")

            # Compliance metadata
            cwe_tag = f.get("cwe")
            cwe_id = cwe_tag.get("cwe_id", "CWE-699") if isinstance(cwe_tag, dict) else str(cwe_tag or "CWE-699")
            cwe_name = cwe_tag.get("name", "Software Security Weakness") if isinstance(cwe_tag, dict) else cwe_id
            cwe_url = cwe_tag.get("url", f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html") if isinstance(cwe_tag, dict) else ""

            owasp_tag = str(f.get("owasp") or "A05:2021-Security Misconfiguration")
            mitre_tag = f.get("mitre_attack")
            mitre_id = mitre_tag.get("technique_id", "T1005") if isinstance(mitre_tag, dict) else ""

            # 1. Register Rule
            if rule_id not in rules_dict:
                tags = ["security", "institutional"]
                if cwe_id:
                    tags.append(f"external/cwe/{cwe_id.lower()}")
                if owasp_tag:
                    tags.append(f"owasp/{owasp_tag.split('-')[0].lower()}")
                if mitre_id:
                    tags.append(f"mitre-attack/{mitre_id.lower()}")

                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": title.replace(" ", "_"),
                    "shortDescription": {"text": title[:100]},
                    "fullDescription": {"text": desc},
                    "helpUri": cwe_url or "https://github.com/ibonon/Adversum",
                    "defaultConfiguration": {
                        "level": SEVERITY_TO_LEVEL.get(sev, "warning")
                    },
                    "properties": {
                        "security-severity": SEVERITY_TO_CVSS.get(sev, "5.0"),
                        "tags": tags,
                        "precision": "very-high" if f.get("consensus_score", 0) >= 0.9 else "high",
                        "problem.severity": SEVERITY_TO_LEVEL.get(sev, "warning"),
                    }
                }

            # 2. Build Result
            result_obj: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": SEVERITY_TO_LEVEL.get(sev, "warning"),
                "message": {
                    "text": f"[{sev}] {title}: {desc}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": rel_file,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": max(1, line),
                                "snippet": {
                                    "text": snippet
                                }
                            }
                        }
                    }
                ],
                "properties": {
                    "severity": sev,
                    "module": f.get("module", "native"),
                    "consensusScore": f.get("consensus_score", 0.78),
                    "confidenceLevel": f.get("confidence_level", "Medium"),
                    "enginesConfirmed": f.get("engines_confirmed", [f.get("module", "native")]),
                    "cwe": cwe_id,
                    "owasp": owasp_tag,
                    "isSmtVerified": bool(f.get("proof") or f.get("smt_verified")),
                }
            }

            # 3. Attach Automated Code Fix if proposed
            fix_code = f.get("fix_code") or f.get("patched_snippet")
            if fix_code:
                result_obj["fixes"] = [
                    {
                        "description": {
                            "text": f"Apply verified Adversum fix for {rule_id}"
                        },
                        "fileChanges": [
                            {
                                "artifactLocation": {
                                    "uri": rel_file
                                },
                                "replacements": [
                                    {
                                        "deletedRegion": {
                                            "startLine": max(1, line)
                                        },
                                        "insertedContent": {
                                            "text": fix_code
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]

            results.append(result_obj)

        # Build Top-Level SARIF Object
        run_obj: Dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": self.tool_name,
                    "version": self.tool_version,
                    "semanticVersion": self.tool_version,
                    "informationUri": "https://github.com/ibonon/Adversum",
                    "rules": list(rules_dict.values())
                }
            },
            "results": results
        }

        if executive_scorecard:
            run_obj["properties"] = {
                "adversumScore": executive_scorecard.get("security_score"),
                "adversumGrade": executive_scorecard.get("security_grade"),
                "postureStatus": executive_scorecard.get("posture_status"),
                "totalFindings": executive_scorecard.get("total_findings"),
                "multiEngineQuorums": executive_scorecard.get("multi_engine_quorums"),
                "ccssReady": executive_scorecard.get("ccss_ready"),
            }

        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [run_obj]
        }
