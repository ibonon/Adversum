#!/usr/bin/env python3
"""
Aderyn Adapter for Adversum (Cyfrin Rust Static Analysis Engine)
================================================================
Executes Aderyn CLI, parses report.json outputs, and maps Cyfrin detectors
to unified SWC, CWE, CVSS 4.0 vectors and remediation guidance.
"""
import os
import sys
import json
import subprocess
import tempfile
from typing import List, Dict, Any, Optional

try:
    from .base import BaseSolidityAdapter
    from ..scanner import SolFinding
except (ImportError, ValueError):
    from base import BaseSolidityAdapter
    from scanner import SolFinding

# Aderyn Detector -> (SWC, CWE, CVSS, Base Severity, Recommendation)
ADERYN_DETECTOR_MAP: Dict[str, Dict[str, Any]] = {
    "reentrancy-vulnerabilities": {
        "swc": "SWC-107", "cwe": "CWE-841", "cvss": 9.8, "severity": "CRITICAL",
        "title": "Aderyn: Reentrancy Vulnerability",
        "recommendation": "Implement checks-effects-interactions (CEI) and OpenZeppelin ReentrancyGuard."
    },
    "unprotected-selfdestruct": {
        "swc": "SWC-106", "cwe": "CWE-284", "cvss": 9.8, "severity": "CRITICAL",
        "title": "Aderyn: Unprotected selfdestruct Call",
        "recommendation": "Protect selfdestruct behind multi-sig authentication or deprecate it."
    },
    "centralization-risk": {
        "swc": "SWC-105", "cwe": "CWE-284", "cvss": 7.5, "severity": "MEDIUM",
        "title": "Aderyn: Centralization Risk (Single Privileged Owner)",
        "recommendation": "Transfer admin roles to a multi-signature wallet (e.g. Safe) or TimelockController."
    },
    "unsafe-erc20-operations": {
        "swc": "SWC-104", "cwe": "CWE-252", "cvss": 7.5, "severity": "HIGH",
        "title": "Aderyn: Unsafe ERC20 Operation (Missing Return Value Check)",
        "recommendation": "Use OpenZeppelin SafeERC20 wrapper functions."
    },
    "push-zero-opcode": {
        "swc": "SWC-100", "cwe": "CWE-1117", "cvss": 3.0, "severity": "LOW",
        "title": "Aderyn: PUSH0 Opcode Compatibility Risk on L2s",
        "recommendation": "Ensure target EVM compiler settings match the target L2 deployment network support."
    },
    "arbitrary-transfer": {
        "swc": "SWC-105", "cwe": "CWE-284", "cvss": 9.2, "severity": "CRITICAL",
        "title": "Aderyn: Arbitrary Token Transfer",
        "recommendation": "Validate that msg.sender has authorized the transfer."
    },
    "unused-state-variable": {
        "swc": "SWC-135", "cwe": "CWE-561", "cvss": 2.0, "severity": "INFO",
        "title": "Aderyn: Unused State Variable",
        "recommendation": "Remove unused variables to save storage and gas."
    },
    "missing-zero-address-validation": {
        "swc": "SWC-100", "cwe": "CWE-20", "cvss": 5.0, "severity": "LOW",
        "title": "Aderyn: Missing Zero-Address Check",
        "recommendation": "Add require(addr != address(0)) check on setters."
    }
}

class AderynAdapter(BaseSolidityAdapter):
    def tool_name(self) -> str:
        return "Aderyn (Cyfrin)"

    def _default_executable_name(self) -> str:
        return "aderyn"

    def _env_var_name(self) -> str:
        return "ADERYN_BIN"

    def run(self, target_path: str, timeout: int = 300) -> List[SolFinding]:
        if not self.is_available():
            return []

        exe = self.executable_path or "aderyn"
        findings: List[SolFinding] = []

        temp_file = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        temp_file.close()
        temp_json_path = temp_file.name

        try:
            target_dir = target_path if os.path.isdir(target_path) else os.path.dirname(target_path) or "."
            cmd = [
                exe,
                "--path", target_dir,
                "--output", temp_json_path
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=target_dir
            )

            if os.path.exists(temp_json_path) and os.path.getsize(temp_json_path) > 0:
                with open(temp_json_path, "r", encoding="utf-8", errors="replace") as f:
                    raw_content = f.read()
                findings = self.parse_json_output(raw_content, target_path)

        except subprocess.TimeoutExpired:
            print(f"[WARN] Aderyn timed out after {timeout}s on {target_path}", file=sys.stderr)
        except Exception as e:
            print(f"[WARN] Aderyn execution failed on {target_path}: {e}", file=sys.stderr)
        finally:
            if os.path.exists(temp_json_path):
                try:
                    os.remove(temp_json_path)
                except OSError:
                    pass

        return findings

    def parse_json_output(self, raw_json: str, target_path: str) -> List[SolFinding]:
        findings: List[SolFinding] = []
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return []

        # Aderyn groups issues by severity category (critical_issues, high_issues, medium_issues, low_issues, nc_issues)
        category_map = {
            "critical_issues": ("CRITICAL", 9.5),
            "high_issues": ("HIGH", 8.0),
            "medium_issues": ("MEDIUM", 5.5),
            "low_issues": ("LOW", 3.5),
            "nc_issues": ("INFO", 2.0)
        }

        for cat_key, (default_sev, default_cvss) in category_map.items():
            cat_obj = data.get(cat_key, {})
            if isinstance(cat_obj, dict):
                issues_list = cat_obj.get("issues", [])
            elif isinstance(cat_obj, list):
                issues_list = cat_obj
            else:
                continue

            for issue in issues_list:
                title = issue.get("title", "Aderyn Security Finding")
                desc = issue.get("description", "").strip()
                detector_name = issue.get("detector_name") or title.lower().replace(" ", "-")
                
                meta = ADERYN_DETECTOR_MAP.get(detector_name, {})
                swc = meta.get("swc", "SWC-100")
                cwe = meta.get("cwe", "CWE-699")
                sev = meta.get("severity", default_sev)
                cvss = meta.get("cvss", default_cvss)
                rec = meta.get("recommendation", "Review Cyfrin Aderyn documentation and apply remediation.")

                rule_id = f"ADERYN-{detector_name.upper().replace('-', '_')}"

                instances = issue.get("instances", [])
                if not instances:
                    # Generic finding without specific file instance
                    findings.append(SolFinding(
                        rule_id=rule_id,
                        severity=sev,
                        cwe=cwe,
                        swc=swc,
                        title=title,
                        description=desc,
                        file=target_path,
                        line=1,
                        snippet=title,
                        recommendation=rec,
                        cvss_score=cvss
                    ))
                else:
                    for inst in instances:
                        cpath = inst.get("contract_path") or inst.get("file_path") or target_path
                        line_no = inst.get("line_no") or inst.get("line") or 1
                        snippet = inst.get("src") or inst.get("snippet") or title

                        findings.append(SolFinding(
                            rule_id=rule_id,
                            severity=sev,
                            cwe=cwe,
                            swc=swc,
                            title=title,
                            description=desc,
                            file=cpath,
                            line=line_no,
                            snippet=snippet[:120],
                            recommendation=rec,
                            cvss_score=cvss
                        ))

        return findings
