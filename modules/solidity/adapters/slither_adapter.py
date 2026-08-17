#!/usr/bin/env python3
"""
Slither Adapter for Adversum (Trail of Bits Static Analysis Engine)
===================================================================
Executes Slither CLI, parses raw JSON detector outputs, and maps 80+ detectors
to precise SWC, CWE, CVSS 4.0 vectors and actionable remediation guidance.
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

# Comprehensive Slither Detector -> (SWC, CWE, CVSS, Base Severity, Recommendation)
SLITHER_DETECTOR_MAP: Dict[str, Dict[str, Any]] = {
    # High / Critical
    "reentrancy-eth": {
        "swc": "SWC-107", "cwe": "CWE-841", "cvss": 9.8, "severity": "CRITICAL",
        "title": "Reentrancy Vulnerability (ETH transfer)",
        "recommendation": "Apply the Checks-Effects-Interactions (CEI) pattern and use OpenZeppelin ReentrancyGuard."
    },
    "reentrancy-no-eth": {
        "swc": "SWC-107", "cwe": "CWE-841", "cvss": 8.6, "severity": "HIGH",
        "title": "Reentrancy Vulnerability (State / Token transfer)",
        "recommendation": "Update internal state before calling external token transfer methods."
    },
    "reentrancy-unlimited-gas": {
        "swc": "SWC-107", "cwe": "CWE-841", "cvss": 8.8, "severity": "HIGH",
        "title": "Reentrancy with forward of unlimited gas",
        "recommendation": "Avoid using raw call{value: ...} without reentrancy protection."
    },
    "suicidal": {
        "swc": "SWC-106", "cwe": "CWE-284", "cvss": 9.8, "severity": "CRITICAL",
        "title": "Unprotected selfdestruct Instruction",
        "recommendation": "Protect selfdestruct behind multi-sig and timelock access control, or remove it entirely."
    },
    "controlled-delegatecall": {
        "swc": "SWC-112", "cwe": "CWE-829", "cvss": 9.8, "severity": "CRITICAL",
        "title": "Controlled delegatecall Destination",
        "recommendation": "Ensure delegatecall targets are immutable or controlled strictly by admin access guards."
    },
    "arbitrary-send-eth": {
        "swc": "SWC-105", "cwe": "CWE-284", "cvss": 9.3, "severity": "CRITICAL",
        "title": "Arbitrary ETH Transfer to User-Controlled Address",
        "recommendation": "Enforce strict withdrawal balance accounting and authorization checks."
    },
    "arbitrary-send-erc20": {
        "swc": "SWC-105", "cwe": "CWE-284", "cvss": 9.1, "severity": "CRITICAL",
        "title": "Arbitrary ERC20 Token Transfer",
        "recommendation": "Ensure transferFrom callers cannot specify arbitrary 'from' addresses without prior allowance."
    },
    "tx-origin": {
        "swc": "SWC-115", "cwe": "CWE-284", "cvss": 8.2, "severity": "HIGH",
        "title": "Authentication via tx.origin (Phishing Vulnerability)",
        "recommendation": "Use msg.sender instead of tx.origin for authentication and access control."
    },
    "uninitialized-state": {
        "swc": "SWC-109", "cwe": "CWE-457", "cvss": 8.5, "severity": "HIGH",
        "title": "Uninitialized State Variable",
        "recommendation": "Initialize state variables at declaration or inside the constructor/initializer."
    },
    "uninitialized-storage": {
        "swc": "SWC-109", "cwe": "CWE-824", "cvss": 9.0, "severity": "HIGH",
        "title": "Uninitialized Storage Pointer",
        "recommendation": "Explicitly assign storage pointers or use memory keyword."
    },
    "unchecked-transfer": {
        "swc": "SWC-104", "cwe": "CWE-252", "cvss": 7.5, "severity": "HIGH",
        "title": "Unchecked Return Value for ERC20 transfer / transferFrom",
        "recommendation": "Use OpenZeppelin SafeERC20 (safeTransfer / safeTransferFrom) or check the boolean return value."
    },
    "unchecked-lowlevel": {
        "swc": "SWC-104", "cwe": "CWE-252", "cvss": 7.5, "severity": "HIGH",
        "title": "Unchecked Return Value of Low-Level Call",
        "recommendation": "Require success boolean on low-level call: (bool success, ) = target.call(...); require(success)."
    },
    "shadowing-state": {
        "swc": "SWC-119", "cwe": "CWE-710", "cvss": 6.5, "severity": "MEDIUM",
        "title": "State Variable Shadowing",
        "recommendation": "Rename the shadowed variable to avoid inheritance conflicts."
    },
    "divide-before-multiply": {
        "swc": "SWC-101", "cwe": "CWE-682", "cvss": 7.0, "severity": "MEDIUM",
        "title": "Precision Loss Due to Division Before Multiplication",
        "recommendation": "Perform all multiplications before divisions to prevent precision loss in integer arithmetic."
    },
    "timestamp": {
        "swc": "SWC-116", "cwe": "CWE-330", "cvss": 5.3, "severity": "MEDIUM",
        "title": "Dangerous Reliance on block.timestamp",
        "recommendation": "Do not use block.timestamp as a source of randomness or exact time comparison."
    },
    "weak-prng": {
        "swc": "SWC-120", "cwe": "CWE-330", "cvss": 7.5, "severity": "HIGH",
        "title": "Weak Pseudo-Random Number Generation (PRNG)",
        "recommendation": "Use Chainlink VRF or commit-reveal schemes instead of on-chain block variables."
    },
    "assembly": {
        "swc": "SWC-127", "cwe": "CWE-1117", "cvss": 4.5, "severity": "LOW",
        "title": "Use of Inline Assembly",
        "recommendation": "Limit inline assembly usage to performance-critical paths and document safety invariants."
    },
    "constant-function-asm": {
        "swc": "SWC-128", "cwe": "CWE-1117", "cvss": 5.5, "severity": "LOW",
        "title": "Constant/View Function with Assembly Modification",
        "recommendation": "Ensure view/pure functions do not write to contract storage in assembly blocks."
    },
    "costly-loop": {
        "swc": "SWC-128", "cwe": "CWE-400", "cvss": 6.0, "severity": "MEDIUM",
        "title": "Costly Loop (Denial of Service via Block Gas Limit)",
        "recommendation": "Avoid unbounded loops over dynamically-sized arrays; use pull-over-push patterns."
    },
    "dead-code": {
        "swc": "SWC-135", "cwe": "CWE-561", "cvss": 2.5, "severity": "INFO",
        "title": "Dead / Unreachable Code",
        "recommendation": "Remove unused functions and variables to improve readability and save bytecode size."
    },
    "unprotected-upgrade": {
        "swc": "SWC-105", "cwe": "CWE-284", "cvss": 9.8, "severity": "CRITICAL",
        "title": "Unprotected Upgradeable Proxy Initializer",
        "recommendation": "Invoke _disableInitializers() in constructor and guard initialize() with initializer modifier."
    },
    "missing-zero-check": {
        "swc": "SWC-100", "cwe": "CWE-20", "cvss": 5.0, "severity": "LOW",
        "title": "Missing Zero Address Validation",
        "recommendation": "Add require(address_param != address(0), 'Zero address error') to critical setters."
    }
}

class SlitherAdapter(BaseSolidityAdapter):
    def tool_name(self) -> str:
        return "Slither (Trail of Bits)"

    def _default_executable_name(self) -> str:
        return "slither"

    def _env_var_name(self) -> str:
        return "SLITHER_BIN"

    def run(self, target_path: str, timeout: int = 300) -> List[SolFinding]:
        if not self.is_available():
            return []

        exe = self.executable_path or "slither"
        findings: List[SolFinding] = []

        # Create temporary file for Slither JSON output
        temp_file = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        temp_file.close()
        temp_json_path = temp_file.name

        try:
            cmd = [
                exe,
                target_path,
                "--json", temp_json_path,
                "--checklist",
                "--solc-disable-warnings"
            ]

            # If targeting a project directory, set cwd
            cwd = target_path if os.path.isdir(target_path) else os.path.dirname(target_path) or None

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd
            )

            # Slither writes JSON to temp_json_path even if exit code is non-zero (it exits non-zero if vulnerabilities are found)
            if os.path.exists(temp_json_path) and os.path.getsize(temp_json_path) > 0:
                with open(temp_json_path, "r", encoding="utf-8", errors="replace") as f:
                    raw_content = f.read()
                findings = self.parse_json_output(raw_content, target_path)

        except subprocess.TimeoutExpired:
            print(f"[WARN] Slither timed out after {timeout}s on {target_path}", file=sys.stderr)
        except Exception as e:
            print(f"[WARN] Slither execution failed on {target_path}: {e}", file=sys.stderr)
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

        results = data.get("results", {})
        detectors = results.get("detectors", [])

        for item in detectors:
            check_name = item.get("check", "unknown")
            description = item.get("description", "").strip()
            impact = (item.get("impact") or "Low").upper()

            # Retrieve mapped metadata or default values
            meta = SLITHER_DETECTOR_MAP.get(check_name, {})
            swc = meta.get("swc", "SWC-100")
            cwe = meta.get("cwe", "CWE-699")
            title = meta.get("title", f"Slither: {check_name.replace('-', ' ').title()}")
            recommendation = meta.get("recommendation", "Review and remediate according to Trail of Bits guidelines.")
            
            # Severity mapping
            severity = meta.get("severity")
            if not severity:
                if impact in ("HIGH", "CRITICAL"):
                    severity = "HIGH"
                elif impact == "MEDIUM":
                    severity = "MEDIUM"
                elif impact == "LOW":
                    severity = "LOW"
                else:
                    severity = "INFO"

            cvss = meta.get("cvss", 7.5 if severity == "HIGH" else 5.0 if severity == "MEDIUM" else 3.0)

            # Extract source location from elements
            elements = item.get("elements", [])
            file_loc = target_path
            line_no = 1
            snippet = ""

            for el in elements:
                src_map = el.get("source_mapping", {})
                if src_map:
                    fname = src_map.get("filename_relative") or src_map.get("filename_absolute")
                    if fname:
                        file_loc = fname
                    lines = src_map.get("lines", [])
                    if lines:
                        line_no = lines[0]
                    snippet = el.get("name", "")
                    break

            rule_id = f"SLITHER-{check_name.upper().replace('-', '_')}"

            findings.append(SolFinding(
                rule_id=rule_id,
                severity=severity,
                cwe=cwe,
                swc=swc,
                title=title,
                description=description or title,
                file=file_loc,
                line=line_no,
                snippet=snippet or description[:80],
                recommendation=recommendation,
                cvss_score=cvss
            ))

        return findings
