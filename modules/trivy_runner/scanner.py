#!/usr/bin/env python3
"""
Adversum Trivy Runner (Aqua Security SCA, Dependency CVEs, IaC & Secrets)
========================================================================
Executes Trivy CLI, parses Schema v2 JSON outputs, and maps CVEs, package
version fixes, IaC misconfigurations, and leaked credentials to Adversum's
unified finding schema and CVSS 4.0 framework.
"""
import os
import sys
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

@dataclass
class TrivyFinding:
    rule_id: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cwe: str
    title: str
    description: str
    file: str
    line: int
    snippet: str
    recommendation: str
    cvss_score: float
    module: str = "trivy"
    pkg_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None

class TrivyScanner:
    def __init__(self, executable_path: Optional[str] = None):
        self.executable_path = executable_path or self._find_executable()

    def _find_executable(self) -> Optional[str]:
        env_bin = os.environ.get("TRIVY_BIN")
        if env_bin and os.path.exists(env_bin):
            return env_bin
        return shutil.which("trivy")

    def is_available(self) -> bool:
        """Returns True if the trivy binary is installed and reachable."""
        return bool(self.executable_path and (os.path.exists(self.executable_path) or shutil.which(self.executable_path)))

    def scan(
        self,
        target_path: str,
        scanners: str = "vuln,misconfig,secret",
        timeout: int = 300
    ) -> List[TrivyFinding]:
        """
        Runs Trivy filesystem scan on target and returns normalized findings.
        """
        if not self.is_available():
            return []

        exe = self.executable_path or "trivy"
        findings: List[TrivyFinding] = []

        temp_file = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        temp_file.close()
        temp_json_path = temp_file.name

        try:
            cmd = [
                exe,
                "fs",
                "--scanners", scanners,
                "--format", "json",
                "--output", temp_json_path,
                "--quiet",
                target_path
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=target_path if os.path.isdir(target_path) else os.path.dirname(target_path) or None
            )

            if os.path.exists(temp_json_path) and os.path.getsize(temp_json_path) > 0:
                with open(temp_json_path, "r", encoding="utf-8", errors="replace") as f:
                    raw_content = f.read()
                findings = self.parse_json_output(raw_content, target_path)

        except subprocess.TimeoutExpired:
            print(f"[WARN] Trivy timed out after {timeout}s on {target_path}", file=sys.stderr)
        except Exception as e:
            print(f"[WARN] Trivy execution failed on {target_path}: {e}", file=sys.stderr)
        finally:
            if os.path.exists(temp_json_path):
                try:
                    os.remove(temp_json_path)
                except OSError:
                    pass

        return findings

    def parse_json_output(self, raw_json: str, target_path: str) -> List[TrivyFinding]:
        """
        Parses Trivy Schema v2 JSON output across Vulnerabilities, Misconfigurations, and Secrets.
        """
        findings: List[TrivyFinding] = []
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return []

        results = data.get("Results", [])
        for target_result in results:
            target_file = target_result.get("Target", target_path)
            
            # 1. Package Vulnerabilities (SCA / CVEs)
            for vuln in target_result.get("Vulnerabilities", []):
                vuln_id = vuln.get("VulnerabilityID", "UNKNOWN-CVE")
                pkg_name = vuln.get("PkgName", "unknown-package")
                installed_ver = vuln.get("InstalledVersion", "")
                fixed_ver = vuln.get("FixedVersion", "")
                raw_sev = (vuln.get("Severity") or "UNKNOWN").upper()
                title = vuln.get("Title") or f"Vulnerability {vuln_id} in {pkg_name}"
                desc = vuln.get("Description", "").strip() or title
                primary_url = vuln.get("PrimaryURL", "")

                # CWE Extraction
                cwe_ids = vuln.get("CweIDs", [])
                cwe = cwe_ids[0] if cwe_ids else "CWE-1395"

                # CVSS Score extraction
                cvss_data = vuln.get("CVSS", {})
                cvss_score = 7.5
                if "nvd" in cvss_data and "V3Score" in cvss_data["nvd"]:
                    cvss_score = float(cvss_data["nvd"]["V3Score"])
                elif "redhat" in cvss_data and "V3Score" in cvss_data["redhat"]:
                    cvss_score = float(cvss_data["redhat"]["V3Score"])
                else:
                    if raw_sev == "CRITICAL":
                        cvss_score = 9.8
                    elif raw_sev == "HIGH":
                        cvss_score = 7.8
                    elif raw_sev == "MEDIUM":
                        cvss_score = 5.5
                    elif raw_sev == "LOW":
                        cvss_score = 3.0

                severity = raw_sev if raw_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "INFO"

                fix_msg = f"Upgrade {pkg_name} to version {fixed_ver} or higher." if fixed_ver else f"Review upstream advisory for {pkg_name}."
                if primary_url:
                    fix_msg += f" Advisory: {primary_url}"

                snippet = f"{pkg_name}@{installed_ver}"
                if fixed_ver:
                    snippet += f" -> fixed in {fixed_ver}"

                findings.append(TrivyFinding(
                    rule_id=f"TRIVY-{vuln_id}",
                    severity=severity,
                    cwe=cwe,
                    title=f"{vuln_id}: {pkg_name} ({installed_ver})",
                    description=desc,
                    file=target_file,
                    line=1,
                    snippet=snippet,
                    recommendation=fix_msg,
                    cvss_score=cvss_score,
                    pkg_name=pkg_name,
                    installed_version=installed_ver,
                    fixed_version=fixed_ver
                ))

            # 2. Infrastructure-as-Code Misconfigurations (Docker, K8s, Terraform)
            for misconf in target_result.get("Misconfigurations", []):
                misc_id = misconf.get("ID", "MISCONFIG")
                title = misconf.get("Title", "IaC Security Misconfiguration")
                desc = misconf.get("Description", "").strip()
                resolution = misconf.get("Resolution", "").strip()
                raw_sev = (misconf.get("Severity") or "MEDIUM").upper()
                primary_url = misconf.get("PrimaryURL", "")

                severity = raw_sev if raw_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"
                cvss_score = 8.5 if severity == "CRITICAL" else 7.0 if severity == "HIGH" else 4.5 if severity == "MEDIUM" else 2.5

                # Extract line number if available
                line_no = 1
                lines_info = misconf.get("Lines", [])
                if lines_info and isinstance(lines_info, list) and len(lines_info) > 0:
                    line_no = lines_info[0].get("Number", 1)

                rec = resolution or "Remediate infrastructure configuration according to Aqua Security best practices."
                if primary_url:
                    rec += f" Reference: {primary_url}"

                findings.append(TrivyFinding(
                    rule_id=f"TRIVY-IAC-{misc_id}",
                    severity=severity,
                    cwe="CWE-1008",
                    title=title,
                    description=desc or title,
                    file=target_file,
                    line=line_no,
                    snippet=title,
                    recommendation=rec,
                    cvss_score=cvss_score
                ))

            # 3. Leaked Credentials / Secrets
            for secret in target_result.get("Secrets", []):
                sec_id = secret.get("RuleID", "LEAKED_SECRET")
                category = secret.get("Category", "Secret")
                title = secret.get("Title", f"Exposed {category} Credential")
                raw_sev = (secret.get("Severity") or "CRITICAL").upper()
                start_line = secret.get("StartLine", 1)

                findings.append(TrivyFinding(
                    rule_id=f"TRIVY-SECRET-{sec_id.upper().replace('-', '_')}",
                    severity=raw_sev if raw_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "CRITICAL",
                    cwe="CWE-798",
                    title=title,
                    description=f"Hardcoded sensitive {category} credential exposed in source file.",
                    file=target_file,
                    line=start_line,
                    snippet=title,
                    recommendation="Immediately revoke and rotate the exposed credential, and remove it from git history.",
                    cvss_score=9.8
                ))

        return findings
