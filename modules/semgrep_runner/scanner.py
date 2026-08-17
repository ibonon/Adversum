#!/usr/bin/env python3
"""
Adversum Semgrep Runner & Institutional Semantic Rules Engine
============================================================
Integrates Semgrep OSS CLI with custom institutional YAML rules and community
registries (p/security-audit, p/owasp, p/secrets), parsing findings into Adversum's
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
class SemgrepFinding:
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
    module: str = "semgrep"

class SemgrepScanner:
    def __init__(self, executable_path: Optional[str] = None, default_config: Optional[str] = None):
        self.executable_path = executable_path or self._find_executable()
        self.rules_dir = os.path.join(os.path.dirname(__file__), "rules", "institutional")
        self.default_config = default_config or self.rules_dir

    def _find_executable(self) -> Optional[str]:
        env_bin = os.environ.get("SEMGREP_BIN")
        if env_bin and os.path.exists(env_bin):
            return env_bin
        return shutil.which("semgrep")

    def is_available(self) -> bool:
        """Returns True if the semgrep binary is installed and reachable."""
        return bool(self.executable_path and (os.path.exists(self.executable_path) or shutil.which(self.executable_path)))

    def scan(self, target_path: str, config: Optional[str] = None, timeout: int = 300) -> List[SemgrepFinding]:
        """
        Runs Semgrep on target file or directory with specified or default institutional rules.
        """
        if not self.is_available():
            return []

        active_config = config or self.default_config
        exe = self.executable_path or "semgrep"
        findings: List[SemgrepFinding] = []

        try:
            cmd = [
                exe,
                "scan",
                "--config", active_config,
                "--json",
                "--quiet",
                "--disable-version-check",
                "--no-git-ignore" if os.path.isfile(target_path) else "--metrics=off",
                target_path
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=target_path if os.path.isdir(target_path) else os.path.dirname(target_path) or None
            )

            # Semgrep writes JSON to stdout
            if proc.stdout and proc.stdout.strip().startswith("{"):
                findings = self.parse_json_output(proc.stdout, target_path)
            elif proc.stderr and "{" in proc.stderr:
                # In some cases output is sent to stderr
                findings = self.parse_json_output(proc.stderr[proc.stderr.find("{"):], target_path)

        except subprocess.TimeoutExpired:
            print(f"[WARN] Semgrep timed out after {timeout}s on {target_path}", file=sys.stderr)
        except Exception as e:
            print(f"[WARN] Semgrep execution error on {target_path}: {e}", file=sys.stderr)

        return findings

    def parse_json_output(self, raw_json: str, target_path: str) -> List[SemgrepFinding]:
        """
        Parses Semgrep raw JSON output and converts each result into a normalized SemgrepFinding.
        """
        findings: List[SemgrepFinding] = []
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return []

        results = data.get("results", [])
        for item in results:
            check_id = item.get("check_id", "semgrep-finding")
            path = item.get("path", target_path)
            start = item.get("start", {})
            line_no = start.get("line", 1)
            
            extra = item.get("extra", {})
            message = extra.get("message", "").strip()
            raw_severity = extra.get("severity", "WARNING").upper()
            metadata = extra.get("metadata", {})
            
            lines_snippet = extra.get("lines", message[:120])
            snippet = lines_snippet.strip().split("\n")[0][:120] if lines_snippet else ""

            # Metadata extraction
            cwe = metadata.get("cwe", "CWE-699")
            if isinstance(cwe, list):
                cwe = cwe[0] if cwe else "CWE-699"

            custom_rule_id = metadata.get("rule_id", f"SEMGREP-{check_id.upper().replace('.', '_').replace('-', '_')}")
            title = metadata.get("title", check_id.split(".")[-1].replace("-", " ").title())
            recommendation = metadata.get("recommendation", "Review code logic and apply remediation according to security best practices.")

            # Severity & CVSS mapping
            if "cvss" in metadata:
                try:
                    cvss = float(metadata["cvss"])
                except (ValueError, TypeError):
                    cvss = 7.5
            else:
                if raw_severity == "ERROR":
                    cvss = 8.8
                elif raw_severity == "WARNING":
                    cvss = 6.0
                elif raw_severity == "INFO":
                    cvss = 3.5
                else:
                    cvss = 5.0

            if raw_severity == "ERROR":
                severity = "CRITICAL" if cvss >= 9.0 else "HIGH"
            elif raw_severity == "WARNING":
                severity = "MEDIUM"
            elif raw_severity == "INFO":
                severity = "LOW"
            else:
                severity = "INFO"

            findings.append(SemgrepFinding(
                rule_id=custom_rule_id,
                severity=severity,
                cwe=str(cwe),
                title=title,
                description=message or title,
                file=path,
                line=line_no,
                snippet=snippet,
                recommendation=recommendation,
                cvss_score=cvss
            ))

        return findings
