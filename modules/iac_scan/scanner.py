#!/usr/bin/env python3
"""
Adversum IaC Scanner
Detects real Infrastructure-as-Code misconfigurations in Dockerfiles,
Kubernetes YAML, Terraform (.tf) and docker-compose files.
"""
import os
import re
import json

# ---------------------------------------------------------------------------
# Dockerfile patterns
# ---------------------------------------------------------------------------

# Captures any ENV assignment: ENV KEY=value or ENV KEY value
_DOCKERFILE_ENV_ASSIGN = re.compile(
    r'^ENV\s+(?P<key>[A-Z0-9_]+)\s*[=\s]\s*(?P<val>\S[^\\\n]*)',
    re.IGNORECASE | re.MULTILINE,
)

# Keywords that indicate a variable holds a secret (matches anywhere in the var name)
_SECRET_KEYWORD = re.compile(
    r'(?:SECRET|PASSWORD|PASSWD|API_?KEY|APIKEY|TOKEN|PRIVATE_?KEY|SIGNING_?KEY|HMAC_?KEY|JWT_?SECRET|DB_?PASS|DB_?PASSWORD|AUTH_?TOKEN|CREDENTIALS?|CERT|PRIVATE)',
    re.IGNORECASE,
)


# Detects ADD with a URL (security anti-pattern — no checksum verification)
_DOCKERFILE_ADD_URL = re.compile(
    r'^ADD\s+https?://',
    re.IGNORECASE | re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Kubernetes / docker-compose YAML patterns
# ---------------------------------------------------------------------------
_K8S_PRIVILEGED      = re.compile(r'privileged\s*:\s*true',          re.IGNORECASE)
_K8S_HOST_PID        = re.compile(r'hostPID\s*:\s*true',             re.IGNORECASE)
_K8S_HOST_NETWORK    = re.compile(r'hostNetwork\s*:\s*true',         re.IGNORECASE)
_K8S_ALL_CAPS        = re.compile(r'add\s*:\s*\[?["\']?ALL["\']?\]?', re.IGNORECASE)
_K8S_NO_READONLY_FS  = re.compile(r'readOnlyRootFilesystem\s*:\s*false', re.IGNORECASE)

# ---------------------------------------------------------------------------
# Terraform patterns
# ---------------------------------------------------------------------------
_TF_PUBLIC_READ      = re.compile(r'acl\s*=\s*["\']public-read["\']',     re.IGNORECASE)
_TF_PUBLIC_READ_WRITE= re.compile(r'acl\s*=\s*["\']public-read-write["\']', re.IGNORECASE)
_TF_OPEN_CIDR        = re.compile(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', re.IGNORECASE)
_TF_UNENCRYPTED_S3   = re.compile(r'server_side_encryption_configuration', re.IGNORECASE)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_line(content: str, match_start: int) -> int:
    """Return 1-based line number for a match offset."""
    return content.count('\n', 0, match_start) + 1


def _find_all(pattern, content: str) -> list:
    """Return list of (line_no, snippet) for all pattern matches."""
    results = []
    for m in pattern.finditer(content):
        lineno = _find_line(content, m.start())
        snippet = content.splitlines()[lineno - 1].strip()[:120]
        results.append((lineno, snippet))
    return results


def _make_finding(rule_id, severity, cwe, title, description, path, line, snippet, recommendation, cvss):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "cwe": cwe,
        "title": title,
        "description": description,
        "file": path,
        "line": line,
        "snippet": snippet,
        "recommendation": recommendation,
        "cvss_score": cvss,
    }


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

class IaCScanner:
    def __init__(self):
        kb_path = os.path.join(os.path.dirname(__file__), 'kb', 'iac_vulnerabilities.json')
        if os.path.exists(kb_path):
            with open(kb_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.kb = data.get('vulnerabilities', []) if isinstance(data, dict) else data
        else:
            self.kb = []
        self.kb_map = {v['id']: v for v in self.kb}

    def scan_file(self, path: str) -> list:
        if not os.path.exists(path):
            return []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return []

        filename = os.path.basename(path)
        filename_lower = filename.lower()

        # Detect Dockerfiles: named 'Dockerfile', 'dockerfile', or ending with '.dockerfile'
        is_dockerfile = (
            filename_lower == 'dockerfile'
            or filename_lower.endswith('.dockerfile')
            or 'dockerfile' in filename_lower
        )

        if is_dockerfile:
            return self._scan_dockerfile(path, content)
        elif path.endswith(('.yaml', '.yml')):
            return self._scan_yaml(path, content)
        elif path.endswith('.tf'):
            return self._scan_terraform(path, content)
        elif filename_lower == '.env' or 'docker-compose' in filename_lower:
            return self._scan_yaml(path, content) if path.endswith(('.yaml', '.yml')) else []
        return []

    # ── Dockerfile ──────────────────────────────────────────────────────────

    def _scan_dockerfile(self, path: str, content: str) -> list:
        findings = []
        lines = content.splitlines()

        # IaC-DF-001: Running as root (no USER instruction found anywhere)
        # Only flag if there is actually a RUN / ENTRYPOINT / CMD present (real active image)
        has_from = any(l.strip().upper().startswith('FROM') for l in lines)
        has_user = any(re.match(r'^\s*USER\s+', l, re.IGNORECASE) for l in lines)
        has_cmd  = any(re.match(r'^\s*(CMD|ENTRYPOINT|RUN)\s+', l, re.IGNORECASE) for l in lines)

        if has_from and has_cmd and not has_user:
            # Find the first FROM line to point to
            from_line = next((i+1 for i, l in enumerate(lines)
                              if l.strip().upper().startswith('FROM')), 1)
            from_snippet = lines[from_line - 1].strip()[:120]
            findings.append(_make_finding(
                "IaC-DF-001", "HIGH", "CWE-250",
                "Container running as root",
                "No USER instruction found. Container will execute as root by default.",
                path, from_line, from_snippet,
                "Add a 'USER <uid>' instruction before CMD/ENTRYPOINT.",
                7.8,
            ))

        # IaC-DF-002: Secrets hardcoded in ENV
        for m in _DOCKERFILE_ENV_ASSIGN.finditer(content):
            key = m.group('key')
            val = m.group('val').strip()
            # Only flag if the variable name contains a known secret keyword
            if not _SECRET_KEYWORD.search(key):
                continue
            # Skip env-var references: ${VAR}, $VAR
            if val.startswith('$') or '${' in val:
                continue
            # Skip placeholders and empty-looking values
            if len(val) < 4 or val.upper() in ('TRUE', 'FALSE', 'NULL', 'NONE', '""', "''"):
                continue
            lineno = _find_line(content, m.start())
            snippet = content.splitlines()[lineno - 1].strip()[:120]

            findings.append(_make_finding(
                "IaC-DF-002", "CRITICAL", "CWE-798",
                "Secret hardcoded in Dockerfile ENV",
                "Secrets in ENV instructions are stored in image layers and visible in docker history.",
                path, lineno, snippet,
                "Use Docker secrets, BuildKit secrets, or load from a vault at runtime.",
                9.0,
            ))

        # IaC-DF-003: ADD with URL (no integrity check)
        for lineno, snippet in _find_all(_DOCKERFILE_ADD_URL, content):
            findings.append(_make_finding(
                "IaC-DF-003", "MEDIUM", "CWE-494",
                "ADD instruction fetches URL without integrity check",
                "Using ADD with a URL skips checksum verification, enabling supply-chain attacks.",
                path, lineno, snippet,
                "Use RUN curl + sha256sum verification, or COPY with a trusted local file.",
                5.9,
            ))

        return findings

    # ── Kubernetes / docker-compose YAML ─────────────────────────────────────

    def _scan_yaml(self, path: str, content: str) -> list:
        findings = []

        checks = [
            (_K8S_PRIVILEGED, "IaC-K8S-001", "CRITICAL", "CWE-250",
             "Privileged container",
             "Privileged containers have unrestricted access to the host kernel. A breakout grants root on the node.",
             "Remove 'privileged: true' or replace with specific capabilities.",
             9.8),
            (_K8S_HOST_PID, "IaC-K8S-002", "HIGH", "CWE-250",
             "hostPID enabled",
             "Container can see all host processes, enabling container escape and privilege escalation.",
             "Remove 'hostPID: true' unless absolutely required.",
             8.2),
            (_K8S_HOST_NETWORK, "IaC-K8S-003", "HIGH", "CWE-668",
             "hostNetwork enabled",
             "Container shares the host's network namespace, bypassing network policies.",
             "Remove 'hostNetwork: true'.",
             7.5),
            (_K8S_ALL_CAPS, "IaC-K8S-004", "HIGH", "CWE-250",
             "All Linux capabilities granted",
             "capabilities.add: [ALL] grants every kernel capability to the container.",
             "Drop all capabilities and add only the specific ones needed.",
             8.1),
            (_K8S_NO_READONLY_FS, "IaC-K8S-005", "MEDIUM", "CWE-276",
             "Writable root filesystem",
             "readOnlyRootFilesystem: false allows attackers to modify container files after compromise.",
             "Set 'readOnlyRootFilesystem: true' and use emptyDir volumes for writable paths.",
             5.5),
        ]

        for pattern, rule_id, severity, cwe, title, description, recommendation, cvss in checks:
            for lineno, snippet in _find_all(pattern, content):
                findings.append(_make_finding(
                    rule_id, severity, cwe, title, description,
                    path, lineno, snippet, recommendation, cvss,
                ))

        return findings

    # ── Terraform ────────────────────────────────────────────────────────────

    def _scan_terraform(self, path: str, content: str) -> list:
        findings = []

        tf_checks = [
            (_TF_PUBLIC_READ, "IaC-TF-001", "CRITICAL", "CWE-732",
             "S3 bucket publicly readable",
             "ACL 'public-read' exposes all bucket objects to the internet.",
             "Remove public ACL; use IAM bucket policies with explicit principals.",
             9.1),
            (_TF_PUBLIC_READ_WRITE, "IaC-TF-002", "CRITICAL", "CWE-732",
             "S3 bucket publicly readable and writable",
             "ACL 'public-read-write' allows anyone to read and write objects.",
             "Remove public ACL immediately.",
             9.8),
            (_TF_OPEN_CIDR, "IaC-TF-003", "HIGH", "CWE-284",
             "Security group open to 0.0.0.0/0",
             "Ingress rule allows traffic from any IP address.",
             "Restrict cidr_blocks to specific trusted IP ranges.",
             8.6),
        ]

        for pattern, rule_id, severity, cwe, title, description, recommendation, cvss in tf_checks:
            for lineno, snippet in _find_all(pattern, content):
                findings.append(_make_finding(
                    rule_id, severity, cwe, title, description,
                    path, lineno, snippet, recommendation, cvss,
                ))

        return findings


def main():
    pass


if __name__ == '__main__':
    main()
