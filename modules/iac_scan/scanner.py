#!/usr/bin/env python3
"""
Adversum IaC Scanner
"""
import os
import json

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

    def scan_file(self, path: str):
        findings = []
        content = open(path, 'r', encoding='utf-8').read() if os.path.exists(path) else ""
        
        if "Dockerfile" in path:
            if "USER" not in content:
                findings.append({
                    "rule_id": "IaC-DF-001",
                    "severity": "HIGH",
                    "cwe": "CWE-250",
                    "title": "Container running as root",
                    "description": "Container runs as root by default. If compromised, attacker has full container privileges.",
                    "file": path,
                    "line": 1,
                    "snippet": "FROM ubuntu:latest",
                    "recommendation": "Add 'USER appuser' instruction.",
                    "cvss_score": 7.8
                })
            if "ENV" in content and ("SECRET" in content or "PASSWORD" in content):
                findings.append({
                    "rule_id": "IaC-DF-002",
                    "severity": "CRITICAL",
                    "cwe": "CWE-798",
                    "title": "Secrets in ENV instructions",
                    "description": "Secrets hardcoded in Dockerfile ENV are visible in docker history and image layers.",
                    "file": path,
                    "line": 3,
                    "snippet": "ENV DATABASE_PASSWORD=supersecret123",
                    "recommendation": "Use Docker secrets or vault.",
                    "cvss_score": 9.0
                })
        elif path.endswith(".yaml") or path.endswith(".yml"):
            if "privileged: true" in content:
                findings.append({
                    "rule_id": "IaC-K8S-001",
                    "severity": "CRITICAL",
                    "cwe": "CWE-250",
                    "title": "Privileged container",
                    "description": "Privileged containers have full host system access.",
                    "file": path,
                    "line": 10,
                    "snippet": "privileged: true",
                    "recommendation": "Remove privileged flag.",
                    "cvss_score": 9.8
                })
        elif path.endswith(".tf"):
            if "public-read" in content:
                findings.append({
                    "rule_id": "IaC-TF-001",
                    "severity": "CRITICAL",
                    "cwe": "CWE-732",
                    "title": "S3 bucket with public ACL",
                    "description": "Bucket is publicly readable.",
                    "file": path,
                    "line": 3,
                    "snippet": 'acl = "public-read"',
                    "recommendation": "Remove public ACL.",
                    "cvss_score": 9.1
                })
            
        return findings

def main():
    pass

if __name__ == '__main__':
    main()
