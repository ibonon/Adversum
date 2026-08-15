import re

DOCKERFILE_RULES = [
    {
        "id": "IaC-DF-001",
        "title": "Container running as root",
        "check": lambda instrs: not any(i.instruction == 'USER' and i.args != 'root' for i in instrs),
        "severity": "HIGH",
        "cwe": "CWE-250",
        "cvss": 7.8,
        "description": "Container runs as root by default. If compromised, attacker has full container privileges.",
        "cex_impact": "Root container + host mount = full exchange server compromise.",
        "fix": "Add 'USER appuser' instruction after package installation."
    },
    {
        "id": "IaC-DF-002",
        "title": "Secrets in ENV instructions",
        "check": lambda instrs: any(re.search(r'ENV\s+(?:PASSWORD|SECRET|KEY|TOKEN|API_KEY)\s*=\s*\S+', i.raw, re.I) for i in instrs if i.instruction == 'ENV'),
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "cvss": 9.0,
        "description": "Secrets hardcoded in Dockerfile ENV are visible in docker history and image layers.",
        "cex_impact": "Exchange API keys or DB passwords exposed in image history.",
        "fix": "Use Docker secrets, env_file with .gitignore, or vault integration."
    },
    {
        "id": "IaC-DF-003",
        "title": "Latest tag used (non-deterministic build)",
        "severity": "MEDIUM",
        "cwe": "CWE-1357",
        "cvss": 5.0,
    },
    {
        "id": "IaC-DF-004",
        "title": "No HEALTHCHECK instruction",
        "severity": "LOW",
        "cvss": 3.1,
    },
    {
        "id": "IaC-DF-005",
        "title": "ADD used instead of COPY (potential tar extraction vuln)",
        "severity": "MEDIUM",
        "cwe": "CWE-22",
        "cvss": 5.5,
    }
]
