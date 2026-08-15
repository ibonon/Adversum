K8S_RULES = [
    {
        "id": "IaC-K8S-001",
        "title": "Privileged container",
        "path": "spec.containers[*].securityContext.privileged",
        "bad_value": True,
        "severity": "CRITICAL",
        "cwe": "CWE-250",
        "cvss": 9.8,
        "description": "Privileged containers have full host system access.",
        "cex_impact": "Exchange node compromise allows fund theft via host access."
    },
    {
        "id": "IaC-K8S-002",
        "title": "Container running as root (runAsUser: 0)",
        "path": "spec.containers[*].securityContext.runAsUser",
        "bad_value": 0,
        "severity": "HIGH",
        "cwe": "CWE-250",
        "cvss": 7.8,
    },
    {
        "id": "IaC-K8S-003",
        "title": "No resource limits defined",
        "severity": "MEDIUM",
        "cvss": 5.5,
        "description": "Containers without resource limits can exhaust node resources (DoS).",
        "cex_impact": "Exchange API unavailability during high-volume trading."
    },
    {
        "id": "IaC-K8S-004",
        "title": "Secret stored as ConfigMap (plaintext)",
        "severity": "CRITICAL",
        "cwe": "CWE-312",
        "cvss": 9.0,
    },
    {
        "id": "IaC-K8S-005",
        "title": "hostPID or hostNetwork enabled",
        "severity": "CRITICAL",
        "cwe": "CWE-668",
        "cvss": 9.8,
    },
    {
        "id": "IaC-K8S-006",
        "title": "Image pull policy not Always (stale images)",
        "severity": "LOW",
    },
    {
        "id": "IaC-K8S-007",
        "title": "No Network Policy defined",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Without NetworkPolicy, any pod can communicate with any other pod.",
        "cex_impact": "Lateral movement from compromised pod to hot wallet service."
    }
]
