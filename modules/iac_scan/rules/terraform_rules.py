TF_RULES = [
    {
        "id": "IaC-TF-001",
        "title": "S3 bucket with public ACL",
        "pattern": r'acl\s*=\s*["\']public-read',
        "severity": "CRITICAL",
        "cwe": "CWE-732",
        "cvss": 9.1,
        "cex_impact": "Exchange user data, KYC documents, or logs exposed publicly."
    },
    {
        "id": "IaC-TF-002",
        "title": "Security group open to 0.0.0.0/0 on sensitive ports",
        "pattern": r'cidr_blocks\s*=\s*\[["\']0\.0\.0\.0/0',
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "cvss": 9.8,
    },
    {
        "id": "IaC-TF-003",
        "title": "RDS with publicly accessible enabled",
        "pattern": r'publicly_accessible\s*=\s*true',
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "cvss": 9.5,
        "cex_impact": "Exchange database directly accessible from internet."
    },
    {
        "id": "IaC-TF-004",
        "title": "S3 bucket without encryption",
        "pattern": r'aws_s3_bucket(?!.*server_side_encryption)',
        "severity": "HIGH",
        "cwe": "CWE-311",
        "cvss": 7.5,
    },
    {
        "id": "IaC-TF-005",
        "title": "CloudTrail logging disabled",
        "severity": "HIGH",
        "cwe": "CWE-778",
        "cvss": 7.0,
        "cex_impact": "No audit trail for privileged operations on exchange infrastructure."
    },
    {
        "id": "IaC-TF-006",
        "title": "IAM policy with * permissions",
        "pattern": r'\"Effect\"\s*:\s*\"Allow\"[^}]*\"Action\"\s*:\s*\"\*\"',
        "severity": "CRITICAL",
        "cwe": "CWE-732",
        "cvss": 9.8,
    }
]
