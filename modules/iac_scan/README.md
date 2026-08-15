# IaC Scan Module

This module analyzes Infrastructure-as-Code to detect configuration vulnerabilities, specifically tailored for AlphaNex Exchange (CEX) environments where infrastructure must be bulletproof.

## Categories and Rules
- Dockerfile: Root containers, secrets in ENV, non-deterministic tags.
- Kubernetes: Privileged containers, missing resource limits, host namespaces.
- Terraform: Public S3 buckets, open security groups, disabled CloudTrail.

## Usage
```bash
# Scan a directory
python scanner.py --target ./infra/ --format sarif

# Specific scan
python scanner.py --target ./k8s/ --type kubernetes --format markdown

# Generate CEX checklist
python scanner.py --checklist cex --format markdown
```
