"""
IaC Fixer — Auto-Remediation pour configurations d'Infrastructure-as-Code
"""
import re

def fix_iac(finding: dict, content: str) -> str:
    rule_id = finding.get("rule_id", "")
    
    if rule_id == "IaC-DF-001" or ("Dockerfile" in finding.get("file", "") and "USER" not in content):
        # Ajoute USER appuser avant CMD/ENTRYPOINT
        if "CMD" in content:
            content = content.replace("CMD", "USER appuser\nCMD", 1)
        elif "ENTRYPOINT" in content:
            content = content.replace("ENTRYPOINT", "USER appuser\nENTRYPOINT", 1)
        else:
            content += "\nUSER appuser\n"

    if rule_id == "IaC-DF-002" or "DATABASE_PASSWORD" in content:
        # Enleve secret en ENV
        content = re.sub(r'ENV\s+DATABASE_PASSWORD=.*', '# ENV DATABASE_PASSWORD removed (use secrets volume)', content)

    if rule_id == "IaC-K8S-001" or "privileged: true" in content:
        # Passe privileged: true à false
        content = content.replace("privileged: true", "privileged: false")

    if rule_id == "IaC-TF-001" or "public-read" in content:
        # Passe public-read à private
        content = content.replace('acl = "public-read"', 'acl = "private"')
        content = content.replace("acl    = \"public-read\"", 'acl    = "private"')

    return content
