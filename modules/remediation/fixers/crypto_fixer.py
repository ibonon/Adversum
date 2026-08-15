"""
Crypto Fixer — Auto-Remediation pour mauvais usages cryptographiques
"""
import re

def fix_crypto(finding: dict, content: str) -> str:
    rule_id = finding.get("rule_id", "")
    
    if rule_id == "CRYPTO-001" or "md5" in content.lower():
        # Remplace md5 par sha256
        content = re.sub(r'hashlib\.md5\(', 'hashlib.sha256(', content)
        content = re.sub(r'createHash\(["\']md5["\']\)', 'createHash("sha256")', content)

    if rule_id == "CRYPTO-003" or "MODE_ECB" in content:
        # Remplace MODE_ECB par MODE_GCM
        content = content.replace("AES.MODE_ECB", "AES.MODE_GCM")

    if rule_id == "CRYPTO-008" or "verify=False" in content:
        # Remplace verify=False par verify=True
        content = content.replace("verify=False", "verify=True")
        content = content.replace("verify = False", "verify = True")

    if rule_id == "CRYPTO-004" or "AES_KEY" in content:
        # Remplace les clés hardcodées par os.getenv
        content = re.sub(r'AES_KEY\s*=\s*b?["\'][^"\']+["\']', 'import os; AES_KEY = os.getenv("AES_SECRET_KEY", "default_secure_key").encode()', content)

    return content
