"""
Python Fixer — Auto-Remediation pour le code Python (Taint & SAST)
"""
import re

def fix_python(finding: dict, content: str) -> str:
    rule_id = finding.get("rule_id", "")
    
    if "EVAL" in rule_id or "eval(" in content:
        if "ast" not in content:
            content = "import ast\n" + content
        content = re.sub(r'eval\(', 'ast.literal_eval(', content)

    if "SYSTEM" in rule_id or "os.system(" in content:
        if "subprocess" not in content:
            content = "import subprocess\n" + content
        content = re.sub(r'os\.system\(([^)]+)\)', r'subprocess.run(\1, shell=False, check=True)', content)

    if "YAML" in rule_id or "yaml.load(" in content:
        content = re.sub(r'yaml\.load\(([^)]+)\)', r'yaml.safe_load(\1)', content)

    return content
