import re

def analyze(content: str) -> list:
    findings = []
    lines = content.split('\n')
    
    for i, line in enumerate(lines):
        # ERC20 transfer without boolean check
        if '.transfer(' in line and 'require(' not in line and 'bool' not in line:
            findings.append({
                'rule_id': 'SOL-007',
                'line': i + 1,
                'snippet': line.strip()
            })
            
        # Approve front-running vulnerability
        if 'approve(' in line:
            # Note: This is a simplistic check; real detection needs data flow.
            # Using SOL-009 as a placeholder for front-running issues.
            findings.append({
                'rule_id': 'SOL-009',
                'line': i + 1,
                'snippet': line.strip()
            })
            
    return findings
