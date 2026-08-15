import re

def analyze(content: str) -> list:
    findings = []
    lines = content.split('\n')
    
    for i, line in enumerate(lines):
        # Delegatecall
        if '.delegatecall(' in line:
            findings.append({
                'rule_id': 'SOL-005',
                'line': i + 1,
                'snippet': line.strip()
            })
            
        # Assembly with call/delegatecall
        if 'assembly' in line:
            # Simplistic check, looking ahead
            context = "".join(lines[i:min(i+10, len(lines))])
            if 'call(' in context or 'delegatecall(' in context:
                findings.append({
                    'rule_id': 'SOL-014',
                    'line': i + 1,
                    'snippet': line.strip()
                })
                
        # Obsolete call.value
        if '.call.value' in line:
            findings.append({
                'rule_id': 'SOL-007',
                'line': i + 1,
                'snippet': line.strip()
            })
            
    return findings
