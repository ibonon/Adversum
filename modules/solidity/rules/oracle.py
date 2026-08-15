import re

def analyze(content: str) -> list:
    findings = []
    lines = content.split('\n')
    
    for i, line in enumerate(lines):
        # Direct use of getReserves for spot price
        if 'getReserves()' in line:
            findings.append({
                'rule_id': 'SOL-009', # Mapped to manipulation
                'line': i + 1,
                'snippet': line.strip()
            })
            
        # Using block.timestamp as a price source (heuristic)
        if 'block.timestamp' in line and ('price' in line.lower() or 'rate' in line.lower()):
            findings.append({
                'rule_id': 'SOL-006',
                'line': i + 1,
                'snippet': line.strip()
            })
            
    return findings
