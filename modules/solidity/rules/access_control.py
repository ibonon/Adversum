import re

def analyze(content: str) -> list:
    findings = []
    lines = content.split('\n')
    
    for i, line in enumerate(lines):
        # Checking for tx.origin usage
        if re.search(r'tx\.origin\s*(==|!=)', line) or re.search(r'require\(.*tx\.origin', line):
            findings.append({
                'rule_id': 'SOL-002',
                'line': i + 1,
                'snippet': line.strip()
            })
            
        # Checking for selfdestruct without onlyOwner (simplified)
        if 'selfdestruct(' in line or 'suicide(' in line:
            # Look backwards 5 lines for onlyOwner
            context = "".join(lines[max(0, i-5):i+1])
            if 'onlyOwner' not in context and 'require(' not in context:
                findings.append({
                    'rule_id': 'SOL-003',
                    'line': i + 1,
                    'snippet': line.strip()
                })
                
    return findings
