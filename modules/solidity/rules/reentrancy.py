import re

def analyze(content: str) -> list:
    findings = []
    lines = content.split('\n')
    
    has_non_reentrant = 'nonReentrant' in content
    
    for i, line in enumerate(lines):
        # Very basic check for external calls before state updates
        if re.search(r'\.(call\{|transfer\(|send\()', line):
            if not has_non_reentrant:
                findings.append({
                    'rule_id': 'SOL-001',
                    'line': i + 1,
                    'snippet': line.strip()
                })
    return findings
