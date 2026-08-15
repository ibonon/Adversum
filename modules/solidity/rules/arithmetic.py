import re

def analyze(content: str) -> list:
    findings = []
    lines = content.split('\n')
    
    # Check pragma for pre-0.8.0 versions
    pragma_match = re.search(r'pragma solidity \^?0\.[0-7]\.', content)
    
    for i, line in enumerate(lines):
        if pragma_match and re.search(r'([+\-*/]=?|\+\+|--)', line):
            # Exclude comments
            if not line.strip().startswith('//'):
                findings.append({
                    'rule_id': 'SOL-004',
                    'line': i + 1,
                    'snippet': line.strip()
                })
    return findings
