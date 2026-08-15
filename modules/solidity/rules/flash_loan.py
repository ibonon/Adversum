import re

def analyze(content: str) -> list:
    findings = []
    lines = content.split('\n')
    
    flash_loan_callbacks = ['onFlashLoan', 'executeOperation', 'uniswapV2Call']
    
    for i, line in enumerate(lines):
        for callback in flash_loan_callbacks:
            if f'function {callback}' in line:
                # Look ahead for initiator validation
                context = "".join(lines[i:min(i+15, len(lines))])
                if 'require(msg.sender' not in context and 'require(_initiator' not in context:
                    findings.append({
                        'rule_id': 'SOL-015', # Assuming mapped to unvalidated callback
                        'line': i + 1,
                        'snippet': line.strip()
                    })
    return findings
