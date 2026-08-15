"""
Solidity Fixer — Auto-Remediation pour Smart Contracts
"""
import re

def fix_solidity(finding: dict, content: str) -> str:
    rule_id = finding.get("rule_id", "")
    lines = content.splitlines()
    line_idx = max(0, finding.get("line", 1) - 1)

    if rule_id == "SOL-002" or "tx.origin" in content:
        # Remplace tx.origin par msg.sender
        content = content.replace("tx.origin", "msg.sender")

    if rule_id == "SOL-004" or "pragma solidity" in content:
        # Met a jour la pragma vers >=0.8.0 pour overflow automatique
        content = re.sub(r'pragma solidity \^\d+\.\d+\.\d+;', 'pragma solidity ^0.8.20;', content)

    if rule_id == "SOL-001" or "Reentrancy" in finding.get("title", ""):
        # Ajoute import ReentrancyGuard si pas present
        if "ReentrancyGuard" not in content:
            if "contract " in content:
                content = re.sub(
                    r'(contract\s+\w+)',
                    r'import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";\n\n\1 is ReentrancyGuard',
                    content,
                    count=1
                )

    return content
