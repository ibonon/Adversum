import re
from typing import List, Dict, Any

class UnbackedMintRule:
    RULE_ID = "BRIDGE-007"
    SEVERITY = "CRITICAL"
    CWE = "CWE-284"
    TITLE = "Unconstrained Cross-Chain Minting / Missing Collateral Backing Invariant"
    DESCRIPTION = (
        "Bridge execution logic invokes token minting functions without verifying that underlying collateral is locked 1:1 on the source chain, "
        "or allows arbitrary destination contracts to trigger minting (unbacked asset inflation)."
    )
    RECOMMENDATION = (
        "Enforce strict minter role separation (e.g. AccessControl DEFAULT_ADMIN_ROLE / BRIDGE_ROLE), "
        "maintain circuit-breaker caps on daily net mint volume, and verify proof of collateral lock."
    )
    CVSS_SCORE = 9.9

    def analyze(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()

        # Check for minting calls inside external bridge message callbacks
        mint_patterns = re.finditer(r'(?:_mint|mint)\s*\(\s*([^,\)]+)\s*,\s*([^,\)]+)\s*\)', content)
        for match in mint_patterns:
            start_pos = match.start()
            line_no = content[:start_pos].count('\n') + 1

            context_start = max(0, line_no - 20)
            context_end = min(len(lines), line_no + 10)
            context_text = "\n".join(lines[context_start:context_end])

            # Check if this is within a bridge execution handler without access control or proof check
            is_in_bridge_function = bool(re.search(r'function\s+(?:handleMessage|processMessage|onReceive|executeCrossChain|mintWrapped|unlock)', context_text, re.IGNORECASE))
            has_guard = bool(re.search(r'(?:onlyBridge|onlyRelayer|onlyGateway|require\(msg\.sender|require\(isValidProof)', context_text))
            has_rate_limit = bool(re.search(r'(?:dailyLimit|rateLimit|circuitBreaker|volumeCap|maxMintPerDay)', context_text, re.IGNORECASE))

            if is_in_bridge_function and not has_guard:
                findings.append({
                    "rule_id": self.RULE_ID,
                    "severity": self.SEVERITY,
                    "cwe": self.CWE,
                    "title": self.TITLE,
                    "description": "Bridge token minting routine lacks caller authentication or valid message proof verification, allowing arbitrary users to mint unbacked wrapped assets.",
                    "file": file_path,
                    "line": line_no,
                    "snippet": lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0),
                    "recommendation": self.RECOMMENDATION,
                    "cvss_score": self.CVSS_SCORE,
                    "module": "cross_chain",
                })
            elif is_in_bridge_function and not has_rate_limit:
                findings.append({
                    "rule_id": "BRIDGE-008",
                    "severity": "MEDIUM",
                    "cwe": "CWE-770",
                    "title": "Missing Rate-Limiting / Circuit Breaker on Cross-Chain Minting",
                    "description": "Cross-chain bridge mints assets without a global rate-limiting ceiling or circuit-breaker, enabling catastrophic total drain in case of zero-day exploit.",
                    "file": file_path,
                    "line": line_no,
                    "snippet": lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0),
                    "recommendation": "Implement an hourly/daily net outflow rate-limiter and automated pause trigger when unusual volume is detected.",
                    "cvss_score": 6.8,
                    "module": "cross_chain",
                })

        return findings
