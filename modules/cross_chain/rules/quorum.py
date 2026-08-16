import re
from typing import List, Dict, Any

class QuorumSecurityRule:
    RULE_ID = "BRIDGE-005"
    SEVERITY = "CRITICAL"
    CWE = "CWE-287"
    TITLE = "Weak Relayer Quorum / Duplicate Signer Replay in Bridge Multi-Sig"
    DESCRIPTION = (
        "Bridge multi-signature aggregation loop fails to ensure strictly ascending signer addresses or reject duplicate signatures, "
        "allowing a single valid relayer signature repeated N times to satisfy the multi-sig quorum threshold."
    )
    RECOMMENDATION = (
        "Enforce strict ascending order on recovered signer addresses (require(currentSigner > previousSigner, 'Signers not sorted or duplicate')) "
        "and enforce a robust minimum multi-sig threshold (e.g., >= 2/3 of validator set)."
    )
    CVSS_SCORE = 9.6

    def analyze(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()

        # Look for loops over signatures with ecrecover / ECDSA.recover
        multi_sig_loop = re.finditer(r'for\s*\([^)]+\)\s*\{([^}]+(?:ecrecover|ECDSA\.recover)[^}]+)\}', content, re.DOTALL)
        for match in multi_sig_loop:
            loop_body = match.group(1)
            start_pos = match.start()
            line_no = content[:start_pos].count('\n') + 1

            has_strictly_greater = bool(re.search(r'>\s*lastSigner|>\s*prevSigner|>\s*previousSigner|isSortedAndUnique', loop_body))
            has_seen_signers_mapping = bool(re.search(r'seenSigners\s*\[|visitedSigners\s*\[', loop_body))

            if not (has_strictly_greater or has_seen_signers_mapping):
                findings.append({
                    "rule_id": self.RULE_ID,
                    "severity": self.SEVERITY,
                    "cwe": self.CWE,
                    "title": self.TITLE,
                    "description": "Multi-signature verification loop recovers signers without ensuring uniqueness or ascending address order. An attacker can duplicate a single signature to bypass threshold checks.",
                    "file": file_path,
                    "line": line_no,
                    "snippet": lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0)[:80],
                    "recommendation": self.RECOMMENDATION,
                    "cvss_score": self.CVSS_SCORE,
                    "module": "cross_chain",
                })

        # Check for single-relayer authorization without timelock
        single_relayer_pattern = re.finditer(r'function\s+(?:setRelayer|setValidator|updateRelayer|transferRelayerRole)\s*\([^)]*\)\s*(?:external|public)\s*(?:onlyOwner|onlyAdmin)?', content)
        for match in single_relayer_pattern:
            func_sig = match.group(0)
            start_pos = match.start()
            line_no = content[:start_pos].count('\n') + 1
            context_start = max(0, line_no - 5)
            context_end = min(len(lines), line_no + 20)
            context_text = "\n".join(lines[context_start:context_end])

            if not re.search(r'(?:timelock|delay|queued|schedule|propose)', context_text, re.IGNORECASE):
                findings.append({
                    "rule_id": "BRIDGE-006",
                    "severity": "HIGH",
                    "cwe": "CWE-284",
                    "title": "Instantaneous Relayer/Validator Role Migration Without Timelock",
                    "description": "Critical bridge validator or relayer keys can be replaced immediately without timelock delay, exposing the bridge to total takeover in case of single-key compromise.",
                    "file": file_path,
                    "line": line_no,
                    "snippet": lines[line_no - 1].strip(),
                    "recommendation": "Route validator key rotations through a 48-hour timelock controller to provide emergency response window.",
                    "cvss_score": 8.2,
                    "module": "cross_chain",
                })

        return findings
