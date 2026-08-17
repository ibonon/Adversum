import re
from typing import List, Dict, Any

class ReplayVulnerabilityRule:
    RULE_ID = "BRIDGE-001"
    SEVERITY = "CRITICAL"
    CWE = "CWE-294"
    TITLE = "Cross-Chain Message Replay Vulnerability"
    DESCRIPTION = (
        "Cross-chain message verification fails to include the destination chain ID (block.chainid) "
        "in the signed message digest or domain separator, allowing transactions to be replayed across multiple chains."
    )
    RECOMMENDATION = (
        "Enforce strict EIP-712 domain separation including block.chainid and target contract address. "
        "Track processed message nonces or hashes in a persistent mapping (e.g., mapping(bytes32 => bool) public executedMessages)."
    )
    CVSS_SCORE = 9.8

    def analyze(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()

        # Check for ecrecover / ECDSA.recover without chainId or domain separator
        ecrecover_matches = re.finditer(r'(?:ecrecover|ECDSA\.recover)\s*\(([^)]+)\)', content, re.IGNORECASE)
        for match in ecrecover_matches:
            call_span = match.group(0)
            start_pos = match.start()
            line_no = content[:start_pos].count('\n') + 1

            # Check surrounding context (25 lines above/below) for chainid and replay mapping
            context_start = max(0, line_no - 25)
            context_end = min(len(lines), line_no + 25)
            context_text = "\n".join(lines[context_start:context_end])

            has_chain_id = bool(re.search(
                r'(?:block\.chainid|chainId|_chainId|DOMAIN_SEPARATOR|_domainSeparatorV4|_hashTypedDataV4|EIP712|EIP712Upgradeable|ERC2612|permit)',
                context_text, re.IGNORECASE
            ))
            has_replay_check = bool(re.search(
                r'(?:executed|processed|consumed|usedNonces|nullifiers|seenMessages|nonces\[|_useNonce|_nonces)\s*\[|\b_useNonce\b|\bnonces\b',
                context_text, re.IGNORECASE
            ))

            if not has_chain_id:
                findings.append({
                    "rule_id": self.RULE_ID,
                    "severity": self.SEVERITY,
                    "cwe": self.CWE,
                    "title": self.TITLE,
                    "description": "Signature verification does not bind the message to the current chainId, enabling cross-chain replay.",
                    "file": file_path,
                    "line": line_no,
                    "snippet": lines[line_no - 1].strip() if line_no <= len(lines) else call_span,
                    "recommendation": self.RECOMMENDATION,
                    "cvss_score": self.CVSS_SCORE,
                    "module": "cross_chain",
                })
            elif not has_replay_check and "view" not in context_text and "pure" not in context_text:
                findings.append({
                    "rule_id": "BRIDGE-002",
                    "severity": "HIGH",
                    "cwe": "CWE-294",
                    "title": "Missing Replay Nullifier in Bridge Message Processing",
                    "description": "Cross-chain packet execution does not record the message hash in an execution registry, allowing identical messages to be processed repeatedly.",
                    "file": file_path,
                    "line": line_no,
                    "snippet": lines[line_no - 1].strip() if line_no <= len(lines) else call_span,
                    "recommendation": "Mark message hashes or nonces as consumed before executing payload: executedMessages[msgHash] = true;",
                    "cvss_score": 8.6,
                    "module": "cross_chain",
                })

        return findings
