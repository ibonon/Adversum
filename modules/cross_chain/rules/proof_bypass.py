import re
from typing import List, Dict, Any

class ProofBypassRule:
    RULE_ID = "BRIDGE-003"
    SEVERITY = "CRITICAL"
    CWE = "CWE-697"
    TITLE = "Uninitialized Root / Zero-Value Merkle Proof Bypass"
    DESCRIPTION = (
        "Bridge verification accepts uninitialized or zero-hash roots (bytes32(0)), allowing attackers to forge arbitrary "
        "cross-chain state proofs (identical to the Nomad Bridge $190M vulnerability pattern)."
    )
    RECOMMENDATION = (
        "Explicitly disallow zero-hash roots: require(root != bytes32(0), 'Invalid zero root'); "
        "Initialize confirmation mappings with non-zero sentinel values rather than default storage state."
    )
    CVSS_SCORE = 10.0

    def analyze(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()

        # Check for Merkle / Root lookup mappings like acceptableRoot[root] or roots[root]
        root_lookup_pattern = re.compile(
            r'(?:acceptableRoot|acceptableRoots|validRoots|approvedRoots|confirmedRoots|roots)\s*\[([^\]]+)\]',
            re.IGNORECASE
        )

        for match in root_lookup_pattern.finditer(content):
            root_var = match.group(1).strip()
            start_pos = match.start()
            line_no = content[:start_pos].count('\n') + 1

            # Check if there is an explicit check preventing bytes32(0) or 0x0
            context_start = max(0, line_no - 15)
            context_end = min(len(lines), line_no + 15)
            context_text = "\n".join(lines[context_start:context_end])

            has_zero_check = bool(re.search(
                rf'(?:require|if)\s*\(\s*(?:{re.escape(root_var)}\s*!=\s*(?:bytes32\(0\)|0x0|address\(0\)|0)|!isZero\({re.escape(root_var)}\))',
                context_text
            ))

            if not has_zero_check:
                findings.append({
                    "rule_id": self.RULE_ID,
                    "severity": self.SEVERITY,
                    "cwe": self.CWE,
                    "title": self.TITLE,
                    "description": f"Root variable '{root_var}' is queried in acceptable root mapping without verifying '{root_var} != bytes32(0)', which can allow default uninitialized storage roots to validate forged messages.",
                    "file": file_path,
                    "line": line_no,
                    "snippet": lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0),
                    "recommendation": self.RECOMMENDATION,
                    "cvss_score": self.CVSS_SCORE,
                    "module": "cross_chain",
                })

        # Check for MerkleProof.verify where leaf or root is unchecked
        merkle_verify_matches = re.finditer(r'MerkleProof(?:Upgradeable)?\.verify\s*\(([^)]+)\)', content)
        for match in merkle_verify_matches:
            args = [a.strip() for a in match.group(1).split(',')]
            start_pos = match.start()
            line_no = content[:start_pos].count('\n') + 1
            if len(args) >= 3:
                root_arg = args[1]
                leaf_arg = args[2]
                context_start = max(0, line_no - 10)
                context_end = min(len(lines), line_no + 10)
                context_text = "\n".join(lines[context_start:context_end])
                if "require" not in context_text and "revert" not in context_text:
                    findings.append({
                        "rule_id": "BRIDGE-004",
                        "severity": "HIGH",
                        "cwe": "CWE-345",
                        "title": "Unchecked MerkleProof Verification Return Value",
                        "description": "MerkleProof.verify returns a boolean that is not asserted, allowing unverified cross-chain proofs to proceed.",
                        "file": file_path,
                        "line": line_no,
                        "snippet": lines[line_no - 1].strip(),
                        "recommendation": "Wrap MerkleProof verification in a require statement: require(MerkleProof.verify(proof, root, leaf), 'Invalid proof');",
                        "cvss_score": 8.8,
                        "module": "cross_chain",
                    })

        return findings
