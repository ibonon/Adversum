#!/usr/bin/env python3
"""
Adversum Proof of Reserves & Liability SAST Scanner
Audits liability aggregation queries, database snapshots, Merkle sum tree generators,
and on-chain PoR attestation contracts for critical solvency calculation flaws.
"""
import os
import re
import sys
from typing import List, Dict, Any
from dataclasses import dataclass, asdict

@dataclass
class PoRFinding:
    rule_id: str
    severity: str
    cwe: str
    title: str
    description: str
    file: str
    line: int
    snippet: str
    recommendation: str
    cvss_score: float
    module: str = "proof_of_reserves"

class ProofOfReservesScanner:
    SUPPORTED_EXTENSIONS = {".py", ".ts", ".js", ".sql", ".sol", ".go"}

    def scan_file(self, file_path: str) -> List[PoRFinding]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            lines = content.splitlines()

            # Rule 1: Missing Negative Balance Exclusion in Liability Query / Generator
            liability_query_matches = re.finditer(
                r'(?:SELECT|find|query|aggregate).*(?:sum|balance|liability|user_balance)',
                content,
                re.IGNORECASE
            )
            for match in liability_query_matches:
                start_pos = match.start()
                line_no = content[:start_pos].count('\n') + 1
                context_start = max(0, line_no - 5)
                context_end = min(len(lines), line_no + 15)
                context_text = "\n".join(lines[context_start:context_end])

                if "balance" in context_text.lower() and not re.search(r'(?:balance\s*>=\s*0|balance\s*>\s*0|WHERE.*balance|assert.*balance\s*>=)', context_text, re.IGNORECASE):
                    findings.append(PoRFinding(
                        rule_id="POR-001",
                        severity="CRITICAL",
                        cwe="CWE-840",
                        title="Unvalidated Negative Balances in Proof of Reserves Aggregator",
                        description="Liability aggregation routine does not strictly enforce non-negative user balances, enabling an operator to conceal unbacked liabilities by injecting artificial negative accounts.",
                        file=file_path,
                        line=line_no,
                        snippet=lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0),
                        recommendation="Enforce a strict non-negative check on all leaves: require(user_balance >= 0) and filter queries with WHERE balance >= 0.",
                        cvss_score=9.5
                    ))

            # Rule 2: Unsalted User Hashes in Merkle Leaves (Privacy Leak)
            unsalted_leaf_matches = re.finditer(
                r'(?:sha256|keccak256|createHash)\s*\(\s*(?:user_id|userId|account_id|email)\s*(?:\+|\,)\s*(?:balance|user_balance)\s*\)',
                content,
                re.IGNORECASE
            )
            for match in unsalted_leaf_matches:
                start_pos = match.start()
                line_no = content[:start_pos].count('\n') + 1
                findings.append(PoRFinding(
                    rule_id="POR-002",
                    severity="HIGH",
                    cwe="CWE-359",
                    title="Unsalted Merkle Leaf Hash (Customer Balance Deanonymization)",
                    description="Merkle tree leaf construction hashes user identifiers with balance without a unique user salt, allowing rainbow-table deanonymization of customer account balances.",
                    file=file_path,
                    line=line_no,
                    snippet=lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0),
                    recommendation="Incorporate a high-entropy per-user cryptographic salt: hash(userId + ':' + balance + ':' + userSalt).",
                    cvss_score=7.8
                ))

            # Rule 3: Missing On-Chain Timelock / Multi-Sig on PoR Root Publisher
            por_publish_matches = re.finditer(
                r'function\s+(?:publishRoot|updateReservesRoot|setMerkleRoot|setLiabilitiesRoot)\s*\([^)]*\)',
                content
            )
            for match in por_publish_matches:
                start_pos = match.start()
                line_no = content[:start_pos].count('\n') + 1
                context_start = max(0, line_no - 5)
                context_end = min(len(lines), line_no + 15)
                context_text = "\n".join(lines[context_start:context_end])

                if not re.search(r'(?:onlyAuditor|onlyQuorum|multiSig|timelock|validSignature)', context_text, re.IGNORECASE):
                    findings.append(PoRFinding(
                        rule_id="POR-003",
                        severity="MEDIUM",
                        cwe="CWE-284",
                        title="Unrestricted / Single-Key Proof of Reserves Root Attestation",
                        description="On-chain Proof of Reserves root updater can be executed by a single unconstrained key without independent auditor co-signature or multi-party computation verification.",
                        file=file_path,
                        line=line_no,
                        snippet=lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0),
                        recommendation="Require independent third-party auditor signatures or a multi-sig quorum for on-chain PoR root updates.",
                        cvss_score=6.5
                    ))

        except Exception as e:
            print(f"[WARN] PoR scan failed on {file_path}: {e}", file=sys.stderr)

        return findings

    def scan_directory(self, target_dir: str) -> List[PoRFinding]:
        all_findings = []
        for root, _, files in os.walk(target_dir):
            for file in files:
                if any(file.endswith(ext) for ext in self.SUPPORTED_EXTENSIONS):
                    full_path = os.path.join(root, file)
                    all_findings.extend(self.scan_file(full_path))
        return all_findings
