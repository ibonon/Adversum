#!/usr/bin/env python3
"""
Adversum Cross-Chain Bridge & Interoperability Scanner
Analyzes bridge contracts, relayer verification routines, message execution mappings,
and Merkle proof handlers for high-impact cross-chain vulnerability patterns.
"""
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

# Import rules
try:
    from .rules import ALL_RULES
except ImportError:
    from rules import ALL_RULES

@dataclass
class BridgeFinding:
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
    module: str = "cross_chain"

class CrossChainScanner:
    SUPPORTED_EXTENSIONS = {".sol", ".vy", ".rs"}

    def __init__(self):
        self.rules = [rule_cls() for rule_cls in ALL_RULES]

    def scan_file(self, file_path: str) -> List[BridgeFinding]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            for rule in self.rules:
                rule_findings = rule.analyze(content, file_path)
                for rf in rule_findings:
                    findings.append(BridgeFinding(
                        rule_id=rf["rule_id"],
                        severity=rf["severity"],
                        cwe=rf["cwe"],
                        title=rf["title"],
                        description=rf["description"],
                        file=rf["file"],
                        line=rf["line"],
                        snippet=rf["snippet"],
                        recommendation=rf["recommendation"],
                        cvss_score=rf["cvss_score"],
                        module="cross_chain"
                    ))
        except Exception as e:
            print(f"[WARN] Error scanning {file_path} in cross_chain scanner: {e}", file=sys.stderr)

        return findings

    def scan_directory(self, target_dir: str) -> List[BridgeFinding]:
        all_findings = []
        for root, _, files in os.walk(target_dir):
            for file in files:
                if any(file.endswith(ext) for ext in self.SUPPORTED_EXTENSIONS):
                    full_path = os.path.join(root, file)
                    all_findings.extend(self.scan_file(full_path))
        return all_findings

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Adversum Cross-Chain Bridge Scanner")
    parser.add_argument("--target", required=True, help="Target file or directory to scan")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    args = parser.parse_args()

    scanner = CrossChainScanner()
    if os.path.isfile(args.target):
        res = scanner.scan_file(args.target)
    else:
        res = scanner.scan_directory(args.target)

    if args.json:
        print(json.dumps([asdict(f) for f in res], indent=2))
    else:
        print(f"\n[+] Cross-Chain Scan Results ({len(res)} findings):")
        for f in res:
            print(f"  [{f.severity}] {f.rule_id} ({f.file}:{f.line}) - {f.title}")
            print(f"     Fix: {f.recommendation}\n")
