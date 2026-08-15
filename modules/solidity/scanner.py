#!/usr/bin/env python3
"""
Adversum Solidity Scanner — Smart Contract Security Analysis
Contexte : Audit sécurité plateforme CEX (AlphaNex Exchange)
"""
import os
import json
import importlib
import pkgutil
import argparse
from dataclasses import dataclass, asdict
from typing import List

@dataclass
class SolFinding:
    rule_id: str
    severity: str
    cwe: str
    swc: str
    title: str
    description: str
    file: str
    line: int
    snippet: str
    recommendation: str
    cvss_score: float

class SolidityScanner:
    def __init__(self, rules_package, kb_path):
        self.rules_package = rules_package
        with open(kb_path, 'r', encoding='utf-8') as f:
            self.kb = json.load(f)['vulnerabilities']
        self.kb_map = {v['id']: v for v in self.kb}
        self.rules = []
        self._load_rules()
    
    def _load_rules(self):
        for _, name, _ in pkgutil.iter_modules(self.rules_package.__path__):
            mod = importlib.import_module(f'{self.rules_package.__name__}.{name}')
            if hasattr(mod, 'analyze'):
                self.rules.append(mod.analyze)

    def scan_file(self, path: str) -> List[SolFinding]:
        findings = []
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {path}: {e}")
            return findings

        for rule in self.rules:
            results = rule(content)
            for res in results:
                kb_info = self.kb_map.get(res['rule_id'], {})
                findings.append(SolFinding(
                    rule_id=res['rule_id'],
                    severity=kb_info.get('severity', 'INFO'),
                    cwe=kb_info.get('cwe', ''),
                    swc=kb_info.get('swc', ''),
                    title=kb_info.get('title', 'Unknown Vulnerability'),
                    description=kb_info.get('description', ''),
                    file=path,
                    line=res['line'],
                    snippet=res['snippet'],
                    recommendation=kb_info.get('recommendation', ''),
                    cvss_score=kb_info.get('cvss_score', 0.0)
                ))
        return findings

    def scan_directory(self, path: str) -> List[SolFinding]:
        all_findings = []
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(('.sol', '.vy')):
                    all_findings.extend(self.scan_file(os.path.join(root, file)))
        return all_findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Adversum Solidity Scanner")
    parser.add_argument('--target', required=True, help="File or directory to scan")
    parser.add_argument('--format', choices=['json', 'sarif'], default='json')
    args = parser.parse_args()

    import rules
    scanner = SolidityScanner(rules, 'kb/vulnerabilities.json')
    
    if os.path.isdir(args.target):
        findings = scanner.scan_directory(args.target)
    else:
        findings = scanner.scan_file(args.target)
        
    if args.format == 'sarif':
        from output.sarif_emitter import to_sarif
        print(json.dumps(to_sarif(findings), indent=2))
    else:
        print(json.dumps([asdict(f) for f in findings], indent=2))
