#!/usr/bin/env python3
"""
Adversum Solidity Scanner — Smart Contract Security Analysis
Multi-Engine Architecture: Native AST/Regex Engine + Slither (Trail of Bits) + Aderyn (Cyfrin)
"""
import os
import json
import importlib
import pkgutil
import argparse
from dataclasses import dataclass, asdict
from typing import List, Optional

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
    def __init__(
        self,
        rules_package=None,
        kb_path=None,
        enable_native: bool = True,
        enable_slither: bool = True,
        enable_aderyn: bool = True,
        slither_bin: Optional[str] = None,
        aderyn_bin: Optional[str] = None
    ):
        # Default rules package and kb_path if not provided
        if rules_package is None:
            try:
                from . import rules as default_rules
                rules_package = default_rules
            except (ImportError, ValueError):
                import rules as default_rules
                rules_package = default_rules

        if kb_path is None:
            kb_path = os.path.join(os.path.dirname(__file__), 'kb', 'vulnerabilities.json')

        self.rules_package = rules_package
        self.enable_native = enable_native

        if os.path.exists(kb_path):
            with open(kb_path, 'r', encoding='utf-8') as f:
                self.kb = json.load(f).get('vulnerabilities', [])
        else:
            self.kb = []

        self.kb_map = {v['id']: v for v in self.kb}
        self.rules = []
        if self.enable_native and self.rules_package:
            self._load_rules()

        # Multi-Engine Orchestrator (Slither + Aderyn)
        try:
            from .adapters.orchestrator import MultiEngineOrchestrator
            self.orchestrator = MultiEngineOrchestrator(
                enable_native=enable_native,
                enable_slither=enable_slither,
                enable_aderyn=enable_aderyn,
                slither_bin=slither_bin,
                aderyn_bin=aderyn_bin
            )
        except (ImportError, ValueError):
            try:
                from adapters.orchestrator import MultiEngineOrchestrator
                self.orchestrator = MultiEngineOrchestrator(
                    enable_native=enable_native,
                    enable_slither=enable_slither,
                    enable_aderyn=enable_aderyn,
                    slither_bin=slither_bin,
                    aderyn_bin=aderyn_bin
                )
            except Exception:
                self.orchestrator = None

    def _load_rules(self):
        try:
            for _, name, _ in pkgutil.iter_modules(self.rules_package.__path__):
                mod = importlib.import_module(f'{self.rules_package.__name__}.{name}')
                if hasattr(mod, 'analyze'):
                    self.rules.append(mod.analyze)
        except Exception as e:
            print(f"[WARN] Failed to load native Solidity rules: {e}")

    def scan_file(self, path: str) -> List[SolFinding]:
        findings = []
        if self.enable_native:
            try:
                with open(path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()

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
            except Exception as e:
                print(f"[WARN] Error scanning file {path}: {e}")

        # If running on single file and orchestrator is enabled, pass findings through deduplicator
        if self.orchestrator:
            return self.orchestrator.deduplicate(findings)
        return findings

    def scan_directory(self, path: str) -> List[SolFinding]:
        native_findings = []
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(('.sol', '.vy')):
                    native_findings.extend(self.scan_file(os.path.join(root, file)))

        if self.orchestrator:
            return self.orchestrator.run_all(path, native_findings=native_findings)

        return native_findings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Adversum Solidity Scanner (Multi-Engine)")
    parser.add_argument('--target', required=True, help="File or directory to scan")
    parser.add_argument('--format', choices=['json', 'sarif'], default='json')
    parser.add_argument('--no-slither', action='store_true', help="Disable Slither engine")
    parser.add_argument('--no-aderyn', action='store_true', help="Disable Aderyn engine")
    parser.add_argument('--slither-bin', help="Custom path to Slither executable")
    parser.add_argument('--aderyn-bin', help="Custom path to Aderyn executable")
    args = parser.parse_args()

    scanner = SolidityScanner(
        enable_slither=not args.no_slither,
        enable_aderyn=not args.no_aderyn,
        slither_bin=args.slither_bin,
        aderyn_bin=args.aderyn_bin
    )

    if os.path.isdir(args.target):
        findings = scanner.scan_directory(args.target)
    else:
        findings = scanner.scan_file(args.target)

    if args.format == 'sarif':
        try:
            from output.sarif_emitter import to_sarif
            print(json.dumps(to_sarif(findings), indent=2))
        except ImportError:
            print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(json.dumps([asdict(f) for f in findings], indent=2))
