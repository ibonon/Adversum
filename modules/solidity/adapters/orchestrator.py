#!/usr/bin/env python3
"""
Multi-Engine Solidity Orchestrator & Smart Deduplicator
======================================================
Coordinates execution of Adversum Native Engine, Slither (Trail of Bits),
and Aderyn (Cyfrin), standardizes all findings into a unified schema,
and deduplicates overlapping detections with composite tool attribution.
"""
import os
import sys
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor

try:
    from .slither_adapter import SlitherAdapter
    from .aderyn_adapter import AderynAdapter
    from ..scanner import SolFinding
except (ImportError, ValueError):
    from slither_adapter import SlitherAdapter
    from aderyn_adapter import AderynAdapter
    from scanner import SolFinding

SEVERITY_WEIGHT = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}

class MultiEngineOrchestrator:
    def __init__(
        self,
        enable_native: bool = True,
        enable_slither: bool = True,
        enable_aderyn: bool = True,
        slither_bin: Optional[str] = None,
        aderyn_bin: Optional[str] = None
    ):
        self.enable_native = enable_native
        self.slither_adapter = SlitherAdapter(executable_path=slither_bin) if enable_slither else None
        self.aderyn_adapter = AderynAdapter(executable_path=aderyn_bin) if enable_aderyn else None

    def get_active_engines(self) -> List[str]:
        engines = []
        if self.enable_native:
            engines.append("Adversum Native AST Engine")
        if self.slither_adapter and self.slither_adapter.is_available():
            engines.append("Slither (Trail of Bits)")
        if self.aderyn_adapter and self.aderyn_adapter.is_available():
            engines.append("Aderyn (Cyfrin)")
        return engines

    def run_all(
        self,
        target_path: str,
        native_findings: Optional[List[SolFinding]] = None,
        timeout: int = 300
    ) -> List[SolFinding]:
        """
        Executes all active Solidity analysis engines and returns a deduplicated list of findings.
        """
        all_findings: List[SolFinding] = []

        if native_findings:
            all_findings.extend(native_findings)

        # Run external tools in parallel
        tasks = []
        if self.slither_adapter and self.slither_adapter.is_available():
            tasks.append(("Slither", self.slither_adapter))
        if self.aderyn_adapter and self.aderyn_adapter.is_available():
            tasks.append(("Aderyn", self.aderyn_adapter))

        if tasks:
            with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
                futures = {
                    executor.submit(adapter.run, target_path, timeout): name
                    for name, adapter in tasks
                }
                for f in futures:
                    name = futures[f]
                    try:
                        res = f.result()
                        all_findings.extend(res)
                    except Exception as e:
                        print(f"[WARN] Engine {name} failed: {e}", file=sys.stderr)

        return self.deduplicate(all_findings)

    def deduplicate(self, findings: List[SolFinding]) -> List[SolFinding]:
        """
        Groups findings by normalized file path, approximate line number (within +/- 3 lines),
        and vulnerability category (SWC/CWE), merging duplicates into a composite finding.
        """
        if not findings:
            return []

        merged_groups: List[SolFinding] = []

        for item in findings:
            item_file = os.path.normpath(item.file).lower()
            item_cwe = (item.cwe or "").upper()
            item_swc = (item.swc or "").upper()
            matched = False

            for existing in merged_groups:
                exist_file = os.path.normpath(existing.file).lower()
                exist_cwe = (existing.cwe or "").upper()
                exist_swc = (existing.swc or "").upper()

                # Same file check
                if item_file != exist_file and not item_file.endswith(exist_file) and not exist_file.endswith(item_file):
                    continue

                # Same line proximity check (within 3 lines)
                if abs(item.line - existing.line) > 3:
                    continue

                # Same vulnerability type check
                cwe_match = (item_cwe and exist_cwe and item_cwe == exist_cwe)
                swc_match = (item_swc and exist_swc and item_swc == exist_swc)
                title_match = (item.rule_id.split("-")[0] == existing.rule_id.split("-")[0])

                if cwe_match or swc_match or title_match:
                    # Duplicate found — Merge metadata!
                    matched = True
                    
                    # 1. Update severity / CVSS to highest
                    if SEVERITY_WEIGHT.get(item.severity.upper(), 0) > SEVERITY_WEIGHT.get(existing.severity.upper(), 0):
                        existing.severity = item.severity
                        existing.cvss_score = max(existing.cvss_score, item.cvss_score)
                    
                    # 2. Enrich description with corroboration note
                    if item.rule_id not in existing.description:
                        existing.description += f" [Corroborated by {item.rule_id}]"

                    # 3. Update SWC/CWE if existing was missing
                    if not existing.swc and item.swc:
                        existing.swc = item.swc
                    if not existing.cwe and item.cwe:
                        existing.cwe = item.cwe

                    break

            if not matched:
                merged_groups.append(item)

        return merged_groups
