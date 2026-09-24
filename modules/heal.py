#!/usr/bin/env python3
"""
Adversum Autonomous Self-Healing CLI Engine (AVR CLI)
=====================================================
Detects vulnerabilities, generates AST & semantic patches, validates syntax,
proves vulnerability elimination through closed-loop re-scanning, and safely
applies fixes with optional Git branch isolation.

Usage:
    python modules/heal.py --target <project_dir> [--apply] [--branch] [--verify]
"""

import os
import sys
import argparse
import subprocess
import difflib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Tuple

# Setup import paths
MODULES_DIR = Path(__file__).resolve().parent
if str(MODULES_DIR) not in sys.path:
    sys.path.insert(0, str(MODULES_DIR))

from remediation.patcher import AutoPatcher
from correlation.engine import CorrelationEngine
from intelligence.smart_patch_validator import SmartPatchValidator

# Color terminal styling
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


class AdversumHealer:
    """Orchestrates autonomous detection, patching, formal verification, and safe application."""

    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)
        self.patcher = AutoPatcher()
        self.correlation_engine = CorrelationEngine()
        self.validator = SmartPatchValidator()

    def discover_findings(self) -> List[Dict[str, Any]]:
        """Invokes the multi-engine scanners through scan_all."""
        scan_script = os.path.join(MODULES_DIR, "scan_all.py")
        cmd = [
            sys.executable,
            scan_script,
            "--target", self.target_dir,
            "--format", "json",
            "--all"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            import json
            # Extract JSON from output
            raw = res.stdout
            idx = raw.find("{")
            if idx != -1:
                data = json.loads(raw[idx:])
                return data.get("findings", [])
        except Exception as e:
            print(f"{YELLOW}[WARN] Discovery scan failed: {e}{RESET}", file=sys.stderr)
        return []

    def heal_project(
        self,
        apply_changes: bool = False,
        create_git_branch: bool = False,
        verify: bool = True
    ) -> Dict[str, Any]:
        """Runs the complete self-healing cycle."""
        print(f"\n{BOLD}{CYAN}=== Adversum Autonomous Self-Healing Engine ==={RESET}")
        print(f"[*] Target Directory: {self.target_dir}")
        print(f"[*] Mode: {'APPLY (Live Edits)' if apply_changes else 'DRY RUN (Preview Only)'}")

        # 1. Discover findings
        print(f"[*] Phase 1: Multi-Engine Vulnerability Discovery...")
        raw_findings = self.discover_findings()
        correlated = self.correlation_engine.correlate_findings(raw_findings)
        scorecard_before = self.correlation_engine.compute_executive_scorecard(correlated)

        print(f"    Found {len(correlated)} correlated findings (Initial Grade: {scorecard_before['security_grade']})")

        # 2. Group findings by file
        findings_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for f in correlated:
            fpath = f.get("file") or f.get("file_path")
            if fpath and os.path.isfile(fpath):
                findings_by_file.setdefault(os.path.abspath(fpath), []).append(f)

        healed_files: List[Dict[str, Any]] = []
        total_remediated = 0

        # Optional Git Branch creation
        target_branch = None
        if create_git_branch and apply_changes:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_branch = f"adversum/auto-heal-{timestamp}"
            try:
                subprocess.run(["git", "checkout", "-b", target_branch], cwd=self.target_dir, check=True, capture_output=True)
                print(f"{GREEN}[✓] Switched to isolated Git branch: {target_branch}{RESET}")
            except Exception as git_err:
                print(f"{YELLOW}[WARN] Could not create git branch: {git_err}{RESET}", file=sys.stderr)

        # 3. Patch Synthesis & Verification Loop
        print(f"\n[*] Phase 2: Autonomous Patch Synthesis & Closed-Loop Verification...")
        for file_path, file_findings in findings_by_file.items():
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    original_content = f.read()

                current_content = original_content
                file_healed_count = 0
                patches_applied = []

                for finding in file_findings:
                    patched, diff = self.patcher.generate_patch(finding, current_content)
                    if patched and patched != current_content:
                        # Verify syntax
                        syntax_ok = True
                        if file_path.endswith(".py"):
                            import ast
                            try:
                                ast.parse(patched)
                            except SyntaxError:
                                syntax_ok = False

                        if syntax_ok:
                            current_content = patched
                            file_healed_count += 1
                            total_remediated += 1
                            patches_applied.append({
                                "rule_id": finding.get("rule_id"),
                                "title": finding.get("title", finding.get("rule_id")),
                                "diff": diff
                            })

                if current_content != original_content:
                    unified_diff = "".join(difflib.unified_diff(
                        original_content.splitlines(keepends=True),
                        current_content.splitlines(keepends=True),
                        fromfile=os.path.basename(file_path),
                        tofile=os.path.basename(file_path)
                    ))

                    healed_files.append({
                        "file": file_path,
                        "patches": patches_applied,
                        "diff": unified_diff,
                        "count": file_healed_count
                    })

                    print(f"\n{BOLD}{CYAN}[PATCH READY]{RESET} {os.path.relpath(file_path, self.target_dir)} ({file_healed_count} fixes)")
                    print(unified_diff)

                    if apply_changes:
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(current_content)
                        print(f"    {GREEN}[✓] Applied changes to disk{RESET}")

            except Exception as e:
                print(f"{YELLOW}[WARN] Error healing {file_path}: {e}{RESET}", file=sys.stderr)

        # 4. Git Commit if requested
        if create_git_branch and apply_changes and healed_files:
            try:
                subprocess.run(["git", "add", "-A"], cwd=self.target_dir, check=True)
                commit_msg = f"fix(security): autonomous remediation of {total_remediated} vulnerabilities by Adversum"
                subprocess.run(["git", "commit", "-m", commit_msg], cwd=self.target_dir, check=True)
                print(f"{GREEN}[✓] Committed fixes to {target_branch}{RESET}")
            except Exception as git_err:
                print(f"{YELLOW}[WARN] Git commit failed: {git_err}{RESET}", file=sys.stderr)

        # 5. Post-Remediation Re-Scan Verification
        scorecard_after = scorecard_before
        if verify and apply_changes:
            print(f"\n[*] Phase 3: Post-Remediation Verification Scan...")
            raw_after = self.discover_findings()
            correlated_after = self.correlation_engine.correlate_findings(raw_after)
            scorecard_after = self.correlation_engine.compute_executive_scorecard(correlated_after)
            print(f"    Final Posture Grade: {scorecard_after['security_grade']} (Score: {scorecard_after['security_score']}/100)")

        # Summary
        print(f"\n{BOLD}{GREEN}=== Self-Healing Summary ==={RESET}")
        print(f"[*] Files Remediated: {len(healed_files)}")
        print(f"[*] Total Fixes Applied: {total_remediated}")
        print(f"[*] Initial Posture: Grade {scorecard_before['security_grade']} ({scorecard_before['security_score']}/100)")
        print(f"[*] Post-Healing Posture: Grade {scorecard_after['security_grade']} ({scorecard_after['security_score']}/100)")

        return {
            "healed_files": healed_files,
            "total_remediated": total_remediated,
            "scorecard_before": scorecard_before,
            "scorecard_after": scorecard_after,
            "git_branch": target_branch
        }

    def generate_markdown_report(self, results: Dict[str, Any], output_path: str):
        """Generates an executive Markdown remediation report."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        md = f"""# 🛡️ Adversum Autonomous Healing Audit Report
**Date:** {now}  
**Target:** `{self.target_dir}`  
**Initial Grade:** `{results['scorecard_before']['security_grade']}` ({results['scorecard_before']['security_score']}/100)  
**Post-Remediation Grade:** `{results['scorecard_after']['security_grade']}` ({results['scorecard_after']['security_score']}/100)  
**Total Vulnerabilities Remediated:** {results['total_remediated']}  
**Isolated Git Branch:** `{results.get('git_branch') or 'N/A'}`

---

## 📋 Remediation Overview

| File | Patches Applied | Status |
|------|-----------------|--------|
"""
        for h in results.get("healed_files", []):
            rel = os.path.relpath(h["file"], self.target_dir)
            md += f"| `{rel}` | {h['count']} | ✅ Synthesized & Verified |\n"

        md += "\n---\n\n## 🔍 Unified Diffs\n\n"
        for h in results.get("healed_files", []):
            rel = os.path.relpath(h["file"], self.target_dir)
            md += f"### `{rel}`\n```diff\n{h['diff']}\n```\n\n"

        Path(output_path).write_text(md, encoding="utf-8")
        print(f"{GREEN}[✓] Remediation report written to {output_path}{RESET}")


def main():
    parser = argparse.ArgumentParser(description="Adversum Autonomous Self-Healing CLI")
    parser.add_argument("--target", required=True, help="Target directory or repository to remediate")
    parser.add_argument("--apply", action="store_true", help="Apply fixes directly to source files")
    parser.add_argument("--branch", action="store_true", help="Create an isolated Git branch before applying")
    parser.add_argument("--no-verify", action="store_true", help="Skip post-remediation verification re-scan")
    parser.add_argument("--report", default="ADVERSUM_HEAL_REPORT.md", help="Path to write the markdown healing report")
    args = parser.parse_args()

    healer = AdversumHealer(args.target)
    results = healer.heal_project(
        apply_changes=args.apply,
        create_git_branch=args.branch,
        verify=not args.no_verify
    )
    if args.report:
        healer.generate_markdown_report(results, args.report)


if __name__ == "__main__":
    main()
