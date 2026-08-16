#!/usr/bin/env python3
"""
Adversum Security Modules — Unified Scanner
============================================
Contexte : Audit sécurité CEX/Exchange (AlphaNex Exchange)

Modules disponibles :
  - solidity    : Smart contracts (Solidity/Vyper) — reentrancy, delegatecall, oracle...
  - crypto      : Mauvais usages crypto (ECB, MD5, JWT alg=none, TLS verify=False...)
  - iac         : Infrastructure-as-Code (Dockerfile, K8s, Terraform, docker-compose)

Usage :
  python scan_all.py --target ./contracts/          # Scan Solidity uniquement
  python scan_all.py --target ./backend/ ./infra/   # Scan crypto + IaC
  python scan_all.py --target ./ --all              # Tout scanner
  python scan_all.py --target ./ --format sarif     # Output SARIF 2.1
  python scan_all.py --target ./ --format markdown  # Rapport client
  python scan_all.py --target ./ --format json      # Machine-readable
"""

import argparse
import json
import sys
import os
from pathlib import Path
from datetime import datetime, timezone

# Ajoute les modules au path
MODULES_DIR = Path(__file__).parent
sys.path.insert(0, str(MODULES_DIR))

# ── Couleurs terminal ──────────────────────────────────────────────────────────
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

SEVERITY_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      GREEN,
    "INFO":     DIM,
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def detect_targets(paths: list[str]) -> dict:
    """
    Détecte automatiquement quels modules lancer selon les types de fichiers trouvés.
    Retourne un dict {module: [paths]}.
    """
    targets = {"solidity": [], "crypto": [], "iac": [], "cex_api": []}

    SOLIDITY_EXT  = {".sol", ".vy"}
    CRYPTO_EXT    = {".py", ".js", ".ts", ".java"}
    IAC_PATTERNS  = {"Dockerfile", "docker-compose", ".tf", ".yaml", ".yml", ".env"}

    IGNORE_DIRS = {
        ".git", "node_modules", "venv", ".venv", "dist", "build", "target", 
        "vendor", "third_party", "deps", ".cache", ".next", ".out", "out", 
        "coverage", ".tox", "site-packages", ".idea", ".vscode",
        ".yarn", ".turbo", ".pnpm-store", "locales", "translations", 
        "docs", "website", "bench", "benchmark", "benchmarks", 
        "fixtures", "e2e", "test-results", "artifacts", "public", "assets", "static", "tmp", "temp",
        "__tests__", "__mocks__", "mock", "mocks", "test-fixtures"
    }


    for path_str in paths:
        p = Path(path_str)
        if p.is_file():
            ext = p.suffix.lower()
            name = p.name
            if ext in SOLIDITY_EXT:
                targets["solidity"].append(str(p))
            elif ext in CRYPTO_EXT:
                targets["crypto"].append(str(p))
                targets["cex_api"].append(str(p))
            elif ext in {".tf", ".yaml", ".yml"} or any(pat in name for pat in IAC_PATTERNS):
                targets["iac"].append(str(p))
        elif p.is_dir():
            for root, dirs, files in os.walk(path_str):
                # Prune heavy/third-party/generated directories in-place (avoids walking .git / node_modules)
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.git')]
                
                for filename in files:
                    ext = os.path.splitext(filename)[1].lower()
                    
                    # Skip minified, bundle, sourcemaps, declaration files
                    if (filename.endswith((".d.ts", ".min.js", ".bundle.js", ".map"))
                            or filename.endswith(".lock")):
                        continue

                    full_path = os.path.join(root, filename)
                    try:
                        if os.path.getsize(full_path) > 1_000_000:
                            continue
                    except OSError:
                        continue

                    if ext in SOLIDITY_EXT:
                        targets["solidity"].append(full_path)
                    elif ext in CRYPTO_EXT:
                        targets["crypto"].append(full_path)
                        targets["cex_api"].append(full_path)
                    elif (ext in {".tf", ".yaml", ".yml"}
                          or filename == "Dockerfile"
                          or "docker-compose" in filename
                          or filename == ".env"):
                        targets["iac"].append(full_path)

    return targets


from concurrent.futures import ThreadPoolExecutor

def _scan_files_parallel(scanner, files: list[str]) -> list:
    """Scanne une liste de fichiers en parallèle en utilisant un pool de threads."""
    if not files:
        return []
    max_workers = min(32, (os.cpu_count() or 4) * 4)
    chunksize = max(1, len(files) // (max_workers * 4))
    all_findings = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(scanner.scan_file, files, chunksize=chunksize)
        for res in results:
            if res:
                all_findings.extend(res)
    return all_findings

def run_solidity(target_files: list[str]) -> list[dict]:
    """Lance le scanner Solidity et retourne les findings normalisés."""
    if not target_files:
        return []
    try:
        from solidity.scanner import SolidityScanner  # type: ignore
        import solidity.rules as solidity_rules
        kb_path = os.path.join(MODULES_DIR, "solidity", "kb", "vulnerabilities.json")
        scanner = SolidityScanner(rules_package=solidity_rules, kb_path=kb_path)
        findings = _scan_files_parallel(scanner, target_files)
        return [_normalize(f, "solidity") for f in findings]
    except Exception as e:
        print(f"{YELLOW}[WARN] Solidity module not available: {e}{RESET}", file=sys.stderr)
        return []


def run_crypto(target_files: list[str]) -> list[dict]:
    """Lance le scanner Crypto Misuse et retourne les findings normalisés."""
    if not target_files:
        return []
    try:
        from crypto_misuse.scanner import CryptoMisuseScanner  # type: ignore
        scanner = CryptoMisuseScanner()
        findings = _scan_files_parallel(scanner, target_files)
        return [_normalize(f, "crypto") for f in findings]
    except Exception as e:
        print(f"{YELLOW}[WARN] Crypto module not available: {e}{RESET}", file=sys.stderr)
        return []


def run_iac(target_files: list[str]) -> list[dict]:
    """Lance le scanner IaC et retourne les findings normalisés."""
    if not target_files:
        return []
    try:
        from iac_scan.scanner import IaCScanner  # type: ignore
        scanner = IaCScanner()
        findings = _scan_files_parallel(scanner, target_files)
        return [_normalize(f, "iac") for f in findings]
    except Exception as e:
        print(f"{YELLOW}[WARN] IaC module not available: {e}{RESET}", file=sys.stderr)
        return []


def run_cex_api(target_files: list[str]) -> list[dict]:
    """Lance le scanner CEX Trading API & Matching Engine."""
    if not target_files:
        return []
    try:
        from cex_api.scanner import CEXApiScanner  # type: ignore
        scanner = CEXApiScanner()
        findings = _scan_files_parallel(scanner, target_files)
        return [_normalize(f, "cex_api") for f in findings]
    except Exception as e:
        print(f"{YELLOW}[WARN] CEX API module not available: {e}{RESET}", file=sys.stderr)
        return []


def run_ccss_audit(target_dir: str):
    """Lance l'évaluation de conformité CCSS (CryptoCurrency Security Standard)."""
    try:
        from ccss_audit.checker import CCSSChecker  # type: ignore
        checker = CCSSChecker()
        return checker.audit_target(target_dir)
    except Exception as e:
        print(f"{YELLOW}[WARN] CCSS module not available: {e}{RESET}", file=sys.stderr)
        return None


def run_threat_model(target_dir: str):
    """Lance le générateur de modélisation des menaces CEX STRIDE."""
    try:
        from threat_model.generator import CEXThreatModelGenerator  # type: ignore
        gen = CEXThreatModelGenerator()
        return gen.generate_model(target_dir)
    except Exception as e:
        print(f"{YELLOW}[WARN] Threat Model module not available: {e}{RESET}", file=sys.stderr)
        return None



def _normalize(finding, module: str) -> dict:
    """Normalise un finding quelconque en dict unifié."""
    if isinstance(finding, dict):
        f = finding
    else:
        # Dataclass ou objet avec __dict__
        f = finding.__dict__ if hasattr(finding, "__dict__") else vars(finding)

    return {
        "module":      module,
        "rule_id":     f.get("rule_id", f.get("id", "UNKNOWN")),
        "severity":    f.get("severity", "MEDIUM").upper(),
        "cwe":         f.get("cwe", ""),
        "title":       f.get("title", f.get("message", "")),
        "description": f.get("description", ""),
        "file":        f.get("file", f.get("file_path", "")),
        "line":        f.get("line", 0),
        "snippet":     f.get("snippet", ""),
        "recommendation": f.get("recommendation", f.get("fix", "")),
        "cvss_score":  float(f.get("cvss_score", f.get("cvss", 0.0))),
    }


# == Output formatters ==========================================================

def print_text(findings: list[dict], stats: dict) -> None:
    """Affichage terminal coloré."""
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  ADVERSUM SECURITY SCAN - CEX Audit Report{RESET}")
    print(f"{DIM}  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}{RESET}")
    print(f"{BOLD}{'='*70}{RESET}\n")

    # Stats par sévérité
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = stats.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLOR[sev]
            print(f"  {color}*{RESET} {sev:<10} {count} finding{'s' if count > 1 else ''}")
    print(f"  {'-'*40}")
    print(f"  {'TOTAL':<10} {stats.get('total', 0)} findings\n")

    if not findings:
        print(f"{GREEN}  [OK] No findings. Clean codebase.{RESET}\n")
        return

    # Findings triés par sévérité
    sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    current_module = None

    for f in sorted_findings:
        if f["module"] != current_module:
            current_module = f["module"]
            module_label = {"solidity": "Smart Contracts", "crypto": "Crypto Misuse", "iac": "IaC"}.get(current_module, current_module)
            print(f"\n{CYAN}{BOLD}  > {module_label.upper()}{RESET}")
            print(f"  {'-'*60}")

        color = SEVERITY_COLOR.get(f["severity"], "")
        loc = f"{Path(f['file']).name}:{f['line']}" if f["file"] else "unknown"
        print(f"\n  {color}[{f['severity']}]{RESET} {BOLD}{f['rule_id']}{RESET} - {f['title']}")
        print(f"  {DIM}Location: {loc}{RESET}")
        if f["cwe"]:
            print(f"  {DIM}Tag: {f['cwe']}  |  CVSS {f['cvss_score']:.1f}{RESET}")
        if f["description"]:
            print(f"  {f['description'][:120]}{'...' if len(f['description']) > 120 else ''}")
        if f["recommendation"]:
            print(f"  {GREEN}-> Fix:{RESET} {f['recommendation'][:100]}")

    print(f"\n{BOLD}{'='*70}{RESET}\n")


def to_sarif(findings: list[dict], targets: list[str]) -> dict:
    """Génère un SARIF 2.1.0 consolidé."""
    rules = {}
    results = []
    artifacts = {t: i for i, t in enumerate(set(f["file"] for f in findings if f["file"]))}

    for f in findings:
        rid = f["rule_id"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f["title"],
                "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": f["description"]},
                "properties": {
                    "tags": [f["cwe"]] if f["cwe"] else [],
                    "precision": "high",
                    "problem.severity": "error" if f["severity"] in ("CRITICAL", "HIGH") else "warning",
                    "cwe": [f["cwe"]] if f["cwe"] else [],
                    "module": f["module"],
                },
            }

        level = "error" if f["severity"] in ("CRITICAL", "HIGH") else "warning" if f["severity"] == "MEDIUM" else "note"
        result = {
            "ruleId": rid,
            "level": level,
            "message": {"text": f"{f['title']}: {f['description']}"[:200]},
            "locations": [],
            "properties": {
                "severity":   f["severity"],
                "cvssScore":  f["cvss_score"],
                "cwe":        f["cwe"],
                "module":     f["module"],
            },
        }
        if f["file"]:
            result["locations"].append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f["file"].replace("\\", "/"),
                        "index": artifacts.get(f["file"], 0),
                    },
                    "region": {"startLine": max(1, f["line"])},
                }
            })
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Adversum",
                    "version": "5.0",
                    "informationUri": "https://adversum.io",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "artifacts": [{"location": {"uri": uri.replace("\\", "/"), "index": idx}} for uri, idx in artifacts.items()],
        }],
    }
    return sarif


def to_markdown(findings: list[dict], targets: list[str], stats: dict) -> str:
    """Génère un rapport Markdown professionnel pour le client."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        f"# Security Assessment Report",
        f"",
        f"**Tool**: Adversum v5.0  ",
        f"**Date**: {now}  ",
        f"**Context**: CEX Security Audit  ",
        f"**Targets**: {', '.join(str(Path(t).name) for t in targets[:5])}",
        f"",
        f"---",
        f"",
        f"## Executive Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if stats.get(sev, 0) > 0:
            lines.append(f"| {sev} | {stats[sev]} |")
    lines += [
        f"| **TOTAL** | **{stats.get('total', 0)}** |",
        f"",
        f"---",
        f"",
        f"## Findings",
        f"",
    ]

    by_module = {}
    for f in findings:
        by_module.setdefault(f["module"], []).append(f)

    module_labels = {"solidity": "Smart Contracts", "crypto": "Cryptographic Misuse", "iac": "Infrastructure-as-Code"}
    for module, mfindings in by_module.items():
        label = module_labels.get(module, module.upper())
        lines += [f"### {label}", f""]
        for f in sorted(mfindings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)):
            loc = f"{Path(f['file']).name}:{f['line']}" if f["file"] else "N/A"
            lines += [
                f"#### `{f['rule_id']}` — {f['title']}",
                f"",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **Severity** | {f['severity']} |",
                f"| **CWE** | {f['cwe'] or 'N/A'} |",
                f"| **CVSS Score** | {f['cvss_score']:.1f} |",
                f"| **Location** | `{loc}` |",
                f"",
                f"{f['description']}",
                f"",
            ]
            if f["recommendation"]:
                lines += [f"**Recommendation**: {f['recommendation']}", f""]
            if f["snippet"]:
                lines += [f"```", f"{f['snippet'][:300]}", f"```", f""]
            lines.append("---")
            lines.append("")
    return "\n".join(lines)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        description="Adversum Unified Security Scanner — CEX Audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--target", nargs="+", required=True, metavar="PATH",
                        help="Files or directories to scan")
    parser.add_argument("--format", choices=["text", "sarif", "markdown", "json", "cex_report"],
                        default="text", help="Output format (default: text)")
    parser.add_argument("--output", metavar="FILE",
                        help="Write output to file (default: stdout)")
    parser.add_argument("--modules", nargs="+",
                        choices=["solidity", "crypto", "iac", "cex_api"],
                        help="Force specific modules (default: auto-detect)")
    parser.add_argument("--cex-audit", action="store_true", help="Run comprehensive institutional CEX audit suite (CCSS, API, SMT, Threat Model)")
    parser.add_argument("--all", action="store_true",
                        help="Run all modules regardless of file types")
    parser.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        default="INFO", help="Minimum severity to report")
    parser.add_argument("--fix", action="store_true",
                        help="Automatically apply fixes to vulnerable files")
    parser.add_argument("--diff", action="store_true",
                        help="Show recommended diffs for vulnerable files")
    parser.add_argument("--poc", metavar="DIR",
                        help="Generate executable Foundry Exploit PoC tests (.t.sol) into DIR for all CRITICAL/HIGH findings")
    args = parser.parse_args()

    # Détection des cibles
    targets_map = detect_targets(args.target)

    # Lancement des scanners
    all_findings: list[dict] = []
    active_modules = args.modules or [k for k, v in targets_map.items() if v]


    if "solidity" in active_modules and targets_map.get("solidity"):
        print(f"{CYAN}[*] Running Solidity scanner...{RESET}", file=sys.stderr)
        all_findings.extend(run_solidity(targets_map["solidity"]))

    if "crypto" in active_modules and targets_map.get("crypto"):
        print(f"{CYAN}[*] Running Crypto Misuse scanner...{RESET}", file=sys.stderr)
        all_findings.extend(run_crypto(targets_map["crypto"]))

    if "iac" in active_modules and targets_map.get("iac"):
        print(f"{CYAN}[*] Running IaC scanner...{RESET}", file=sys.stderr)
        all_findings.extend(run_iac(targets_map["iac"]))

    if ("cex_api" in active_modules or args.cex_audit) and targets_map.get("cex_api"):
        print(f"{CYAN}[*] Running CEX API & Order Book scanner...{RESET}", file=sys.stderr)
        all_findings.extend(run_cex_api(targets_map["cex_api"]))

    # CCSS & Threat Modeling for CEX
    ccss_report = None
    threat_report = None
    target_root = args.target[0] if args.target else "."

    if args.cex_audit or args.format == "cex_report":
        print(f"{CYAN}[*] Running CCSS v3.0 Compliance Audit...{RESET}", file=sys.stderr)
        ccss_report = run_ccss_audit(target_root)
        print(f"{CYAN}[*] Generating CEX STRIDE Threat Model...{RESET}", file=sys.stderr)
        threat_report = run_threat_model(target_root)

    # Filtrer par sévérité minimum
    sev_filter = SEVERITY_ORDER.get(args.min_severity, 4)
    all_findings = [f for f in all_findings if SEVERITY_ORDER.get(f["severity"], 4) <= sev_filter]

    # Statistiques
    stats: dict[str, int] = {"total": len(all_findings)}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        stats[sev] = sum(1 for f in all_findings if f["severity"] == sev)

    # Foundry PoC Generation
    if args.poc:
        print(f"{CYAN}[*] Generating Foundry Exploit PoC files...{RESET}", file=sys.stderr)
        try:
            from poc_generator.generator import FoundryPoCGenerator
            poc_gen = FoundryPoCGenerator()
            generated = poc_gen.export_pocs_for_findings(all_findings, output_dir=args.poc)
            if generated:
                print(f"{GREEN}[+] Generated {len(generated)} PoC test file(s) in '{args.poc}':{RESET}", file=sys.stderr)
                for gf in generated:
                    fname = Path(gf).name
                    print(f"    {GREEN}✓{RESET} {fname}  {DIM}→ forge test --match-contract {Path(fname).stem}Test -vvvv{RESET}", file=sys.stderr)
            else:
                print(f"{YELLOW}[!] No exploitable findings matched a PoC template.{RESET}", file=sys.stderr)
        except Exception as e:
            print(f"{YELLOW}[WARN] PoC generation failed: {e}{RESET}", file=sys.stderr)

    # Remediation (Auto-Fix & Diff)
    if args.fix or args.diff:
        try:
            sys.path.insert(0, str(MODULES_DIR))
            from remediation.patcher import AutoPatcher
            patcher = AutoPatcher()
            
            findings_by_file = {}
            for f in all_findings:
                filepath = f.get("file")
                if filepath and os.path.isfile(filepath):
                    findings_by_file.setdefault(filepath, []).append(f)
                    
            for filepath, file_findings in findings_by_file.items():
                try:
                    with open(filepath, "r", encoding="utf-8") as file_obj:
                        content = file_obj.read()
                        
                    patched_content = content
                    for finding in file_findings:
                        patched_content, _ = patcher.generate_patch(finding, patched_content)
                        
                    if patched_content != content:
                        diff = patcher._generate_unified_diff(content, patched_content, filepath)
                        if args.diff:
                            print(f"\n{CYAN}{BOLD}[DIFF]{RESET} {filepath}")
                            print(diff)
                        if args.fix:
                            with open(filepath, "w", encoding="utf-8") as file_obj:
                                file_obj.write(patched_content)
                            print(f"{GREEN}[FIX] Applied fixes to {filepath}{RESET}")
                except Exception as ex:
                    print(f"{YELLOW}[WARN] Failed to remediate {filepath}: {ex}{RESET}", file=sys.stderr)
        except ImportError as e:
            print(f"{YELLOW}[WARN] Remediation module not available: {e}{RESET}", file=sys.stderr)

    # Génération de l'output
    output_text: str = ""
    if args.format == "text":
        print_text(all_findings, stats)
        return
    elif args.format == "sarif":
        output_text = json.dumps(to_sarif(all_findings, args.target), indent=2)
    elif args.format == "markdown":
        output_text = to_markdown(all_findings, args.target, stats)
    elif args.format == "cex_report":
        if not ccss_report:
            ccss_report = run_ccss_audit(target_root)
        if not threat_report:
            threat_report = run_threat_model(target_root)
        from cex_report.generator import CEXReportGenerator
        gen = CEXReportGenerator()
        output_text = gen.generate_markdown("AlphaNex Exchange", target_root, all_findings, ccss_report, threat_report)
    elif args.format == "json":
        from dataclasses import asdict, is_dataclass
        ccss_dict = asdict(ccss_report) if (ccss_report and is_dataclass(ccss_report)) else None
        threat_dict = asdict(threat_report) if (threat_report and is_dataclass(threat_report)) else None

        output_text = json.dumps({
            "version": "5.0",
            "tool": "adversum",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stats": stats,
            "ccss_compliance": ccss_dict,
            "threat_model": threat_dict,
            "findings": all_findings,
        }, indent=2)

    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"{GREEN}[✓] Report written to {args.output}{RESET}", file=sys.stderr)
    else:
        print(output_text)

    # Exit code non-nul si des findings critiques/high
    if stats.get("CRITICAL", 0) + stats.get("HIGH", 0) > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
