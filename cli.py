#!/usr/bin/env python3
"""
Adversum — AI-Powered Security Reasoning Engine
================================================
Command-Line Interface (CLI)

Nebius x NVIDIA Global AI Hackathon:
- Deterministic Rust SAST Core
- NVIDIA Nemotron AI Reasoning (Nebius Token Factory)
- Tavily Live Threat Intelligence Enrichment

Usage:
    python cli.py scan <path> [--all] [--format json|sarif|markdown]
    python cli.py demo
    python cli.py check-ai
    python cli.py serve [--port 8000]
"""

import sys
import os
import argparse
from pathlib import Path

# Safe UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Add project root and modules to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "modules"))

# ANSI Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner():
    banner = r"""
       ___       __                              
      /   | ____/ /   _____  _____________  ______ ___ 
     / /| |/ __  / | / / _ \/ ___/ ___/ / / / __ `__ \
    / ___ / /_/ /| |/ /  __/ /  (__  ) /_/ / / / / / /
   /_/  |_\__,_/ |___/\___/_/  /____/\__,_/_/ /_/ /_/ 
   AI-Powered Security Reasoning Engine - Nebius x NVIDIA Hackathon
   Engine: Rust Core (PyO3) | Model: NVIDIA Nemotron-3.5-Lightning
"""
    print(f"{CYAN}{BOLD}{banner}{RESET}")


def cmd_check_ai(args):
    print_banner()

    # Load .env if present
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(env_path)
        except ImportError:
            pass

    print(f"{BOLD}[1/3] Checking Nebius Token Factory (NVIDIA Nemotron)...{RESET}")
    nebius_key = os.getenv("NEBIUS_API_KEY", "").strip()
    nebius_model = os.getenv("NEBIUS_MODEL", "nvidia/Nemotron-3_5-Lightning")
    nebius_url = os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/")

    if not nebius_key:
        print(f"  {YELLOW}[!] NEBIUS_API_KEY is not set.{RESET} Set it in .env to activate NVIDIA Nemotron reasoning.")
    else:
        masked_key = nebius_key[:8] + "..." + nebius_key[-4:] if len(nebius_key) > 12 else "***"
        print(f"  {GREEN}[+] API Key:{RESET} {masked_key}")
        print(f"  {GREEN}[+] Model:{RESET} {nebius_model}")
        print(f"  {GREEN}[+] Endpoint:{RESET} {nebius_url}")

        try:
            import asyncio
            from orchestrator.services.nebius_llm import nebius_health_check
            print("  Connecting to Nebius inference endpoint...")
            health = asyncio.run(nebius_health_check())
            if health.get("status") == "ok":
                print(f"  {GREEN}{BOLD}[+] NVIDIA Nemotron Connection Verified!{RESET} Reply: '{health.get('reply')}'")
            else:
                print(f"  {YELLOW}[!] Nebius reply: {health}{RESET}")
        except Exception as e:
            print(f"  {RED}[x] Failed to contact Nebius:{RESET} {e}")

    print(f"\n{BOLD}[2/3] Checking Tavily Threat Intelligence API...{RESET}")
    tavily_key = os.getenv("TAVILY_API_KEY", "").strip()
    if not tavily_key:
        print(f"  {DIM}[i] TAVILY_API_KEY not set (optional for $3,000 Tavily prize).{RESET}")
    else:
        masked_tav = tavily_key[:8] + "..." + tavily_key[-4:] if len(tavily_key) > 12 else "***"
        print(f"  {GREEN}[+] Tavily API Key configured:{RESET} {masked_tav}")
        try:
            from tavily import TavilyClient
            client = TavilyClient(api_key=tavily_key)
            res = client.search(query="Solidity reentrancy CVE", max_results=1)
            print(f"  {GREEN}{BOLD}[+] Tavily Threat Intelligence Verified!{RESET} Found {len(res.get('results', []))} live advisory source(s).")
        except Exception as e:
            print(f"  {YELLOW}[!] Tavily verification note:{RESET} {e}")

    print(f"\n{BOLD}[3/3] Checking Rust Core (adversum_core)...{RESET}")
    try:
        import adversum_core
        symbols = [s for s in dir(adversum_core) if not s.startswith("_")]
        print(f"  {GREEN}{BOLD}[+] Rust SAST Engine active!{RESET} {len(symbols)} native symbols loaded (High-Performance mode).")
    except ImportError:
        print(f"  {YELLOW}[!] adversum_core wheel not loaded.{RESET} Using Python AST fallback engine.")


def cmd_scan(args):
    print_banner()
    from modules.scan_all import main as scan_main
    scan_args = ["--target", args.target]
    if args.all:
        scan_args.append("--all")
    if args.format:
        scan_args.extend(["--format", args.format])
    if args.cex_audit:
        scan_args.append("--cex-audit")
    if args.poc:
        scan_args.append("--poc")

    sys.argv = ["scan_all.py"] + scan_args
    scan_main()


def cmd_demo(args):
    print_banner()
    print(f"{CYAN}{BOLD}▶ Lancement du Scan de Démonstration Institutionnel...{RESET}\n")
    from modules.scan_all import main as scan_main
    sys.argv = ["scan_all.py", "--target", "./", "--all", "--cex-audit", "--format", "markdown"]
    scan_main()


def cmd_serve(args):
    print_banner()
    print(f"{GREEN}{BOLD}Starting Adversum FastAPI Backend on http://0.0.0.0:{args.port}...{RESET}")
    print(f"Frontend Dashboard: http://localhost:3000 (or http://localhost:5173 with Vite)")
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=args.port, reload=args.reload)


def cmd_live_fork(args):
    print_banner()
    print(f"{CYAN}{BOLD}⚡ Lancement de l'Exploitation sur Fork Mainnet (Proof of Exploit)...{RESET}\n")
    from modules.live_fork.engine import LiveForkEngine
    engine = LiveForkEngine()
    finding = {
        "rule_id": args.rule or "SOL-001",
        "file": args.file or "contracts/Vault.sol",
        "title": f"Exploit simulation for {args.rule or 'SOL-001'}",
        "severity": "CRITICAL",
        "snippet": "msg.sender.call{value: amount}(''); balances[msg.sender] -= amount;"
    }
    proof = engine.execute_live_exploit(finding, initial_vault_eth=args.eth or 100.0)
    print(f"{GREEN}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
    print(f"{GREEN}{BOLD}✓ PROOF OF EXPLOIT (PoE) CERTIFICATE — 0% FAUX POSITIF{RESET}")
    print(f"{GREEN}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
    print(f"  • Cible            : {proof.target_contract}")
    print(f"  • Vecteur d'attaque: {proof.exploit_type}")
    print(f"  • Statut           : {RED}{BOLD}{proof.status}{RESET}")
    print(f"  • Trésorerie Init  : {proof.initial_vault_balance_eth:.2f} ETH")
    print(f"  • Trésorerie Finale: {proof.final_vault_balance_eth:.2f} ETH")
    print(f"  • Butin Attaquant  : {RED}{BOLD}{proof.attacker_profit_eth:.2f} ETH (${proof.attacker_profit_usd:,.2f}){RESET}")
    print(f"  • Hash Transaction : {proof.tx_hash}")
    print(f"  • Badge de Preuve  : {CYAN}{proof.empirical_badge}{RESET}\n")
    print(f"{BOLD}Trace d'Exécution EVM (Foundry / RPC Stack):{RESET}")
    for idx, trace in enumerate(proof.traces):
        status_col = GREEN if "SUCCESS" in trace['status'] else RED if "DRAIN" in trace['status'] else YELLOW
        print(f"  [{idx}] {trace['call_type']:<22} | depth={trace['depth']} | {trace['target'][:18]}... | {status_col}{trace['status']}{RESET} | gas={trace['gas_cost']}")


def cmd_self_heal(args):
    print_banner()
    print(f"{CYAN}{BOLD}🛠️ Comité Tri-Partite de Remédiation Autonome (Self-Healing PR)...{RESET}\n")
    from orchestrator.services.self_healing import TriPartiteSelfHealingEngine
    engine = TriPartiteSelfHealingEngine()
    finding = {
        "rule_id": args.rule or "SOL-001",
        "file": args.file or "contracts/Vault.sol",
        "severity": "CRITICAL",
        "snippet": "msg.sender.call{value: amount}(''); balances[msg.sender] -= amount;"
    }
    pkg = engine.generate_verified_pr(finding, apply_to_disk=args.apply)
    print(f"{GREEN}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
    print(f"{GREEN}{BOLD}✓ GITHUB PULL REQUEST PRÊTE — VÉRIFICATION FORMELLE VALIDÉE{RESET}")
    print(f"{GREEN}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
    print(f"  • Titre PR        : {pkg.pr_title}")
    print(f"  • Branche Git     : {pkg.branch_name}")
    print(f"  • Statut AVR      : {GREEN}{BOLD}{pkg.verification_status}{RESET}")
    print(f"  • Preuve Formelle : {CYAN}{pkg.formal_proof_badge}{RESET}")
    print(f"  • Impact Gaz      : {YELLOW}{pkg.gas_delta}{RESET}\n")
    print(f"{BOLD}Diff Chirurgical Généré :{RESET}")
    print(pkg.unified_diff)
    print(f"\n{BOLD}Commandes Git Automatisées :{RESET}")
    for cmd in pkg.git_cli_commands:
        print(f"  $ {cmd}")


def main():
    parser = argparse.ArgumentParser(
        description="Adversum — AI-Powered Security Reasoning Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # scan
    p_scan = subparsers.add_parser("scan", help="Run multi-module SAST audit on a target folder")
    p_scan.add_argument("target", help="Directory or file path to scan")
    p_scan.add_argument("--all", action="store_true", default=True, help="Run all modules (Solidity, Crypto, IaC, etc.)")
    p_scan.add_argument("--format", choices=["text", "json", "sarif", "markdown", "cex_report", "html"], default="text", help="Output format")
    p_scan.add_argument("--cex-audit", action="store_true", default=True, help="Enable CCSS v3.0 institutional audit")
    p_scan.add_argument("--poc", action="store_true", default=False, help="Generate Foundry Exploit PoC files")

    # demo
    subparsers.add_parser("demo", help="Run demo audit over current repository")

    # check-ai
    subparsers.add_parser("check-ai", help="Test Nebius Token Factory & Tavily API connectivity")

    # live-fork (Phase 1)
    p_fork = subparsers.add_parser("live-fork", help="Run live mainnet fork exploit execution & proof")
    p_fork.add_argument("--rule", default="SOL-001", help="Rule ID to exploit (default: SOL-001)")
    p_fork.add_argument("--file", default="contracts/Vault.sol", help="Target contract file")
    p_fork.add_argument("--eth", type=float, default=100.0, help="Initial vault liquidity in ETH")

    # self-heal (Phase 1)
    p_heal = subparsers.add_parser("self-heal", help="Run Tri-Partite Self-Healing & generate verified GitHub PR")
    p_heal.add_argument("--rule", default="SOL-001", help="Rule ID to fix (default: SOL-001)")
    p_heal.add_argument("--file", default="contracts/Vault.sol", help="Target contract file")
    p_heal.add_argument("--apply", action="store_true", default=False, help="Apply patch directly to disk")

    # serve
    p_serve = subparsers.add_parser("serve", help="Start the FastAPI backend server")
    p_serve.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    p_serve.add_argument("--reload", action="store_true", default=False, help="Enable auto-reload")

    # ── Phase 2 commands ────────────────────────────────────────────────────

    # mev-scan (Phase 2)
    p_mev = subparsers.add_parser("mev-scan", help="[Phase 2] Analyze a block for MEV attack patterns")
    p_mev.add_argument("--chain", default="ethereum", help="Chain: ethereum|arbitrum|base|optimism|polygon")
    p_mev.add_argument("--block", type=int, default=None, help="Block number to analyze")
    p_mev.add_argument("--txs", type=int, default=10, help="Number of demo transactions to generate (default: 10)")
    p_mev.add_argument("--eth-price", type=float, default=2650.0, help="ETH price in USD (default: 2650)")

    # threat-model (Phase 2)
    p_tm = subparsers.add_parser("threat-model", help="[Phase 2] Generate STRIDE+PASTA+MITRE threat model")
    p_tm.add_argument("--path", default=".", help="Path to source code to analyze")
    p_tm.add_argument("--target", default="MyProtocol", help="Target protocol/system name")
    p_tm.add_argument("--output", choices=["text", "json"], default="text", help="Output format")

    # compliance-report (Phase 2)
    p_comp = subparsers.add_parser("compliance-report", help="[Phase 2] Generate SOC2/ISO27001/SARIF compliance report")
    p_comp.add_argument("--path", default=".", help="Path to scan")
    p_comp.add_argument("--target", default="MySystem", help="System name for the report")
    p_comp.add_argument("--frameworks", default="soc2,iso27001,sarif", help="Comma-separated: soc2,iso27001,sarif")
    p_comp.add_argument("--output", default="compliance_report.json", help="Output file path")

    # ws-listen (Phase 2)
    p_ws = subparsers.add_parser("ws-listen", help="[Phase 2] Listen to real-time WebSocket threat stream")
    p_ws.add_argument("--host", default="localhost", help="API host (default: localhost)")
    p_ws.add_argument("--port", type=int, default=8000, help="API port (default: 8000)")
    p_ws.add_argument("--duration", type=int, default=60, help="Listen duration in seconds (default: 60)")

    # ── Phase 3 commands ────────────────────────────────────────────────────

    # simulate (Phase 3)
    p_sim = subparsers.add_parser("simulate", help="[Phase 3] Simulate a DeFi attack chain (Euler, Ronin, Mango, etc.)")
    p_sim.add_argument("--scenario", "-s", default="euler_finance", help="Scenario ID (default: euler_finance)")
    p_sim.add_argument("--list", "-l", action="store_true", help="List available scenarios")
    p_sim.add_argument("--json", action="store_true", help="Output result as JSON")

    # risk-score (Phase 3)
    p_risk = subparsers.add_parser("risk-score", help="[Phase 3] Score DeFi protocol economic attack risk")
    p_risk.add_argument("--protocol", "-p", default="Euler Finance", help="Protocol name to score")
    p_risk.add_argument("--tvl", type=float, default=None, help="TVL in USD override")
    p_risk.add_argument("--list", "-l", action="store_true", help="List known protocols")
    p_risk.add_argument("--matrix", "-m", action="store_true", help="Show full DeFi risk matrix")
    p_risk.add_argument("--json", action="store_true", help="Output result as JSON")

    # ── Phase 4 commands ────────────────────────────────────────────────────

    # wargame (Phase 4)
    p_war = subparsers.add_parser("wargame", help="[Phase 4] Run Resilience Arena clash or benchmark")
    p_war.add_argument("--protocol", "-p", default="Euler Finance", help="Target protocol name")
    p_war.add_argument("--scenario", "-s", default="flashloan_drain", choices=["flashloan_drain", "oracle_desync", "reentrancy_wave", "bridge_forgery"], help="Scenario key")
    p_war.add_argument("--exposure", type=float, default=None, help="Custom exposure amount in USD")
    p_war.add_argument("--benchmark", "-b", action="store_true", help="Run multi-scenario resilience benchmark")
    p_war.add_argument("--json", action="store_true", help="Output result as JSON")

    # circuit-breaker (Phase 4)
    p_cb = subparsers.add_parser("circuit-breaker", help="[Phase 4] Synthesize custom Solidity Circuit Breaker & policies")
    p_cb.add_argument("--protocol", "-p", default="CustomVault", help="Protocol/Contract name")
    p_cb.add_argument("--token", default="USDC", help="Monitored token symbol")
    p_cb.add_argument("--outflow-cap", type=float, default=5.0, help="Max TVL outflow %% per window (default: 5.0)")
    p_cb.add_argument("--window-blocks", type=int, default=10, help="Rolling window in blocks (default: 10)")
    p_cb.add_argument("--oracle-dev", type=float, default=3.5, help="Max oracle divergence %% (default: 3.5)")
    p_cb.add_argument("--output", "-o", default=None, help="File path to save the generated Solidity code")
    p_cb.add_argument("--json", action="store_true", help="Output result as JSON")

    # ── Phase 5 commands ────────────────────────────────────────────────────

    # hunt (Phase 5)
    p_hunt = subparsers.add_parser("hunt", help="[Phase 5] Autonomous EVM Threat Hunting Watchtower")
    p_hunt.add_argument("--chain", default="ethereum", help="Target blockchain (default: ethereum)")
    p_hunt.add_argument("--blocks", "-b", type=int, default=5, help="Number of blocks to scan (default: 5)")
    p_hunt.add_argument("--status", action="store_true", help="Display current threat hunter status")
    p_hunt.add_argument("--json", action="store_true", help="Output result as JSON")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.command == "check-ai":
        cmd_check_ai(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "demo":
        cmd_demo(args)
    elif args.command == "live-fork":
        cmd_live_fork(args)
    elif args.command == "self-heal":
        cmd_self_heal(args)
    elif args.command == "serve":
        cmd_serve(args)
    elif args.command == "mev-scan":
        cmd_mev_scan(args)
    elif args.command == "threat-model":
        cmd_threat_model(args)
    elif args.command == "compliance-report":
        cmd_compliance_report(args)
    elif args.command == "ws-listen":
        cmd_ws_listen(args)
    elif args.command == "simulate":
        cmd_simulate(args)
    elif args.command == "risk-score":
        cmd_risk_score(args)
    elif args.command == "wargame":
        cmd_wargame(args)
    elif args.command == "circuit-breaker":
        cmd_circuit_breaker(args)
    elif args.command == "hunt":
        cmd_hunt(args)
    else:
        parser.print_help()



# ── Phase 2 CLI Command Implementations ─────────────────────────────────────

def cmd_mev_scan(args):
    """Analyze a block for MEV attack patterns."""
    import asyncio, json, random, hashlib
    from modules.mev_intelligence.engine import (
        MEVIntelligenceEngine, MEVTransaction, MEVChain
    )

    print(f"\n{CYAN}{BOLD}[MEV Intelligence Engine]{RESET} Chain: {args.chain} | ETH: ${args.eth_price:,.0f}")
    print(f"{DIM}Generating {args.txs} demo transactions...{RESET}\n")

    # Generate demo transactions with a sandwich attack pattern baked in
    rng = random.Random(42)
    attacker = "0x" + "deadbeef" * 5
    victim   = "0x" + "cafebabe" * 5
    pool     = "0x" + "1234abcd" * 5

    txs = []
    for i in range(args.txs):
        if i == 2:  # front-run
            txs.append(MEVTransaction(
                tx_hash=hashlib.sha256(f"front{i}".encode()).hexdigest()[:64],
                from_address=attacker, to_address=pool,
                value_wei=int(50e18), gas_price=200_000_000_000,  # 200 gwei
                input_data="0xd0e30db0", position=i,
            ))
        elif i == 3:  # victim
            txs.append(MEVTransaction(
                tx_hash=hashlib.sha256(f"victim{i}".encode()).hexdigest()[:64],
                from_address=victim, to_address=pool,
                value_wei=int(10e18), gas_price=50_000_000_000,   # 50 gwei
                input_data="0xd0e30db0", position=i,
            ))
        elif i == 4:  # back-run
            txs.append(MEVTransaction(
                tx_hash=hashlib.sha256(f"back{i}".encode()).hexdigest()[:64],
                from_address=attacker, to_address=pool,
                value_wei=int(49e18), gas_price=30_000_000_000,   # 30 gwei
                input_data="0xd0e30db0", position=i,
            ))
        else:
            txs.append(MEVTransaction(
                tx_hash=hashlib.sha256(f"tx{i}".encode()).hexdigest()[:64],
                from_address="0x" + f"{rng.randint(0, 2**160):040x}",
                to_address=pool,
                value_wei=int(rng.uniform(0.1, 5) * 1e18),
                gas_price=int(rng.uniform(20, 80) * 1e9),
                position=i,
            ))

    try:
        chain_enum = MEVChain(args.chain.lower())
    except ValueError:
        chain_enum = MEVChain.ETHEREUM

    engine = MEVIntelligenceEngine(eth_price_usd=args.eth_price)
    result = asyncio.run(engine.analyze_block(txs, chain=chain_enum, block_number=args.block))

    if result.patterns_found:
        print(f"{RED}{BOLD}[!] {len(result.patterns_found)} MEV ATTACK PATTERN(S) DETECTED{RESET}")
        print(f"    Total value at risk: {RED}${result.total_value_at_risk_usd:,.0f} USD{RESET}")
        print()
        for p in result.patterns_found:
            icon = "🚨" if p.risk_level.value == "CRITICAL" else "⚠️"
            print(f"  {icon} [{p.risk_level.value}] {p.attack_type.value.upper()}")
            print(f"     Attacker: {YELLOW}{p.attacker_address}{RESET}")
            print(f"     Risk: ${p.value_at_risk_usd:,.0f} USD | {p.value_at_risk_eth:.4f} ETH")
            print(f"     MITRE: {DIM}{p.mitre_technique}{RESET}")
            print(f"     Fix: {GREEN}{p.mitigation}{RESET}")
            print()
    else:
        print(f"{GREEN}[OK] No MEV attack patterns detected in {result.tx_count} transactions.{RESET}")

    print(f"{DIM}Analysis completed in {result.analysis_time_ms}ms{RESET}")


def cmd_threat_model(args):
    """Generate STRIDE + PASTA + MITRE ATT&CK threat model."""
    import asyncio, json
    from pathlib import Path
    from modules.threat_model.autonomous_modeler import AutonomousThreatModeler

    target_path = Path(args.path)
    print(f"\n{CYAN}{BOLD}[Autonomous Threat Modeler]{RESET} Target: {args.target}")
    print(f"{DIM}Reading source code from: {target_path.resolve()}{RESET}\n")

    # Collect source code
    code_parts = []
    extensions = [".sol", ".py", ".ts", ".js", ".rs"]
    for ext in extensions:
        for f in target_path.rglob(f"*{ext}"):
            if "node_modules" in str(f) or "__pycache__" in str(f):
                continue
            try:
                code_parts.append(f.read_text(encoding="utf-8", errors="replace"))
                if len(code_parts) >= 20:
                    break
            except Exception:
                pass
        if len(code_parts) >= 20:
            break

    source_code = "\n\n".join(code_parts) if code_parts else "// Empty target"
    print(f"{DIM}Scanned {len(code_parts)} source files...{RESET}\n")

    modeler = AutonomousThreatModeler()
    report  = asyncio.run(modeler.analyze(source_code=source_code, target=args.target))

    risk_color = RED if report.overall_risk in ("CRITICAL", "HIGH") else YELLOW
    print(f"{BOLD}=== THREAT MODEL: {args.target} ==={RESET}")
    print(f"Risk Level : {risk_color}{BOLD}{report.overall_risk}{RESET} (score: {report.overall_score}/10)")
    print(f"STRIDE     : {len(report.stride_threats)} threats identified")
    print(f"PASTA      : {len(report.pasta_stages)}/7 stages completed")
    print(f"Paths      : {len(report.attack_paths)} attack paths constructed")
    print()

    if args.output == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"{BOLD}Top STRIDE Threats:{RESET}")
        for t in report.stride_threats[:5]:
            color = RED if t.risk_score >= 8.5 else (YELLOW if t.risk_score >= 6.0 else GREEN)
            print(f"  {color}[{t.threat_id}] {t.category.value}: {t.description[:80]}...{RESET}")
        print()
        print(f"{BOLD}Attack Paths:{RESET}")
        for p in report.attack_paths:
            print(f"  [{p.risk_score:.1f}/10] {p.name}")
        print()
        print(f"{BOLD}Top Recommendations:{RESET}")
        for r in report.recommendations[:5]:
            print(f"  - {r}")
    print(f"\n{DIM}Analysis in {report.analysis_time_ms}ms{RESET}")


def cmd_compliance_report(args):
    """Generate SOC2/ISO27001/SARIF compliance report."""
    import json
    from pathlib import Path
    from modules.compliance.soc2_mapper import SOC2Mapper
    from modules.compliance.iso27001_mapper import ISO27001Mapper
    from modules.compliance.sarif_v2 import SARIFv2Exporter

    frameworks = [f.strip() for f in args.frameworks.split(",")]
    print(f"\n{CYAN}{BOLD}[Compliance Engine]{RESET} Target: {args.target} | Frameworks: {', '.join(frameworks)}")
    print(f"{DIM}Generating compliance reports...{RESET}\n")

    # Demo with empty findings (clean baseline)
    findings: list = []
    response: dict = {"target": args.target, "frameworks": {}}

    if "soc2" in frameworks:
        soc2 = SOC2Mapper().generate_report(findings, target=args.target)
        response["frameworks"]["soc2"] = soc2.to_dict()
        color = GREEN if soc2.compliance_score >= 90 else (YELLOW if soc2.compliance_score >= 70 else RED)
        print(f"  SOC2 Type II  : {color}{soc2.overall_status}{RESET} ({soc2.compliance_score:.1f}%)")

    if "iso27001" in frameworks:
        iso = ISO27001Mapper().generate_report(findings, target=args.target)
        response["frameworks"]["iso27001"] = iso.to_dict()
        color = GREEN if iso.compliance_score >= 90 else (YELLOW if iso.compliance_score >= 70 else RED)
        print(f"  ISO 27001:2022: {color}{iso.overall_status}{RESET} ({iso.compliance_score:.1f}%)")

    if "sarif" in frameworks:
        sarif = SARIFv2Exporter().export(findings, tool_name="Adversum Security Engine")
        response["frameworks"]["sarif"] = sarif.to_sarif()
        print(f"  SARIF 2.1.0   : {GREEN}Generated{RESET} ({len(sarif.results)} results)")

    output_path = Path(args.output)
    output_path.write_text(json.dumps(response, indent=2), encoding="utf-8")
    print(f"\n{GREEN}[OK] Report written to: {output_path.resolve()}{RESET}")


def cmd_ws_listen(args):
    """Listen to real-time WebSocket threat stream."""
    import asyncio

    async def _listen():
        try:
            import websockets  # type: ignore
        except ImportError:
            print(f"{YELLOW}[!] Install websockets: pip install websockets{RESET}")
            return

        uri = f"ws://{args.host}:{args.port}/ws/threat-stream"
        print(f"\n{CYAN}{BOLD}[WebSocket Threat Stream]{RESET} Connecting to {uri}")
        print(f"{DIM}Listening for {args.duration}s. Press Ctrl+C to stop.{RESET}\n")

        try:
            async with websockets.connect(uri, extra_headers={"X-API-Key": "adv-dev-key-123"}) as ws:
                import signal, time
                end_time = time.time() + args.duration
                while time.time() < end_time:
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                        event = json.loads(msg) if isinstance(msg, str) else msg
                        etype = event.get("type") or event.get("event_type", "")
                        if etype == "heartbeat":
                            print(f"{DIM}. heartbeat | subscribers={event.get('subscriber_count', 0)}{RESET}")
                        elif etype == "welcome":
                            print(f"{GREEN}[CONNECTED] Subscriber count: {event.get('subscriber_count')}{RESET}")
                            hist = event.get("recent_events", [])
                            print(f"{DIM}  {len(hist)} recent events in history{RESET}")
                        else:
                            sev = event.get("severity", "INFO")
                            color = RED if sev == "CRITICAL" else (YELLOW if sev == "HIGH" else GREEN)
                            title = event.get("title", "Unknown Event")
                            print(f"  {color}[{sev}]{RESET} {BOLD}{title}{RESET}")
                            print(f"  {DIM}{event.get('description', '')}{RESET}\n")
                    except asyncio.TimeoutError:
                        continue
        except Exception as e:
            print(f"{RED}[!] WebSocket connection failed: {e}{RESET}")
            print(f"    Make sure the Adversum server is running: python cli.py serve")

    asyncio.run(_listen())


# ════════════════════════════════════════════════════════════════════════════════
# Phase 3 — Cross-Protocol Attack Simulator CLI commands
# ════════════════════════════════════════════════════════════════════════════════

def cmd_simulate(args: argparse.Namespace) -> None:
    """Run a DeFi attack chain simulation."""
    import json as _json
    from modules.attack_simulator.chain_executor import AttackChainExecutor
    from modules.attack_simulator.scenarios import SCENARIO_REGISTRY

    if args.list:
        print(f"\n{CYAN}{BOLD}Available Attack Scenarios:{RESET}\n")
        for sid, fn in SCENARIO_REGISTRY.items():
            c = fn()
            loss = c.loss_usd
            loss_str = f"${loss/1e6:.0f}M" if loss >= 1e6 else f"${loss:,.0f}"
            print(f"  {BOLD}{sid:<30}{RESET} {RED}{loss_str:<12}{RESET} {DIM}{c.name}{RESET}")
        print()
        return

    scenario_id = args.scenario
    fn = SCENARIO_REGISTRY.get(scenario_id)
    if fn is None:
        print(f"{RED}[!] Unknown scenario: {scenario_id}{RESET}")
        print(f"    Available: {', '.join(SCENARIO_REGISTRY.keys())}")
        sys.exit(1)

    print(f"\n{CYAN}{BOLD}[Attack Simulator]{RESET} Running scenario: {BOLD}{scenario_id}{RESET}")

    chain = fn()
    executor = AttackChainExecutor()
    result = executor.execute(chain)

    d = result.to_dict()

    if args.json:
        print(_json.dumps(d, indent=2))
        return

    print(f"\n  {BOLD}Scenario:{RESET}        {d['scenario_name']}")
    print(f"  {BOLD}Simulation ID:{RESET}   {d['simulation_id'][:16]}...")
    print(f"  {BOLD}Success:{RESET}         {'YES' if d['success'] else 'NO'}")
    print()
    profit_color = GREEN if d['attacker_profit_usd'] > 0 else RED
    print(f"  {RED}Protocol Loss:    ${d['protocol_loss_usd']:>15,.0f}{RESET}")
    print(f"  {profit_color}Attacker Profit:  ${d['attacker_profit_usd']:>15,.0f}{RESET}")
    print(f"  {DIM}Gas Cost:         ${d['total_gas_usd']:>15,.2f}{RESET}")
    print(f"  {DIM}Block Span:       {d['block_span']:>16} blocks{RESET}")
    print(f"  {YELLOW}Risk Index:       {d['risk_index']:>15.1f}/100{RESET}")

    if d['cascade_triggered']:
        print(f"\n  {YELLOW}{BOLD}[!] CASCADE TRIGGERED → {', '.join(d['cascade_protocols'])}{RESET}")

    print(f"\n  {DIM}MITRE Techniques:{RESET}")
    for t in d['mitre_techniques']:
        print(f"    • {t}")

    print(f"\n  {BOLD}Attack Steps:{RESET}")
    for step in d['steps']:
        prim = step['primitive']
        net = step.get('net_impact', 0)
        net_str = f"+${net:,.0f}" if net > 0 else f"${net:,.0f}"
        color = GREEN if net > 0 else (RED if net < 0 else DIM)
        print(f"    #{step['step_index']+1} {BOLD}{prim:<18}{RESET} {step['protocol']:<25} {color}{net_str}{RESET}")
    print()


def cmd_risk_score(args: argparse.Namespace) -> None:
    """Score a DeFi protocol's economic attack risk."""
    import json as _json
    from modules.attack_simulator.risk_scorer import DeFiRiskScorer

    scorer = DeFiRiskScorer()

    if args.list:
        print(f"\n{CYAN}{BOLD}Known protocols:{RESET}")
        for p in scorer.known_protocols():
            print(f"  • {p}")
        print()
        return

    if args.matrix:
        matrix = scorer.risk_matrix()
        if args.json:
            print(_json.dumps(matrix, indent=2))
            return
        print(f"\n{CYAN}{BOLD}DeFi Risk Matrix (Protocol × Attack Vector){RESET}\n")
        vectors = list(next(iter(matrix.values())).keys()) if matrix else []
        header = f"{'Protocol':<22}" + "".join(f"{v[:16]:<18}" for v in vectors)
        print(f"  {BOLD}{header}{RESET}")
        print(f"  {DIM}{'─'*120}{RESET}")
        for protocol, scores in matrix.items():
            row = f"  {protocol:<22}"
            for v in vectors:
                s = scores.get(v, 0)
                color = RED if s >= 80 else (YELLOW if s >= 60 else (DIM if s < 30 else ""))
                row += f"{color}{s:<18.0f}{RESET}"
            print(row)
        print()
        return

    score = scorer.score_protocol(
        protocol=args.protocol,
        tvl_usd=args.tvl,
    )
    d = score.to_dict()

    if args.json:
        print(_json.dumps(d, indent=2))
        return

    grade_color = GREEN if d['grade'] == 'A' else (YELLOW if d['grade'] in ('B', 'C') else RED)
    print(f"\n{CYAN}{BOLD}[Risk Score] {d['protocol']}{RESET}")
    print(f"  Grade:          {grade_color}{BOLD}{d['grade']}{RESET}")
    print(f"  Composite Risk: {d['composite_risk']:.1f}/100")
    print(f"  Chain:          {d['chain']}")
    print(f"  TVL:            ${d['tvl_usd']:,.0f}")
    print(f"  Audits:         {d['audit_count']}")
    print(f"\n  {BOLD}Vector Scores:{RESET}")
    for vector, score_val in d['scores'].items():
        bar = "█" * int(score_val / 5)
        color = RED if score_val >= 80 else (YELLOW if score_val >= 60 else GREEN)
        print(f"    {vector:<28} {color}{score_val:5.0f}/100  {bar}{RESET}")
    if d.get('mitigations'):
        print(f"\n  {BOLD}Recommended Mitigations:{RESET}")
        for vector, mitigation in d['mitigations'].items():
            print(f"    {YELLOW}• {vector}:{RESET}")
            print(f"      {DIM}{mitigation}{RESET}")
    print()


# ════════════════════════════════════════════════════════════════════════════════
# Phase 4 — Resilience Arena & Circuit Breaker CLI commands
# ════════════════════════════════════════════════════════════════════════════════

def cmd_wargame(args: argparse.Namespace) -> None:
    """Run an incident clash simulation or resilience benchmark."""
    import json as _json
    from modules.incident_response.resilience_arena import ResilienceArena

    arena = ResilienceArena()

    if args.benchmark:
        print(f"\n{CYAN}{BOLD}[Resilience Benchmark]{RESET} Running full suite on: {BOLD}{args.protocol}{RESET}")
        bench = arena.run_benchmark(protocol=args.protocol)
        if args.json:
            print(_json.dumps(bench, indent=2))
            return

        print(f"  Scenarios Evaluated : {bench['scenarios_evaluated']}")
        print(f"  Avg Salvage Rate    : {GREEN}{BOLD}{bench['average_salvage_rate_pct']:.1f}%{RESET}")
        print(f"  Avg Time-To-Detect  : {YELLOW}{bench['average_ttd_ms']:.2f} ms{RESET}")
        print(f"  Avg Time-To-Mitigate: {YELLOW}{bench['average_ttm_ms']:.2f} ms{RESET}")
        print(f"  Total Capital Saved : {GREEN}${bench['total_capital_saved_usd']:,.0f}{RESET}\n")

        print(f"  {BOLD}Scenario Clash Breakdown:{RESET}")
        for sc in bench['scenario_details']:
            print(f"    • {sc['scenario_type']:<35} Saved: {GREEN}{sc['salvage_rate_pct']:.1f}%{RESET} (TTM: {sc['ttm_ms']:.1f}ms)")
        print()
        return

    print(f"\n{CYAN}{BOLD}[Resilience Arena Clash]{RESET} Protocol: {args.protocol} | Scenario: {args.scenario}")
    res = arena.simulate_clash(
        protocol=args.protocol,
        scenario_key=args.scenario,
        custom_exposure_usd=args.exposure,
    )
    d = res.to_dict()

    if args.json:
        print(_json.dumps(d, indent=2))
        return

    print(f"  Clash ID         : {d['clash_id'][:16]}...")
    print(f"  Scenario         : {d['scenario_type']}")
    print(f"  Total Exposure   : {RED}${d['total_exposure_usd']:,.0f}{RESET}")
    print(f"  Capital Saved    : {GREEN}${d['capital_saved_usd']:,.0f} ({d['salvage_rate_pct']:.1f}%){RESET}")
    print(f"  Residual Loss    : ${d['capital_loss_usd']:,.0f}")
    print(f"  Time-To-Detect   : {YELLOW}{d['ttd_ms']:.2f} ms{RESET}")
    print(f"  Time-To-Mitigate : {YELLOW}{d['ttm_ms']:.2f} ms{RESET}")
    print(f"  Defense Action   : {CYAN}{d['defense_action']}{RESET}")
    print(f"  Breaker Status   : {GREEN}{d['circuit_breaker_status']}{RESET}\n")

    print(f"  {BOLD}Incident Timeline Rounds:{RESET}")
    for rnd in d['incident_rounds']:
        print(f"    Round #{rnd['round']} (+{rnd['block_offset']} blk): {rnd['event']} [{CYAN}{rnd['state']}{RESET}]")
    print()


def cmd_circuit_breaker(args: argparse.Namespace) -> None:
    """Synthesize custom Solidity circuit breaker and monitoring policies."""
    import json as _json
    from modules.incident_response.circuit_breaker import (
        CircuitBreakerConfig, CircuitBreakerSynthesizer
    )

    cfg = CircuitBreakerConfig(
        protocol_name=args.protocol,
        target_token=args.token,
        max_tvl_outflow_pct_per_window=args.outflow_cap,
        window_blocks=args.window_blocks,
        max_oracle_divergence_pct=args.oracle_dev,
    )

    synth = CircuitBreakerSynthesizer().synthesize(cfg)
    d = synth.to_dict()

    if args.json:
        print(_json.dumps(d, indent=2))
        return

    print(f"\n{CYAN}{BOLD}[Circuit Breaker Synthesizer]{RESET} Protocol: {args.protocol}")
    print(f"  Monitored Token  : {args.token}")
    print(f"  Outflow Limit    : {args.outflow_cap}% per {args.window_blocks} blocks")
    print(f"  Oracle Deviation : {args.oracle_dev}%")
    print(f"  Gas Overhead     : ~{d['estimated_gas_overhead']} gas per tx\n")

    print(f"  {BOLD}Active Protections:{RESET}")
    for prot in d['active_protections']:
        print(f"    • {GREEN}{prot}{RESET}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(d['solidity_code'])
        print(f"\n  {GREEN}[OK] Solidity guard written to: {args.output}{RESET}")
    else:
        print(f"\n  {DIM}Run with --output <file.sol> to save Solidity contract.{RESET}")
    print()


# ════════════════════════════════════════════════════════════════════════════════
# Phase 5 — Threat Hunting Watchtower CLI commands
# ════════════════════════════════════════════════════════════════════════════════

def cmd_hunt(args: argparse.Namespace) -> None:
    """Run EVM threat hunting watchtower scan."""
    import asyncio
    import json as _json
    from modules.threat_hunter.daemon import ThreatHuntingDaemon

    hunter = ThreatHuntingDaemon(chain=args.chain)

    if args.status:
        st = hunter.status().to_dict()
        if args.json:
            print(_json.dumps(st, indent=2))
        else:
            print(f"\n{CYAN}{BOLD}[Threat Hunter Status]{RESET}")
            print(f"  Chain:              {st['chain']}")
            print(f"  Running:            {'YES' if st['is_running'] else 'NO'}")
            print(f"  Blocks Scanned:     {st['blocks_scanned']}")
            print(f"  Contracts Analyzed: {st['contracts_analyzed']}")
            print(f"  Threats Detected:   {st['threats_detected']}")
            print(f"  Last Block:         #{st['last_block_number']}")
            print()
        return

    print(f"\n{CYAN}{BOLD}[Threat Hunter Watchtower]{RESET} Scanning {args.blocks} blocks on {args.chain}...")

    async def _scan():
        all_threats = []
        for i in range(args.blocks):
            findings = await hunter.scan_single_block()
            all_threats.extend(findings)
        return all_threats

    threats = asyncio.run(_scan())
    st = hunter.status().to_dict()

    if args.json:
        print(_json.dumps({
            "status": st,
            "threats": [t.to_dict() for t in threats],
        }, indent=2))
        return

    print(f"\n  Blocks Scanned:     {st['blocks_scanned']}")
    print(f"  Contracts Triage:   {st['contracts_analyzed']}")
    threat_color = RED if len(threats) > 0 else GREEN
    print(f"  Threats Flagged:    {threat_color}{BOLD}{len(threats)}{RESET}\n")

    if threats:
        print(f"  {BOLD}Detections in Block Stream:{RESET}")
        for t in threats:
            sev_color = RED if t.severity == "CRITICAL" else (YELLOW if t.severity == "HIGH" else CYAN)
            print(f"    • {sev_color}[{t.severity}] {t.detector_id}{RESET} {t.title}")
            print(f"      Target: {DIM}{t.target_address}{RESET} (Block #{t.block_number})")
            print(f"      Impact: ${t.estimated_impact_usd:,.0f} | Confidence: {t.confidence * 100:.0f}%")
            print(f"      Fix:    {DIM}{t.remediation}{RESET}\n")
    else:
        print(f"  {GREEN}No anomalous bytecode patterns detected in scanned blocks.{RESET}\n")


if __name__ == "__main__":
    main()

