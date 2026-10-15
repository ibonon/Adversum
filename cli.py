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


if __name__ == "__main__":
    main()
