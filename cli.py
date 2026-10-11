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

    # serve
    p_serve = subparsers.add_parser("serve", help="Start the FastAPI backend server")
    p_serve.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    p_serve.add_argument("--reload", action="store_true", default=False, help="Enable auto-reload")

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
    elif args.command == "serve":
        cmd_serve(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
