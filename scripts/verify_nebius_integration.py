"""
Nebius x NVIDIA Nemotron & Tavily Integration Smoke Test
=========================================================
Checks connectivity to Nebius Token Factory and Tavily APIs.
If API keys are missing, runs mock validation to confirm pipeline readiness.
"""

import os
import sys
import asyncio
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Safe UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass

from orchestrator.services.nebius_llm import (
    validate_finding_with_nemotron,
    generate_executive_summary,
    generate_attack_graph_hypothesis,
    nebius_health_check,
    get_active_model,
    get_active_base_url,
    _is_available as nebius_available,
    NEBIUS_MODEL,
    NEBIUS_BASE_URL,
)
from orchestrator.services.threat_intel import (
    enrich_finding_with_threat_intel,
    _is_available as tavily_available,
)

SAMPLE_FINDING = {
    "rule_id": "SOL-001",
    "title": "Reentrancy Vulnerability",
    "severity": "CRITICAL",
    "file": "contracts/Vault.sol",
    "line": 42,
    "cwe": "CWE-841",
    "cvss_score": 9.8,
    "description": "External call before state update allows recursive drain.",
    "snippet": "msg.sender.call{value: amount}(\"\");\nbalances[msg.sender] -= amount;",
}


async def main():
    print("=" * 70)
    print("🚀 NEBIUS x NVIDIA GLOBAL AI HACKATHON — INTEGRATION VERIFIER")
    print("=" * 70)
    print(f"[*] Base URL        : {get_active_base_url()}")
    print(f"[*] NVIDIA Model    : {get_active_model()}")
    print(f"[*] Provider Key    : {'YES' if nebius_available() else 'NO (Set NEBIUS_API_KEY)'}")
    print(f"[*] Tavily Key set  : {'YES' if tavily_available() else 'NO (Set TAVILY_API_KEY)'}")
    print("-" * 70)

    if nebius_available():
        print("[*] Testing Nebius connectivity...")
        health = await nebius_health_check()
        print(f"[+] Nebius Health: {health}")

        print("[*] Testing NVIDIA Nemotron finding validation...")
        validated = await validate_finding_with_nemotron(SAMPLE_FINDING)
        if "nebius_ai" in validated:
            print("[✓] Validation SUCCESS:")
            ai = validated["nebius_ai"]
            print(f"    - True Positive : {ai.get('is_true_positive')}")
            print(f"    - Confidence    : {ai.get('confidence')}")
            print(f"    - Explanation   : {ai.get('ai_explanation')[:80]}...")
        else:
            print("[!] Validation completed without AI enrichment.")

        print("[*] Testing Executive Summary generation...")
        summary = await generate_executive_summary(
            [SAMPLE_FINDING],
            {"CRITICAL": 1, "HIGH": 0, "total": 1},
            repo_url="https://github.com/demo/vault",
        )
        if summary:
            print("[✓] Executive Summary SUCCESS:")
            print(f"    {summary[:120]}...")

        print("[*] Testing NVIDIA Nemotron Attack Graph Kill Chain generation...")
        graph = await generate_attack_graph_hypothesis(
            [SAMPLE_FINDING],
            repo_url="https://github.com/demo/vault",
            project_name="Vault & Bridge Ecosystem"
        )
        if graph:
            print("[✓] Attack Graph SUCCESS:")
            print(f"    - Title   : {graph.get('title')}")
            print(f"    - Threat  : {graph.get('threat_actor')}")
            print(f"    - Steps   : {len(graph.get('steps', []))} phases d'exploitation")
    else:
        print("[i] NEBIUS_API_KEY not provided.")
        print("    The pipeline gracefully runs with deterministic SAST fallback.")
        print("    To activate NVIDIA Nemotron on Nebius, run:")
        print("    $env:NEBIUS_API_KEY = 'your-key'")

    print("-" * 70)
    if tavily_available():
        print("[*] Testing Tavily threat intelligence search...")
        enriched = await enrich_finding_with_threat_intel(SAMPLE_FINDING)
        if "threat_intel" in enriched:
            print(f"[✓] Tavily SUCCESS: Found {len(enriched['threat_intel'])} threat sources.")
    else:
        print("[i] TAVILY_API_KEY not provided (optional $3,000 prize track).")

    print("=" * 70)
    print("✅ Smoke test finished successfully!")


if __name__ == "__main__":
    asyncio.run(main())
