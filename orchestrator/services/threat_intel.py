"""
Tavily Threat Intelligence Enrichment
======================================
Bonus: "Best Use of Tavily" hackathon prize ($3,000).

Enriches security findings with real-world CVE data, public exploits,
and recent security advisories fetched live from the web via Tavily Search.

Environment variables:
    TAVILY_API_KEY  — Your Tavily API key (get one at https://tavily.com)
"""

import os
import asyncio
import logging
from typing import Optional

logger = logging.getLogger("adversum.tavily")


def _is_available() -> bool:
    """Returns True if the Tavily API key is configured or demo mode is active."""
    val = os.getenv("TAVILY_API_KEY", "").strip()
    return bool(val) or os.getenv("TAVILY_MOCK", "").lower() in ("1", "true", "yes")


def _is_demo_mode() -> bool:
    """Returns True if Tavily demo mode is active."""
    val = os.getenv("TAVILY_API_KEY", "").strip().lower()
    return val in ("demo", "mock", "test", "fake") or os.getenv("TAVILY_MOCK", "").lower() in ("1", "true", "yes")


async def enrich_finding_with_threat_intel(finding: dict) -> dict:
    """
    Search for real-world CVEs, exploits, and advisories related to this finding.
    Adds a 'threat_intel' key to the finding dict.
    Falls back gracefully if Tavily is unavailable.
    """
    if not _is_available():
        return finding

    if _is_demo_mode():
        cwe = finding.get("cwe") or "CWE-Security"
        rule_id = finding.get("rule_id", "SEC")
        mock_intel = [
            {
                "title": f"NVD CVE Database: Exploits & Vectors for {cwe}",
                "url": f"https://nvd.nist.gov/vuln/detail/{cwe}",
                "snippet": f"Advisory on real-world exploit patterns corresponding to {rule_id}.",
                "score": 0.94
            },
            {
                "title": f"Snyk Vulnerability Database — Remediation & Threat Analysis ({rule_id})",
                "url": f"https://security.snyk.io/vuln/{rule_id}",
                "snippet": f"Known PoC payloads and security remediation guidelines.",
                "score": 0.88
            }
        ]
        return {**finding, "threat_intel": mock_intel, "tavily_enriched": True}

    try:
        from tavily import AsyncTavilyClient
        client = AsyncTavilyClient(api_key=os.getenv("TAVILY_API_KEY"))

        rule_id = finding.get("rule_id", "")
        description = (finding.get("description") or "")[:120]
        severity = finding.get("severity", "")
        cwe = finding.get("cwe", "")

        # Build targeted query
        parts = [rule_id, description]
        if cwe:
            parts.append(cwe)
        parts.extend(["CVE exploit security advisory 2024 2025 2026"])
        query = " ".join(filter(None, parts))[:400]

        results = await client.search(
            query=query,
            max_results=3,
            search_depth="advanced",
            include_domains=["cve.mitre.org", "nvd.nist.gov", "exploit-db.com",
                             "github.com", "snyk.io", "huntr.com", "securityfocus.com"],
        )

        intel = [
            {
                "title": r.get("title", ""),
                "url": r.get("url", ""),
                "snippet": (r.get("content") or "")[:250],
                "score": round(r.get("score", 0.0), 3),
            }
            for r in results.get("results", [])
            if r.get("title") and r.get("url")
        ]

        if intel:
            logger.info(
                f"[Tavily] Enriched '{rule_id}' with {len(intel)} intel source(s)"
            )
            return {**finding, "threat_intel": intel, "tavily_enriched": True}
        return finding

    except Exception as e:
        logger.warning(f"[Tavily] Enrichment failed for {finding.get('rule_id')}: {e}")
        return finding


async def enrich_findings_batch(findings: list, max_findings: int = 5) -> list:
    """
    Enrich the top N critical/high findings with Tavily threat intelligence.
    Runs enrichment in parallel for speed.
    """
    if not _is_available() or not findings:
        return findings

    # Prioritize CRITICAL and HIGH findings for enrichment
    priority_sevs = {"CRITICAL", "HIGH"}
    priority = [f for f in findings if (f.get("severity") or "").upper() in priority_sevs]
    others = [f for f in findings if f not in priority]

    to_enrich = priority[:max_findings]
    not_enriched = priority[max_findings:] + others

    enriched = await asyncio.gather(
        *[enrich_finding_with_threat_intel(f) for f in to_enrich],
        return_exceptions=True
    )

    result = []
    for orig, val in zip(to_enrich, enriched):
        if isinstance(val, Exception):
            result.append(orig)
        else:
            result.append(val)

    return result + not_enriched
