"""
Nebius Token Factory — NVIDIA Nemotron Integration
===================================================
Hackathon requirement: must use Nebius AI infrastructure + NVIDIA open-source model.

This module provides AI-powered security finding validation and executive report
generation using NVIDIA Nemotron models hosted on Nebius Token Factory.

Usage:
    Set NEBIUS_API_KEY environment variable before starting the API.
    Optionally set NEBIUS_MODEL to override the default model.

Environment variables:
    NEBIUS_API_KEY   — Your Nebius Token Factory API key (required)
    NEBIUS_MODEL     — Model ID (default: nvidia/Nemotron-3_5-Lightning)
    NEBIUS_BASE_URL  — API endpoint (default: https://api.tokenfactory.nebius.com/v1/)
"""

import os
import json
import logging
import asyncio
from typing import Optional

logger = logging.getLogger("adversum.nebius")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NEBIUS_BASE_URL = os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/")
NEBIUS_MODEL = os.getenv("NEBIUS_MODEL", "nvidia/Nemotron-3_5-Lightning")

_client = None


def _is_available() -> bool:
    """Returns True if the Nebius API key is configured or demo mode is active."""
    val = os.getenv("NEBIUS_API_KEY", "").strip()
    return bool(val) or os.getenv("NEBIUS_MOCK", "").lower() in ("1", "true", "yes")


def _is_demo_mode() -> bool:
    """Returns True if demo/simulation mode is active."""
    val = os.getenv("NEBIUS_API_KEY", "").strip().lower()
    return val in ("demo", "mock", "test", "fake") or os.getenv("NEBIUS_MOCK", "").lower() in ("1", "true", "yes")


def _generate_mock_validation(finding: dict) -> dict:
    """Generate realistic Nemotron-style validation for demo & offline video recording."""
    rule_id = finding.get("rule_id", "SEC-VULN")
    sev = (finding.get("severity") or "HIGH").upper()
    is_tp = sev in ("CRITICAL", "HIGH", "MEDIUM")
    confidence = 0.96 if sev == "CRITICAL" else 0.89 if sev == "HIGH" else 0.78
    
    explanation = (
        f"Analyse NVIDIA Nemotron : La règle {rule_id} dans {finding.get('file', 'le code')} présente un schéma "
        f"vulnérable avéré avec un impact direct sur la sécurité des actifs numériques."
    )
    remediation = (
        f"Appliquer un contrôle strict des accès et valider les invariants avant toute transition d'état. "
        f"Se référer au standard {finding.get('cwe', 'CWE-Security')}."
    )
    attack = f"Un attaquant pourrait exploiter cette faille pour contourner les contrôles d'intégrité."

    return {
        "is_true_positive": is_tp,
        "confidence": confidence,
        "ai_explanation": explanation,
        "ai_remediation": remediation,
        "attack_scenario": attack,
        "cwe_reference": finding.get("cwe", "CWE-699")
    }


def _generate_mock_summary(findings: list, stats: dict, repo_url: str = "") -> str:
    """Generate realistic Nemotron CISO executive summary for demo & video recording."""
    critical = stats.get("CRITICAL", 0)
    high = stats.get("HIGH", 0)
    total = stats.get("total", len(findings))

    return (
        f"### Évaluation Globale de la Posture de Sécurité (NVIDIA Nemotron via Nebius)\n\n"
        f"L'analyse automatisée de la cible `{repo_url or 'Target Repository'}` a identifié un total de **{total} vulnérabilité(s)**, "
        f"dont **{critical} critique(s)** et **{high} élevée(s)**. La surface d'attaque principale concerne la gestion des flux de trésorerie "
        f"et l'intégrité des contrôles d'accès cryptographiques.\n\n"
        f"**Impact Métier & Risques Majeurs :** Les failles critiques identifiées exposent les protocoles à des risques d'exfiltration de liquidités "
        f"ou d'altération d'état non autorisée. Une remédiation prioritaire sur les composants de passerelle et de garde d'actifs est impérative.\n\n"
        f"**Plan d'Action Immédiat :**\n"
        f"1. Appliquer les correctifs générés automatiquement sur les {critical} vulnérabilités critiques.\n"
        f"2. Déployer les tests d'exploit Foundry (PoC) dans le pipeline CI/CD avant toute mise en production.\n"
        f"3. Réitérer l'audit différentiel Adversum pour confirmer l'éradication des vecteurs d'attaque."
    )


def get_active_model() -> str:
    """Return the active model ID, adapting to the target provider if needed."""
    env_model = os.getenv("NEBIUS_MODEL")
    if env_model:
        return env_model
    api_key = os.getenv("NEBIUS_API_KEY", "").strip()
    if api_key.startswith("nvapi-"):
        return "nvidia/nemotron-3.5-lightning-30b-a3b"
    return NEBIUS_MODEL


def get_active_base_url() -> str:
    """Return the active base URL, adapting to the target provider if needed."""
    env_url = os.getenv("NEBIUS_BASE_URL")
    if env_url:
        return env_url
    api_key = os.getenv("NEBIUS_API_KEY", "").strip()
    if api_key.startswith("nvapi-"):
        return "https://integrate.api.nvidia.com/v1"
    return NEBIUS_BASE_URL


def _extract_json(raw: str) -> dict:
    """Robustly extract a JSON object from LLM output.

    Handles:
    - <think>...</think> reasoning tags
    - Explicit <json>...</json> and <graph>...</graph> tags
    - Markdown fences (```json ... ```)
    - Nemotron-3.5-Lightning reasoning preambles (prose text before JSON)
    - Trailing commentary / rambling after the JSON
    """
    raw = raw.strip()

    # Strip <think> blocks
    if "<think>" in raw and "</think>" in raw:
        raw = raw.split("</think>", 1)[1].strip()

    # 1. Try explicit tags like <json> ... </json> or <graph> ... </graph>
    for tag in ("json", "graph"):
        open_tag = f"<{tag}>"
        close_tag = f"</{tag}>"
        if open_tag in raw:
            part = raw.split(open_tag, 1)[1]
            if close_tag in part:
                candidate = part.split(close_tag, 1)[0].strip()
            else:
                candidate = part.strip()
            # Clean markdown code fences inside tag if present
            if "```" in candidate:
                fenced = candidate.split("```")
                for f in fenced:
                    if "{" in f and "}" in f:
                        candidate = f
                        if candidate.startswith("json"):
                            candidate = candidate[4:]
                        break
            candidate = candidate.strip()
            try:
                return json.loads(candidate)
            except Exception:
                pass

    # 2. Try direct parse
    try:
        return json.loads(raw)
    except Exception:
        pass

    # 3. Try finding ```json ... ``` or ``` ... ``` fence
    for fence_start in ("```json", "```"):
        if fence_start in raw:
            part = raw.split(fence_start, 1)[1]
            if "```" in part:
                candidate = part.split("```", 1)[0].strip()
                try:
                    return json.loads(candidate)
                except Exception:
                    pass

    # 4. Infallible forward brace matcher: scan every opening { and match closing }
    starts = [i for i, ch in enumerate(raw) if ch == "{"]
    candidates = []
    for s in starts:
        depth = 0
        for e in range(s, len(raw)):
            if raw[e] == "{":
                depth += 1
            elif raw[e] == "}":
                depth -= 1
                if depth == 0:
                    cand = raw[s : e + 1].strip()
                    try:
                        d = json.loads(cand)
                        if isinstance(d, dict):
                            candidates.append(d)
                    except Exception:
                        pass
                    break

    # Prioritize candidate with expected schema keys
    for d in reversed(candidates):
        if any(k in d for k in ("is_true_positive", "confidence", "title", "steps")):
            return d

    if candidates:
        return candidates[-1]

    raise ValueError(f"Could not extract valid JSON from response: {raw[:300]}")


def _clean_reasoning(text: str) -> str:
    """Strip reasoning traces, extract <report> tags, and clean preambles from prose text."""
    import re
    text = text.strip()
    if "<think>" in text and "</think>" in text:
        text = text.split("</think>", 1)[1].strip()

    # Priority 1: If explicit <report> tag exists, extract strictly what's inside
    if "<report>" in text:
        part = text.split("<report>", 1)[1]
        if "</report>" in part:
            return part.split("</report>", 1)[0].strip()
        return part.strip()

    # Priority 2: If Nemotron drafted paragraphs inside a thinking/planning outline
    # (e.g. Draft: "The Digital Asset Platform audit..." or Draft - Paragraph 1: ...)
    drafted_quotes = re.findall(r'Draft:\s*"([^"]{40,})"', text)
    if len(drafted_quotes) >= 2:
        return "\n\n".join(drafted_quotes)

    # Priority 3: Strip numbered analysis headers (e.g. 1. **Analyze the Request:** ... 6. **Review:**)
    # If the text starts with a numbered planning step, look for the final summary or markdown headings
    if re.match(r'^\s*1\.\s+\*\*', text):
        # Look for double newline followed by actual report text or headings
        # If there's a "###" or "**Overall" heading later, cut to it
        heading_match = re.search(r'\n\n(\*{0,2}(?:The |Overall |### |# ).*)', text)
        if heading_match and len(heading_match.group(1)) > 150:
            return heading_match.group(1).strip()

    # Priority 4: Strip common preamble markers
    preamble_markers = [
        "here's a thinking process",
        "here is a thinking process",
        "here's my thinking",
        "let me analyze",
        "let me think",
        "thinking process:",
    ]
    lower = text.lower()
    for marker in preamble_markers:
        if lower.startswith(marker):
            idx = text.find("\n\n", len(marker))
            if idx != -1:
                candidate = text[idx:].strip()
                if len(candidate) > 50:
                    text = candidate
                    break
    return text


def _get_client():
    """Lazily initialize and return the AsyncOpenAI client pointing at Nebius or NVIDIA NIM."""
    global _client
    if _client is None:
        try:
            from openai import AsyncOpenAI
            api_key = os.getenv("NEBIUS_API_KEY")
            if not api_key:
                raise ValueError("NEBIUS_API_KEY is not set")
            
            base_url = get_active_base_url()
            model = get_active_model()
            logger.info(f"[Nebius/NVIDIA] Initializing client — model: {model} at {base_url}")

            _client = AsyncOpenAI(
                api_key=api_key,
                base_url=base_url,
                timeout=60.0,
                max_retries=1,
            )
            logger.info(f"[Nebius/NVIDIA] Client initialized successfully")
        except Exception as e:
            logger.error(f"[Nebius/NVIDIA] Failed to initialize client: {e}")
            raise
    return _client


# ---------------------------------------------------------------------------
# Finding validation
# ---------------------------------------------------------------------------
async def validate_finding_with_nemotron(finding: dict) -> dict:
    """
    Use NVIDIA Nemotron (via Nebius Token Factory) to validate a single
    security finding and enrich it with AI-powered analysis.

    Returns the original finding dict augmented with a 'nebius_ai' key
    containing confidence score, explanation, and remediation advice.
    Falls back gracefully if Nebius is unavailable.
    """
    if not _is_available():
        return finding

    if _is_demo_mode():
        return {**finding, "nebius_ai": _generate_mock_validation(finding), "ai_powered": True}

    try:
        client = _get_client()
        snippet = (finding.get("snippet") or "")[:300]
        prompt = f"""You are an expert application security engineer. Analyze this SAST finding and determine if it is a true or false positive. Be concise and precise.

Finding details:
- Rule ID: {finding.get('rule_id', 'N/A')}
- Severity: {finding.get('severity', 'N/A')}
- File: {finding.get('file', 'N/A')} (line {finding.get('line', '?')})
- Description: {finding.get('description', 'N/A')}
- Code snippet:
```
{snippet}
```

Enclose your final JSON strictly between <json> and </json> tags:
<json>
{{
  "is_true_positive": true,
  "confidence": 0.92,
  "ai_explanation": "Brief explanation of why this is real or a false positive",
  "ai_remediation": "Specific fix recommendation",
  "attack_scenario": "Short real-world attack scenario (1 sentence)",
  "cwe_reference": "CWE-XXX"
}}
</json>"""

        response = await client.chat.completions.create(
            model=get_active_model(),
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a SAST security analyst. Always output your final JSON object enclosed strictly between <json> and </json> tags."
                    )
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=1500,
        )

        raw = response.choices[0].message.content.strip()
        ai_data = _extract_json(raw)
        logger.info(
            f"[Nebius] Validated '{finding.get('rule_id')}' — "
            f"true_positive={ai_data.get('is_true_positive')} "
            f"confidence={ai_data.get('confidence')}"
        )
        return {**finding, "nebius_ai": ai_data, "ai_powered": True}

    except Exception as e:
        logger.warning(f"[Nebius] Validation failed for {finding.get('rule_id')}: {e}")
        return finding


# ---------------------------------------------------------------------------
# Batch validation (top N findings)
# ---------------------------------------------------------------------------
async def validate_findings_batch(findings: list, max_findings: int = 4) -> list:
    """
    Validate up to `max_findings` findings sequentially with a semaphore to avoid
    overwhelming the free-tier NVIDIA NIM rate limit and causing 504 Gateway Timeouts.
    Returns the full findings list with AI enrichment on the first N items.
    """
    if not _is_available() or not findings:
        return findings

    top = findings[:max_findings]
    rest = findings[max_findings:]

    sem = asyncio.Semaphore(1)

    async def _throttled_validate(f):
        async with sem:
            return await validate_finding_with_nemotron(f)

    validated = await asyncio.gather(
        *[_throttled_validate(f) for f in top],
        return_exceptions=True
    )

    result = []
    for orig, val in zip(top, validated):
        if isinstance(val, Exception):
            result.append(orig)
        else:
            result.append(val)

    return result + rest


# ---------------------------------------------------------------------------
# Executive summary generation
# ---------------------------------------------------------------------------
async def generate_executive_summary(
    findings: list,
    stats: dict,
    repo_url: str = "",
    project_name: str = "Target Repository",
) -> Optional[str]:
    """
    Generate a concise executive security report summary using NVIDIA Nemotron.
    Returns a markdown-formatted string, or None if Nebius is unavailable.
    """
    if not _is_available():
        return None

    if _is_demo_mode():
        return _generate_mock_summary(findings, stats, repo_url=repo_url)

    try:
        client = _get_client()
        critical = stats.get("CRITICAL", 0)
        high = stats.get("HIGH", 0)
        medium = stats.get("MEDIUM", 0)
        low = stats.get("LOW", 0)
        total = stats.get("total", len(findings))

        top_rules = list({f.get("rule_id", "UNKNOWN") for f in findings[:10]})[:6]
        top_files = list({f.get("file", "") for f in findings[:10] if f.get("file")})[:4]

        prompt = f"""Write a concise executive security assessment summary for a CISO or board audience.

Project: {project_name}
Repository: {repo_url}
Findings: {critical} CRITICAL, {high} HIGH, {medium} MEDIUM, {low} LOW (total: {total})
Key vulnerability types detected: {', '.join(top_rules)}
Most affected files: {', '.join(top_files)}

Write 3 short paragraphs:
1. Overall security posture and risk level (2-3 sentences)
2. Most critical findings and business impact (2-3 sentences)
3. Immediate recommended actions (2-3 sentences)

Keep it professional, concise, and action-oriented. Use markdown formatting.
Enclose your final 3-paragraph executive report strictly inside <report> and </report> tags."""

        response = await client.chat.completions.create(
            model=get_active_model(),
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior CISO security consultant. Always output your final executive summary strictly enclosed between <report> and </report> tags."
                    )
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=1500,
        )

        summary = _clean_reasoning(response.choices[0].message.content)
        logger.info(f"[Nebius] Executive summary generated ({len(summary)} chars)")
        return summary

    except Exception as e:
        logger.warning(f"[Nebius] Executive summary generation failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
async def nebius_health_check() -> dict:
    """Quick connectivity check for the /health endpoint."""
    if not _is_available():
        return {"status": "disabled", "reason": "NEBIUS_API_KEY not set"}
    if _is_demo_mode():
        return {
            "status": "ok",
            "mode": "demo_simulation",
            "model": get_active_model(),
            "base_url": get_active_base_url(),
            "reply": "OK (Simulation)",
        }
    try:
        client = _get_client()
        response = await client.chat.completions.create(
            model=get_active_model(),
            messages=[{"role": "user", "content": "Reply with the single word: OK"}],
            max_tokens=150,
        )
        reply = _clean_reasoning(response.choices[0].message.content).strip()
        return {
            "status": "ok",
            "model": get_active_model(),
            "base_url": get_active_base_url(),
            "reply": reply,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ---------------------------------------------------------------------------
# Attack Graph & Exploit Chain Hypothesis (NVIDIA Nemotron Reasoning)
# ---------------------------------------------------------------------------
def _generate_mock_attack_graph(findings: list, project_name: str = "") -> dict:
    """Realistic attack graph kill chain for demo mode and visual presentation."""
    return {
        "title": "Chaine d'Attaque Multi-Contrats : Reentrancy Drain & Zero-Root Bridge Exfiltration",
        "threat_actor": "Attaquant Externe / Blackhat MEV Arbitrageur",
        "overall_impact": "Compromission totale de la trésorerie et émission de wrapped-tokens non garantis",
        "complexity": "HIGH",
        "steps": [
            {
                "step": 1,
                "phase": "Accès Initial & Vol de Liquidité",
                "finding_id": "SOL-001",
                "file": "contracts/Vault.sol",
                "action": "Exploite la faille de réentrance dans withdraw() via un contrat fallback pour vider la balance du Vault.",
                "outcome": "Acquisition de 100+ ETH de liquidité non auditée."
            },
            {
                "step": 2,
                "phase": "Escalade & Mouvement Latéral",
                "finding_id": "BRIDGE-003",
                "file": "contracts/CrossChainBridge.sol",
                "action": "Réinjecte les fonds volés en fournissant une preuve Merkle avec racine nulle bytes32(0) acceptée par le bridge.",
                "outcome": "Validation frauduleuse de dépôts inter-chaînes vers un réseau secondaire."
            },
            {
                "step": 3,
                "phase": "Dissimulation & Impact Final",
                "finding_id": "POR-001",
                "file": "custody/liabilities.py",
                "action": "Exploite l'absence de garde de balance négative dans le calcul de passif du Merkle Sum Tree.",
                "outcome": "Dissimulation du déficit de collatéral lors des audits de solvabilité Proof of Reserves."
            }
        ],
        "edges": [
            {"from": "SOL-001", "to": "BRIDGE-003", "relation": "Finance l'attaque du bridge avec les fonds volés du Vault"},
            {"from": "BRIDGE-003", "to": "POR-001", "relation": "Création d'un déficit comptable masqué dans l'arbre de réserve"}
        ]
    }


async def generate_attack_graph_hypothesis(
    findings: list,
    repo_url: str = "",
    project_name: str = "Target System"
) -> Optional[dict]:
    """
    Use NVIDIA Nemotron to reason across all detected vulnerabilities and synthesize
    a multi-step attack graph / kill chain hypothesis.
    """
    if not _is_available() or not findings:
        return None

    if _is_demo_mode():
        return _generate_mock_attack_graph(findings, project_name=project_name)

    try:
        client = _get_client()
        top_findings = findings[:8]
        findings_summary = [
            f"- Rule {f.get('rule_id')} in {f.get('file', '?')} (L{f.get('line', '?')}): {f.get('description', '')[:120]}"
            for f in top_findings
        ]
        prompt = f"""You are an elite offensive security researcher and threat modeling architect.
Analyze the following vulnerabilities found in this software target and synthesize an realistic end-to-end Attack Graph (Multi-Stage Exploit Chain / Kill Chain) showing how an advanced attacker could chain these flaws together.

Target: {project_name} ({repo_url})
Detected Vulnerabilities:
{chr(10).join(findings_summary)}

Enclose your final JSON object strictly between <graph> and </graph> tags:
<graph>
{{
  "title": "Concise title for the multi-stage exploit chain",
  "threat_actor": "External Attacker / Malicious MEV / Insider",
  "overall_impact": "Financial loss or privilege compromise description",
  "complexity": "LOW / MEDIUM / HIGH",
  "steps": [
    {{
      "step": 1,
      "phase": "Initial Access / Privilege Escalation / Lateral Movement / Impact",
      "finding_id": "RULE-ID",
      "file": "filename",
      "action": "Concrete attack action taken",
      "outcome": "Immediate result achieved by attacker"
    }}
  ],
  "edges": [
    {{
      "from": "RULE-ID-1",
      "to": "RULE-ID-2",
      "relation": "Why exploiting 1 enables or compounds 2"
    }}
  ]
}}
</graph>"""
        response = await client.chat.completions.create(
            model=get_active_model(),
            messages=[
                {"role": "system", "content": "You are an automated threat modeling engine. Always output your final compact JSON strictly enclosed between <graph> and </graph> tags."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=1800
        )
        raw = response.choices[0].message.content.strip()
        data = _extract_json(raw)
        logger.info(f"[Nebius/Nemotron] Attack graph hypothesis generated: {data.get('title')}")
        return data
    except Exception as e:
        logger.warning(f"[Nebius/Nemotron] Attack graph generation failed: {e}")
        return _generate_mock_attack_graph(findings, project_name=project_name) if _is_demo_mode() else None

