# 🌐 Tavily Threat Intelligence Integration

> **Hackathon Submission:** Special Prize Track — **$3,000 Best Use of Tavily**

This document details how **Adversum** utilizes the **Tavily Search API** to bridge the gap between static code analysis and real-world threat intelligence.

---

## 🎯 1. The Problem Adversum Solves with Tavily

Static analysis tools (SAST) flag code patterns in isolation (e.g., *"CWE-841: Reentrancy"*). However, developers and security auditors always need context:
- Has this specific vulnerability pattern been exploited in the wild?
- Are there public Proof-of-Concepts (PoCs) or CVE advisories published in 2024–2026?
- What was the historical impact on similar platforms (e.g., The DAO, Nomad Bridge)?

By integrating **Tavily Search**, Adversum enriches every critical and high-severity finding with live, authoritative security advisories directly in the audit dashboard.

---

## ⚙️ 2. Architectural Implementation

- **Service Module**: `orchestrator/services/threat_intel.py`
- **API Endpoint**: Automatically invoked during `POST /api/v1/scan/clone-and-scan` and `POST /api/v1/scan/all`

### Targeted Query Formulation

Adversum builds precision-crafted queries designed to hit official vulnerability databases rather than generic blog posts:

```python
parts = [rule_id, description[:120]]
if cwe:
    parts.append(cwe)
parts.extend(["CVE exploit security advisory 2024 2025 2026"])
query = " ".join(filter(None, parts))[:400]
```

### Domain Whitelisting for Authoritative Sources

Tavily's `include_domains` parameter is leveraged to restrict searches exclusively to trusted security repositories:

```python
results = await client.search(
    query=query,
    max_results=3,
    search_depth="advanced",
    include_domains=[
        "cve.mitre.org",
        "nvd.nist.gov",
        "exploit-db.com",
        "github.com",
        "snyk.io",
        "huntr.com",
        "securityfocus.com"
    ],
)
```

---

## 📊 3. Output in the Adversum Dashboard

Each enriched finding in the UI displays live threat intel cards:

```json
{
  "rule_id": "SOL-001",
  "name": "SOL-001: Reentrancy Attack",
  "threat_intel": [
    {
      "title": "NVD CVE Database: Exploits & Vectors for CWE-841",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2016-10001",
      "snippet": "Advisory on real-world exploit patterns corresponding to SOL-001.",
      "score": 0.95
    },
    {
      "title": "Snyk Vulnerability Database — Cross-Function Reentrancy",
      "url": "https://security.snyk.io/vuln/SNYK-SOLIDITY-REENTRANCY",
      "snippet": "Known PoC payloads and security remediation guidelines.",
      "score": 0.91
    }
  ],
  "tavily_enriched": true
}
```

In the web interface (`DashboardPreview.tsx`), auditors can click directly on the advisory links to see the original CVE, official patches, and public attack history.

---

## 🚀 4. How to Enable & Test

1. Set your Tavily API Key in `.env`:
   ```bash
   TAVILY_API_KEY="tvly-your-api-key-here"
   ```
2. Verify connectivity with the Adversum CLI:
   ```bash
   python cli.py check-ai
   ```
   Output:
   ```
   [2/3] Checking Tavily Threat Intelligence API...
     [+] Tavily API Key configured: tvly-pro...
     [+] Tavily Threat Intelligence Verified! Found 1 live advisory source(s).
   ```
3. Run an audit scan; any critical or high finding will be enriched in real time.
