# ⚡ Adversum Phase 2: AI Autonomous Security Operations Center (AI-ASOC)

This document describes the architecture, operation, and verification of **Phase 2** of Adversum's singularity roadmap — transforming a powerful audit tool into a **24/7 autonomous security operations center**.

---

## 1. Architectural Overview

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                        ADVERSUM AI-ASOC (Phase 2)                                │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐    │
│  │                    Real-Time WebSocket Threat Stream                      │    │
│  │                  (ThreatEventBus — Fan-Out Pub/Sub)                       │    │
│  └──────────┬──────────────┬───────────────┬──────────────┬─────────────────┘    │
│             │              │               │              │                       │
│             ▼              ▼               ▼              ▼                       │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────┐ ┌──────────────────────────┐  │
│  │ MEV & Flash  │ │ Autonomous   │ │  SOC2 +    │ │  Live SOC Dashboard      │  │
│  │ Loan Intel   │ │ Threat Model │ │  ISO27001  │  │  (React 18 WebSocket UI) │  │
│  │ (7 Chains)   │ │ STRIDE+PASTA │ │  + SARIF   │ │  /soc route              │  │
│  └──────────────┘ └──────────────┘ └────────────┘ └──────────────────────────┘  │
│                                                                                  │
│  ══════════════ PHASE 1 FOUNDATION ══════════════════════════════════════════    │
│  Live Fork PoE Engine │ Tri-Partite Self-Healing Bot │ NVIDIA Nemotron AI         │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Module 1: Real-Time WebSocket Threat Stream

### File: `orchestrator/services/threat_stream.py`

Async event bus with fan-out pub/sub, 200-event rolling history, and heartbeat keep-alive.

### Event Types
| Event | Trigger |
|---|---|
| `finding_detected` | SAST core finds a vulnerability |
| `exploit_confirmed` | Live Fork PoE confirms exploit |
| `patch_generated` | Self-Healing Bot creates patch |
| `mev_attack_detected` | MEV engine finds attack pattern |
| `threat_model_ready` | Threat modeler completes analysis |
| `compliance_report` | Compliance scores updated |
| `cve_correlation` | Tavily matches a live CVE |

### WebSocket Endpoint
```
ws://localhost:8000/ws/threat-stream
Header: X-API-Key: <your-key>
```

### REST Endpoints
```http
GET /api/v1/threat-stream/history?limit=50&severity=CRITICAL
GET /api/v1/threat-stream/stats
```

### CLI
```powershell
python cli.py ws-listen --duration 120
```

---

## 3. Module 2: MEV & Flash Loan Attack Intelligence

### File: `modules/mev_intelligence/engine.py`

Multi-chain MEV attack detector supporting 7 EVM chains and 4 core attack types.

### Supported Attack Patterns
| Pattern | Description | MITRE |
|---|---|---|
| **Sandwich** | Front-run + victim + back-run via gas price ordering | T0836 |
| **Flash Loan** | Same-block borrow → exploit → repay | T0828 |
| **Oracle Manipulation** | Single tx distorting >15% of pool TWAP | T0830 |
| **Rug Pull** | Single address draining >80% of liquidity | T0840 |

### Supported Chains
`ethereum` · `arbitrum` · `base` · `optimism` · `polygon` · `bsc` · `avalanche`

### API Endpoint
```http
POST /api/v1/intelligence/mev-analyze
{
  "transactions": [...],
  "chain": "ethereum",
  "pool_liquidity_eth": 1000.0,
  "eth_price_usd": 2650.0
}
```

### CLI
```powershell
python cli.py mev-scan --chain ethereum --txs 15
```

### Output
```json
{
  "analysis_id": "uuid",
  "patterns_found": [{
    "attack_type": "sandwich",
    "risk_level": "CRITICAL",
    "value_at_risk_usd": 26500.0,
    "attacker_address": "0xdead...",
    "mitre_technique": "T0836 — Modify Parameter",
    "mitigation": "Implement slippage tolerance checks..."
  }]
}
```

---

## 4. Module 3: Autonomous Threat Modeling (STRIDE + PASTA + MITRE ATT&CK)

### File: `modules/threat_model/autonomous_modeler.py`

Fully autonomous generation of STRIDE threat matrix, PASTA 7-stage analysis, and MITRE ATT&CK for Web3/ICS mapping — in <60 seconds from raw source code.

### STRIDE Categories Detected
- **Spoofing** — tx.origin auth bypass, ecrecover malleability
- **Tampering** — delegatecall storage collision, selfdestruct
- **Repudiation** — insufficient event logging
- **Information Disclosure** — private on-chain variables
- **Denial of Service** — unbounded loops, block.timestamp manipulation
- **Elevation of Privilege** — unprotected initializers, onlyOwner centralization

### PASTA 7-Stage Process
1. Define Objectives
2. Define Technical Scope
3. Decompose Application
4. Analyze Threats (STRIDE)
5. Detect Vulnerabilities (MITRE ATT&CK mapping)
6. Enumerate Attacks (DREAD scoring)
7. Countermeasures

### API Endpoint
```http
POST /api/v1/intelligence/threat-model
{
  "source_code": "pragma solidity...",
  "target": "MyDeFiProtocol"
}
```

### CLI
```powershell
python cli.py threat-model --path ./contracts --target VaultProtocol
```

---

## 5. Module 4: SOC2 Type II + ISO 27001:2022 + SARIF 2.1 Compliance Engine

### Files
- `modules/compliance/sarif_v2.py` — SARIF 2.1.0 exporter
- `modules/compliance/soc2_mapper.py` — SOC2 TSC control mapper (12 controls)
- `modules/compliance/iso27001_mapper.py` — ISO 27001:2022 Annex A mapper (12 controls)

### SOC2 Controls Covered
`CC6.1` · `CC6.2` · `CC6.3` · `CC6.6` · `CC7.1` · `CC7.2` · `CC7.3` · `CC8.1` · `CC9.1` · `CC9.2` · `A1.1` · `PI1.1`

### ISO 27001:2022 Controls Covered
`A.5.7` · `A.5.23` · `A.8.2` · `A.8.9` · `A.8.16` · `A.8.25` · `A.8.26` · `A.8.27` · `A.8.29` · `A.8.33` · `A.12.6` · `A.16.1`

### SARIF 2.1.0 Compatibility
- GitHub Advanced Security (Code Scanning)
- Azure DevOps Security tab
- VS Code SARIF Viewer extension
- Splunk / Elastic SIEM (via sarif-to-syslog)

### API Endpoints
```http
POST /api/v1/compliance/report
{
  "findings": [...],
  "target": "MyProtocol",
  "frameworks": ["soc2", "iso27001", "sarif"]
}

GET /api/v1/compliance/sarif/{job_id}
```

### CLI
```powershell
python cli.py compliance-report --target MyProtocol --frameworks soc2,iso27001,sarif
```

---

## 6. Module 5: Live AI-ASOC Dashboard

### File: `frontend/src/pages/SOC.tsx`
### Route: `/soc`

Real-time security operations dashboard featuring:
- **WebSocket Threat Feed** — live push stream with severity filtering
- **MEV Attack Panel** — detected patterns with risk valuation and MITRE mapping
- **Compliance Gauges** — SOC2 and ISO 27001 compliance scores (0–100%)
- **Severity Heatmap** — event distribution by CRITICAL/HIGH/MEDIUM/LOW
- **Quick Action Links** — one-click access to Live Fork, Self-Healing, Threat Model

---

## 7. New API Endpoints Summary (Phase 2)

| Method | Path | Purpose |
|---|---|---|
| `WS` | `/ws/threat-stream` | Real-time event push stream |
| `GET` | `/api/v1/threat-stream/history` | Recent event history |
| `GET` | `/api/v1/threat-stream/stats` | Bus statistics |
| `POST` | `/api/v1/intelligence/mev-analyze` | MEV attack detection |
| `POST` | `/api/v1/intelligence/threat-model` | STRIDE+PASTA threat model |
| `POST` | `/api/v1/compliance/report` | SOC2/ISO27001/SARIF reports |
| `GET` | `/api/v1/compliance/sarif/{job_id}` | Export SARIF for audit job |

---

## 8. Test Coverage

```
tests/test_phase2_websocket.py    — 6  tests (pub/sub, fan-out, history, serialization)
tests/test_phase2_mev.py          — 7  tests (sandwich, flash loan, oracle, rug pull, multi-chain)
tests/test_phase2_threat_model.py — 10 tests (STRIDE categories, PASTA stages, attack paths, MITRE)
tests/test_phase2_compliance.py   — 22 tests (SARIF 2.1, SOC2, ISO27001, integration)
tests/test_phase2_api.py          — 13 tests (all new endpoints)
────────────────────────────────────────────────────────────────────────────────
Total Phase 2                     — 58 tests | 58 passed ✅
```
