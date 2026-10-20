# Adversum — Platform Architecture

> **Adversum** is an autonomous, AI-powered blockchain security platform designed to identify,
> triage, and remediate vulnerabilities in EVM-compatible smart contracts at production scale.

---

## Table of Contents

1. [Platform Overview](#1-platform-overview)
2. [C4 Architecture Diagrams](#2-c4-architecture-diagrams)
3. [Phase Breakdown](#3-phase-breakdown)
4. [Core Data Flow](#4-core-data-flow)
5. [Technology Stack](#5-technology-stack)
6. [Key API Endpoints](#6-key-api-endpoints)
7. [Deployment Guide](#7-deployment-guide)
8. [Observability & Metrics](#8-observability--metrics)
9. [Security Model](#9-security-model)
10. [Contribution Guide](#10-contribution-guide)

---

## 1. Platform Overview

Adversum provides a **five-phase autonomous security pipeline** for Web3 protocols:

| Phase | Name                          | Capability                                                        |
|-------|-------------------------------|-------------------------------------------------------------------|
| 1     | Static Analysis Engine        | Multi-tool parallel scanning (Slither, Semgrep, custom Rust)      |
| 2     | AI Triage & Enrichment        | Nebius LLM + Tavily threat-intel enrichment, false-positive reduction |
| 3     | Attack Chain Simulation       | Flashloan/oracle/reentrancy attack chain executor                 |
| 4     | Resilience Arena              | Circuit breaker synthesis, invariant evaluation, wargame sim       |
| 5     | Autonomous Threat Watchtower  | 24/7 EVM block streaming, real-time anomaly hunting               |

### Design Goals

- **Deterministic by default** — Rust-core analysis yields byte-reproducible results
- **AI-augmented, not AI-dependent** — graceful fallback when LLM unavailable
- **Enterprise-grade observability** — Prometheus metrics, structured JSON logs, health probes
- **Zero-trust API security** — API-key auth, rate limiting, CORS enforcement, payload caps

---

## 2. C4 Architecture Diagrams

### 2.1 Context Diagram (Level 1)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          External World                                  │
│                                                                         │
│   ┌──────────────┐    ┌─────────────────┐    ┌──────────────────────┐  │
│   │  Security    │    │   DeFi Protocol │    │  Blockchain Node     │  │
│   │  Analyst     │    │   Developer     │    │  (Ethereum/Base/…)   │  │
│   └──────┬───────┘    └────────┬────────┘    └──────────┬───────────┘  │
│          │                    │                          │              │
└──────────┼────────────────────┼──────────────────────────┼─────────────┘
           │  REST/WebSocket    │  REST API                │ RPC / WS
           ▼                    ▼                          ▼
    ┌─────────────────────────────────────────────────────────────┐
    │                    ADVERSUM PLATFORM                        │
    │           FastAPI Backend  +  React Frontend                │
    └─────────────────────────────────────────────────────────────┘
```

### 2.2 Container Diagram (Level 2)

```
┌────────────────────────────────────────────────────────────────────┐
│                        Adversum Platform                           │
│                                                                    │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │  React SPA   │   │ FastAPI      │   │  Rust Analysis Core  │  │
│  │  (Vite/TS)   │◄──│  Backend     │──►│  (FFI via ctypes)    │  │
│  │  port 5173   │   │  port 8000   │   │  libadversum.so      │  │
│  └──────────────┘   └──────┬───────┘   └──────────────────────┘  │
│                            │                                       │
│          ┌─────────────────┼──────────────────────┐               │
│          ▼                 ▼                       ▼               │
│  ┌──────────────┐  ┌──────────────┐   ┌──────────────────────┐   │
│  │  SQLite DB   │  │  Redis-like  │   │  Prometheus Metrics  │   │
│  │  (SQLModel/  │  │  In-Memory   │   │  /metrics endpoint   │   │
│  │  AsyncIO)    │  │  Result Cache│   │  (prometheus_client) │   │
│  └──────────────┘  └──────────────┘   └──────────────────────┘   │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  External Services                                           │ │
│  │  • Nebius AI  (nvidia/llama-3.1-nemotron-70b-instruct)      │ │
│  │  • Tavily     (real-time threat intelligence)                │ │
│  │  • Ethereum RPC nodes (public / private)                     │ │
│  └──────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────┘
```

### 2.3 Component Diagram (Level 3) — Backend

```
api/main.py (FastAPI Application)
│
├── orchestrator/
│   ├── pipeline/
│   │   └── analysis_pipeline.py      ← Scan orchestration
│   ├── models/
│   │   ├── findings.py               ← ValidatedFinding, RawFinding
│   │   └── sql_models.py             ← Job, FindingModel (SQLModel)
│   ├── services/
│   │   ├── db.py                     ← SQLite async engine + sessions
│   │   ├── nebius_llm.py             ← Nebius/Nemotron LLM client
│   │   ├── threat_intel.py           ← Tavily enrichment client
│   │   ├── threat_stream.py          ← Event bus (pub/sub)
│   │   └── self_healing.py           ← TriPartite remediation engine
│   ├── scanner/
│   │   ├── project_scanner.py        ← File discovery, git clone
│   │   └── fallback_engine.py        ← Python regex fallback
│   ├── reasoning/
│   │   ├── ai_validator.py           ← LLM-based validation
│   │   └── deterministic_validator.py← Rule-based validation
│   ├── core_bridge/
│   │   └── core_wrapper.py           ← Rust FFI bridge
│   └── reporting/
│       └── report_generator.py       ← PDF/Markdown report gen
│
├── modules/
│   ├── live_fork/
│   │   └── engine.py                 ← Foundry/Hardhat fork simulation
│   ├── attack_chain/
│   │   └── executor.py               ← Flashloan/oracle attack sim
│   ├── defi_risk/
│   │   └── scorer.py                 ← DeFi protocol risk scoring
│   ├── resilience/
│   │   ├── arena.py                  ← Wargame incident simulation
│   │   ├── circuit_breaker.py        ← Solidity circuit breaker synth
│   │   └── invariant_evaluator.py    ← 10 DeFi invariant checks
│   └── threat_hunter/
│       └── daemon.py                 ← 24/7 autonomous EVM watcher
│
├── api/
│   └── security.py                   ← Path validation, git URL check
│
└── core/                             ← Rust crate (cargo)
    └── src/
        ├── lib.rs                    ← FFI exports
        ├── scanner.rs                ← AST + pattern matching
        └── validators.rs             ← Deterministic rule engine
```

---

## 3. Phase Breakdown

### Phase 1 — Multi-tool Static Analysis

The entry point for every audit. Adversum orchestrates parallel scanning via:

- **Rust Core** (`libadversum`) — custom AST walker with pre-compiled byte-pattern queries (10–50× faster than Python regex)
- **Slither integration** — Solidity-aware dataflow analysis via subprocess
- **Semgrep** — configurable rule sets for ERC20/ERC721/DeFi patterns
- **Python Fallback Engine** — activated when Rust FFI is unavailable; uses compiled regex

All findings are normalized to `RawFinding` then deduplicated and stored via `SQLModel` in SQLite.

### Phase 2 — AI Triage & Threat Intelligence

Each raw finding passes through:

1. **Deterministic Validator** — rule-based confidence scoring (default, reproducible)
2. **Nebius LLM Validator** (optional) — `nvidia/llama-3.1-nemotron-70b-instruct` for contextual false-positive reduction
3. **Tavily Enrichment** (optional) — real-time search for CVE references, exploit PoCs, similar protocol hacks

Output: `ValidatedFinding` with severity, confidence, remediation suggestion, and CVSS-like score.

### Phase 3 — Attack Chain Simulation

Simulates adversarial exploitation paths for confirmed high/critical findings:

- **Flashloan Drain** — models capital amplification attacks against AMMs
- **Oracle Desynchronization** — TWAP manipulation scenarios
- **Reentrancy Wave** — recursive call exploitation
- **Bridge Forgery** — cross-chain message validation bypass

Each simulation returns estimated USD exposure and attack chain sequence.

### Phase 4 — Resilience Arena & Circuit Breaker Synthesis

Wargame-style adversarial stress testing:

- **ResilienceArena** — runs multi-scenario benchmarks and tracks outcome history
- **CircuitBreakerSynthesizer** — generates tailor-made `CircuitBreakerGuard.sol` with configurable:
  - TVL outflow thresholds per time window
  - Oracle divergence caps
  - Flash loan detection
  - Emergency multisig integration
- **AdversarialInvariantEvaluator** — validates source code against 10 critical DeFi invariants

### Phase 5 — Autonomous Threat Hunting Watchtower

Continuous 24/7 EVM monitoring:

- **ThreatHuntingDaemon** — subscribes to real-time block events via RPC
- Detects anomalous on-chain patterns: large transfers, unusual gas, re-entrancy traces
- Emits structured events through the **ThreatStream EventBus** (internal pub/sub)
- Findings persisted with block number, tx hash, threat type, and confidence score

---

## 4. Core Data Flow

```
Developer / Analyst
       │
       │  POST /api/v1/scan  { path | git_url }
       ▼
┌─────────────────────────────────────────────────────────┐
│  FastAPI Route Handler                                  │
│  1. Validate API key (x-api-key header)                 │
│  2. Validate path / git URL (security.py)               │
│  3. Create Job record in SQLite                         │
│  4. Dispatch background task                            │
└───────────────────────┬─────────────────────────────────┘
                        │ (async background)
                        ▼
┌─────────────────────────────────────────────────────────┐
│  AnalysisPipeline.run()                                 │
│                                                         │
│  ① ProjectScanner.scan()          → file list + hashes │
│  ② Incremental Check (XXH3)       → skip unchanged     │
│  ③ CoreWrapper.analyze()          → RawFinding[]        │
│     └── Rust FFI or Python fallback                     │
│  ④ Validator.validate()           → ValidatedFinding[]  │
│     └── Deterministic or LLM                            │
│  ⑤ Nebius LLM batch (optional)   → enriched findings   │
│  ⑥ Tavily enrichment (optional)  → CVE refs, PoCs      │
│  ⑦ ReportGenerator.generate()    → Markdown/PDF report │
│  ⑧ Store findings in SQLite                            │
│  ⑨ Update Job.status = completed                       │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
          GET /api/v1/jobs/{job_id}/findings
                        │
                        ▼
        ┌───────────────────────────┐
        │  Optional Post-processing │
        │  • Attack chain simulation│
        │  • PR / patch generation  │
        │  • Executive summary      │
        └───────────────────────────┘
```

---

## 5. Technology Stack

| Layer              | Technology                                 | Purpose                                |
|--------------------|--------------------------------------------|----------------------------------------|
| **API**            | Python 3.11 + FastAPI + Uvicorn            | Async REST API framework               |
| **Frontend**       | React 18 + TypeScript + Vite               | Developer dashboard SPA                |
| **Analysis Core**  | Rust (cargo) + ctypes FFI                  | High-performance pattern matching      |
| **Database**       | SQLite + SQLModel + AsyncIO                | Persistent job/finding storage         |
| **LLM**            | Nebius AI (Nemotron-70B)                   | AI triage and false-positive reduction |
| **Threat Intel**   | Tavily Search API                          | Real-time CVE / exploit enrichment     |
| **Metrics**        | prometheus_client                          | `/metrics` Prometheus scrape endpoint  |
| **Rate Limiting**  | slowapi                                    | Per-IP API rate limiting               |
| **Auth**           | FastAPI APIKeyHeader                       | x-api-key header authentication        |
| **Containerization** | Docker + Docker Compose                  | Local & cloud deployment               |
| **CI/CD**          | GitHub Actions                             | Lint, test, security audit             |
| **JSON (fast)**    | orjson (fallback: stdlib json)             | 5–10× faster serialization             |

---

## 6. Key API Endpoints

### Health & Readiness

| Method | Path              | Description                                          |
|--------|-------------------|------------------------------------------------------|
| GET    | `/health/live`    | Kubernetes liveness probe                            |
| GET    | `/health/ready`   | Deep readiness: DB latency, cache, queue, hunter     |

### Scan Lifecycle

| Method | Path                            | Description                            |
|--------|---------------------------------|----------------------------------------|
| POST   | `/api/v1/scan`                  | Start a new smart contract audit       |
| GET    | `/api/v1/jobs`                  | List all audit jobs                    |
| GET    | `/api/v1/jobs/{id}`             | Get job status and metadata            |
| GET    | `/api/v1/jobs/{id}/findings`    | Retrieve validated findings            |
| GET    | `/api/v1/jobs/{id}/report`      | Download full audit report             |

### AI & Enrichment

| Method | Path                                    | Description                              |
|--------|-----------------------------------------|------------------------------------------|
| POST   | `/api/v1/ai/validate`                   | LLM batch finding validation             |
| POST   | `/api/v1/ai/executive-summary`          | Generate executive security summary      |
| GET    | `/api/v1/ai/attack-graph`               | Generate attack graph hypothesis         |
| GET    | `/api/v1/ai/status`                     | Nebius + Tavily availability status      |

### Attack Chain Simulation (Phase 3)

| Method | Path                                    | Description                              |
|--------|-----------------------------------------|------------------------------------------|
| POST   | `/api/v1/simulate/attack-chain`         | Execute simulated attack sequence        |
| GET    | `/api/v1/simulate/risk-score`           | Compute DeFi protocol risk score         |

### Resilience Arena (Phase 4)

| Method | Path                                        | Description                          |
|--------|---------------------------------------------|--------------------------------------|
| POST   | `/api/v1/wargame/simulate-incident`         | Adversarial incident clash sim       |
| POST   | `/api/v1/wargame/synthesize-circuit-breaker`| Generate Solidity CircuitBreakerGuard|
| GET    | `/api/v1/wargame/resilience-benchmark`      | Multi-scenario benchmark run         |
| POST   | `/api/v1/wargame/evaluate-invariants`       | Evaluate 10 DeFi invariants          |

### Threat Hunter (Phase 5)

| Method | Path                              | Description                              |
|--------|-----------------------------------|------------------------------------------|
| POST   | `/api/v1/hunter/start`            | Start autonomous block watcher           |
| POST   | `/api/v1/hunter/stop`             | Stop autonomous block watcher            |
| GET    | `/api/v1/hunter/status`           | Hunter operational metrics               |
| GET    | `/api/v1/hunter/findings`         | Recent autonomous detections             |
| POST   | `/api/v1/hunter/scan-block`       | Manually scan a specific block           |

### Observability

| Method | Path        | Description                                 |
|--------|-------------|---------------------------------------------|
| GET    | `/metrics`  | Prometheus scrape endpoint (counters, hists) |

---

## 7. Deployment Guide

### 7.1 Local Development

```bash
# 1. Install dependencies
make install-dev

# 2. Configure environment
cp .env.example .env
# Edit .env: set NEBIUS_API_KEY, TAVILY_API_KEY, API_KEY

# 3. Start backend + frontend
make dev

# 4. Run tests
make test

# 5. Lint & format
make lint
make format
```

### 7.2 Docker Compose (Recommended for staging)

```yaml
# docker-compose.yml (excerpt)
services:
  backend:
    build:
      context: .
      dockerfile: Dockerfile.backend
    ports:
      - "8000:8000"
    environment:
      - API_KEY=${API_KEY}
      - NEBIUS_API_KEY=${NEBIUS_API_KEY}
      - TAVILY_API_KEY=${TAVILY_API_KEY}
    volumes:
      - ./adversum_local.db:/app/adversum_local.db

  frontend:
    build:
      context: ./frontend
    ports:
      - "80:80"
    depends_on:
      - backend
```

```bash
make docker-build
make docker-up
# Services available at:
#   API:      http://localhost:8000
#   Frontend: http://localhost:80
#   Metrics:  http://localhost:8000/metrics
make docker-down
```

### 7.3 Nebius Cloud / Kubernetes

For production deployment on **Nebius AI Cloud** (recommended for GPU-accelerated LLM inference):

```yaml
# deploy/k8s/deployment.yaml (excerpt)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: adversum-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: adversum-backend
  template:
    spec:
      containers:
        - name: backend
          image: ghcr.io/adversum/backend:latest
          ports:
            - containerPort: 8000
          env:
            - name: API_KEY
              valueFrom:
                secretKeyRef:
                  name: adversum-secrets
                  key: api-key
          livenessProbe:
            httpGet:
              path: /health/live
              port: 8000
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /health/ready
              port: 8000
            initialDelaySeconds: 15
            periodSeconds: 10
```

**Nebius-specific configuration:**
- Use `NEBIUS_API_KEY` with Nebius AI Studio endpoint
- LLM model: `nvidia/llama-3.1-nemotron-70b-instruct` (served on Nebius GPU cluster)
- Set `NEBIUS_BASE_URL=https://api.studio.nebius.ai/v1/`

---

## 8. Observability & Metrics

Adversum exposes the following Prometheus metrics at `GET /metrics`:

| Metric                              | Type      | Description                          |
|-------------------------------------|-----------|--------------------------------------|
| `adversum_http_requests_total`      | Counter   | Total HTTP requests (method/path/status) |
| `adversum_http_errors_total`        | Counter   | Total 5xx errors by path             |
| `adversum_http_duration_seconds`    | Histogram | Request latency (buckets: 10ms–5s)   |
| `adversum_scans_total`              | Counter   | Total audit scans started            |
| `adversum_findings_total`           | Counter   | Total findings by severity           |

### Health Probe Response (`GET /health/ready`)

```json
{
  "status": "ready",
  "ready": true,
  "version": "5.0.0",
  "uptime_s": 3600.0,
  "checks": {
    "api": "ok",
    "database": { "status": "ok", "latency_ms": 1.2 },
    "cache": { "status": "ok", "size": 42, "hit_rate": 0.85 },
    "job_queue": { "status": "ok", "queue_size": 0, "active": 0 },
    "threat_hunter": { "status": "idle", "blocks_scanned": 0 }
  }
}
```

---

## 9. Security Model

### API Authentication

All endpoints (except `/health/*` and `/metrics`) require:

```
x-api-key: <your-api-key>
```

Set `API_KEY` in `.env` or environment. Default dev key: `adv-dev-key-123`.

### Path Validation

The `api/security.py` module enforces:
- Path traversal prevention (blocks `../`, absolute paths outside project)
- Git URL allowlist (only `https://` GitHub/GitLab URLs)
- Payload size cap: 25 MB (`MAX_REQUEST_BODY_BYTES`)

### Rate Limiting

Per-IP rate limiting via `slowapi`:
- Default: configurable per endpoint
- Returns HTTP 429 on limit breach

### CORS

Configured via `ALLOWED_ORIGINS` env var. Defaults to `localhost:3000` and `localhost:5173` (dev only). **Set explicitly in production.**

### Supply Chain Security

```bash
# Audit Python dependencies
make audit-security

# GitHub Actions security workflow
# .github/workflows/security.yml → pip-audit + npm audit on every PR
```

---

## 10. Contribution Guide

### Getting Started

```bash
git clone https://github.com/your-org/adversum.git
cd adversum
make install-dev
cp .env.example .env
```

### Branching Strategy

```
main          ← production-ready, protected
├── feat/*    ← new features
├── fix/*     ← bug fixes
├── chore/*   ← tooling, deps, docs
└── test/*    ← test additions only
```

### Commit Convention (Conventional Commits)

```
feat(phase5): add autonomous block hunter daemon
fix(api): handle missing x-api-key gracefully
chore(deps): bump ruff to 0.17.1
docs(arch): update C4 container diagram
test(phase3): add attack chain simulation coverage
```

### Pre-commit Checks

```bash
make lint       # ruff + eslint
make test       # full pytest suite (165 tests)
make format     # ruff format
```

### Adding a New Endpoint

1. Add route in `api/main.py` with appropriate tag
2. Add Pydantic request/response models
3. Write tests in `tests/test_phase<N>_*.py`
4. Update this ARCHITECTURE.md with endpoint table entry
5. Run `make check-all` before opening a PR

### Test Structure

```
tests/
├── test_phase1_*.py    ← Static analysis + pipeline
├── test_phase2_*.py    ← AI triage + enrichment
├── test_phase3_*.py    ← Attack chain simulation
├── test_phase4_*.py    ← Resilience arena
├── test_phase5_api.py  ← Threat hunter + health probes
└── conftest.py         ← Shared fixtures
```

All tests run with `NEBIUS_MOCK=1` to avoid real LLM calls. 165 tests must remain green on every PR.

---

*Last updated: 2026-10 | Adversum Platform v5.0.0*
