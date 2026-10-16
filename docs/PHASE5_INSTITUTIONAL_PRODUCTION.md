# Phase 5 — Institutional Production Stack & Autonomous Threat Watchtower

## Overview

Phase 5 achieves institutional maturity for Adversum through:
1. **Autonomous 24/7 Threat Hunting Watchtower** (`modules/threat_hunter/`):
   - Continuous EVM block and mempool triage.
   - Heuristics detection for unverified delegatecall proxies, selfdestruct opcodes, tx.origin phishing traps, and metamorphic CREATE2 factories.
   - Autonomous alert stream integration with the SOC live dashboard.
2. **1-Click Multi-Container Production Stack**:
   - Production Docker Compose configuration orchestrating:
     - `backend`: FastAPI with Uvicorn multi-workers
     - `frontend`: Multi-stage build served via Nginx with WebSocket upgrade proxying
     - `redis`: High performance pub/sub message broker
     - `anvil`: Local isolated EVM fork execution node
   - Deployment automation for Windows (`deploy.ps1`) and Linux/macOS/Cloud (`deploy.sh`).
   - Deep enterprise healthcheck and Kubernetes readiness probes (`/health/ready` & `/health/live`).

---

## 1-Click Deployment

### Windows (PowerShell)
```powershell
# Launch full institutional stack and run readiness check
.\deploy.ps1

# View live container logs
.\deploy.ps1 -Logs

# Stop stack
.\deploy.ps1 -Down
```

### Linux / macOS / Cloud (Bash)
```bash
# Launch full institutional stack and run readiness check
./deploy.sh

# Build fresh containers
./deploy.sh --build

# View logs or shutdown
./deploy.sh --logs
./deploy.sh --down
```

---

## Service Endpoints in Production

| Service | Host Port | Internal Routing | Description |
|---|---|---|---|
| **Frontend Web UI** | `80` | `http://localhost/` | Vite SPA served by Nginx |
| **SOC Dashboard** | `80` | `http://localhost/soc` | Real-time threat feed & MEV panel |
| **Adversum War Room** | `80` | `http://localhost/war-room` | Attack Replay, Resilience Arena, Risk Matrix |
| **Backend REST API** | `8000` | `http://localhost:8000/api/` | FastAPI REST services & Swagger docs |
| **WebSocket Threat Stream** | `80` / `8000` | `ws://localhost/ws/threat-stream` | Real-time streaming WebSocket event bus |
| **Foundry Anvil EVM** | `8545` | `http://localhost:8545` | Isolated local mainnet fork engine |
| **Redis Broker** | `6379` | `redis://localhost:6379` | Pub/sub event broker & cache |

---

## Autonomous Threat Hunting CLI

```bash
# Scan recent 10 blocks on Ethereum mainnet
python cli.py hunt --chain ethereum --blocks 10

# Inspect Threat Hunter daemon status
python cli.py hunt --status
```

---

## Quality & Test Status

- **148 / 148 total Python test cases passed (100%)**
- **23 / 23 Rust Core test cases passed (100%)**
- **Frontend build**: 2,428 modules transformed with 0 errors.
