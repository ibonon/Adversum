# Phase 3 — Cross-Protocol Economic Attack Simulator & Visual War Room

## Overview

Phase 3 transforms Adversum into the **world's first DeFi attack simulation platform** combining:
- **Multi-step economic attack chain execution** with cascade propagation
- **5 real-world hack scenarios** (Euler, Ronin, Mango, Wormhole, Generic)
- **DeFi Risk Matrix** scoring 8 protocols × 6 attack vectors
- **Visual War Room** with animated attack flow graph + timeline replay

---

## Architecture

```
modules/attack_simulator/
├── __init__.py
├── chain_executor.py          # Core simulation engine
├── risk_scorer.py             # DeFi economic risk scoring
└── scenarios/
    ├── __init__.py            # SCENARIO_REGISTRY
    ├── euler_finance.py       # $197M — donateToReserves
    ├── ronin_bridge.py        # $625M — validator key compromise
    ├── mango_markets.py       # $116M — oracle price pump
    ├── wormhole.py            # $320M — fake VAA signature
    └── generic_flashloan_cascade.py  # Configurable template

frontend/src/
├── pages/WarRoom.tsx          # Main War Room page (/war-room)
└── components/
    ├── AttackFlow.tsx         # @xyflow/react animated graph
    ├── AttackTimeline.tsx     # Step-by-step horizontal timeline
    └── RiskMatrix.tsx         # Protocol × vector risk matrix
```

---

## API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/api/v1/simulator/run-attack` | Execute a named attack scenario |
| `GET`  | `/api/v1/simulator/scenarios` | List all available scenarios |
| `GET`  | `/api/v1/simulator/replay/{id}` | Replay a completed simulation |
| `POST` | `/api/v1/simulator/risk-score` | Score a protocol economically |
| `GET`  | `/api/v1/simulator/history` | Session simulation history |
| `GET`  | `/api/v1/simulator/risk-matrix` | Full protocol × vector matrix |

---

## Real-World Scenarios

| Scenario | Loss | Key Vectors |
|----------|------|-------------|
| Euler Finance | $197M | Flash Loan + Accounting Bug + Self-Liquidation |
| Ronin Bridge | $625M | Validator Key Compromise + Bridge Drain |
| Mango Markets | $116M | Oracle Price Pump + Governance Vote |
| Wormhole | $320M | Fake VAA + Unbacked Mint |
| Generic Flash Loan Cascade | Configurable | Flash Loan + Oracle + Liquidation + Bridge |

**Total simulated loss across all scenarios: $1.358 Billion**

---

## Attack Primitives

| Primitive | MITRE ATT&CK |
|-----------|--------------|
| `FLASH_LOAN` | T1078 — Valid Accounts |
| `ORACLE_MANIP` | T1565.001 — Stored Data Manipulation |
| `LIQUIDATION` | T1499 — Endpoint Denial of Service |
| `BRIDGE_DRAIN` | T1190 — Exploit Public-Facing Application |
| `GOVERNANCE_VOTE` | T1078.004 — Cloud Accounts |
| `PRICE_PUMP` | T1565 — Data Manipulation |
| `UNBACKED_MINT` | T1036 — Masquerading |
| `DONATE_ATTACK` | T1499.004 — Application Exhaustion |
| `REPAY_FLASH` | T1070 — Indicator Removal |

---

## Risk Scoring

6 attack vectors scored 0–100 per protocol:
- **Oracle Manipulation** (weight: 20%)
- **Flash Loan Attack** (weight: 15%)
- **Cross-Chain Bridge** (weight: 15%)
- **Governance Takeover** (weight: 15%)
- **Liquidity Concentration** (weight: 15%)
- **Smart Contract Exploit** (weight: 20%)

Grades: A (<20) B (<40) C (<60) D (<75) F (≥75)

---

## Cascade Propagation

When a simulation drains >$1M from a known protocol, the engine automatically
identifies downstream protocols that may be impacted:

```
Euler Finance → Compound, Aave, Balancer
Ronin Bridge  → Axie Infinity, Sky Mavis
Wormhole      → Solana DeFi, Portal Bridge
```

---

## Tests

```
tests/test_phase3_simulator.py     — 33 tests (chain executor + scenarios + risk scorer)
tests/test_phase3_api.py           — 13 tests (all 6 API endpoints)
tests/test_phase3_poc_integration.py — 8 tests (PoC generator integration)
Total: 54 new tests
```

---

## War Room Features

- **Scenario Selector** — 5 pre-built + configurable generic
- **KPI Strip** — Protocol Loss, Attacker Profit, Gas Cost, Blocks, Risk Index, Cascade
- **Attack Flow Graph** — animated @xyflow/react graph with typed nodes (attacker/flashloan/target/bridge/oracle/victim)
- **Timeline Replay** — step-by-step horizontal replay with auto-advance (1.2s per step)
- **MITRE ATT&CK badge strip** — per simulation
- **Cascade Alert** — highlights downstream protocols at risk
- **Risk Matrix Tab** — protocol × vector color-coded risk table

---

## Commit

`feat(phase3): Cross-Protocol Attack Simulator + Visual War Room [119/119 tests pass]`
