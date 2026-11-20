# Adversum Frontend

React 18 + Vite + TypeScript + Tailwind CSS dashboard for the Adversum
security engine (audit launch, SOC view, war room, analytics).

## Run

```bash
npm install
npm run dev        # http://localhost:5173 (expects API on :8000)
npm run build
npx tsc --noEmit   # typecheck, must stay at 0 errors
npm run lint
```

## Structure

- `src/pages/` — audit home, SOC dashboard, war room, analytics
- `src/components/` — audit orb, findings, attack-flow and arena views
- Findings carry `z3_verdict` / provenance badges; simulated exploit
  results are labelled `SIMULATED_NOT_AN_ONCHAIN_PROOF` (P3) and must
  never be rendered as on-chain proof.
