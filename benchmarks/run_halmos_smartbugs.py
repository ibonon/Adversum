#!/usr/bin/env python3
"""Per-contract Halmos measurement on SmartBugs reentrancy (pipeline branching).

For every SmartBugs contract labelled `reentrancy`, takes the first
SOL-001 finding of the native rules and runs the per-contract Halmos
harness generated from the *actual* source. Publishes how many become
PROVEN, how many stay DETECTED_UNPROVEN (no drain in bounds), and how
many are UNKNOWN (unsupported shape, compile/tool limits) — the
UNKNOWN rate is reported, never hidden.

    python benchmarks/run_halmos_smartbugs.py
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "modules" / "solidity"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default=r"C:\Users\SMC-DXB\Projects\adversum-bench\smartbugs-curated")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--out", default=str(ROOT / "benchmarks" / "results" / "halmos_smartbugs_reentrancy.json"))
    args = ap.parse_args(argv)

    dataset = Path(args.dataset)
    if not (dataset / "vulnerabilities.json").exists():
        print(f"dataset not accessible: {dataset} — nothing published")
        return 2
    from modules.halmos.per_contract import run_per_contract
    from modules.solidity.rules import reentrancy

    entries = [e for e in json.loads((dataset / "vulnerabilities.json").read_text(encoding="utf-8"))
               if any(v["category"] == "reentrancy" for v in e.get("vulnerabilities", []))]
    counts: Counter = Counter()
    rows = []
    start = time.time()
    for e in entries:
        path = dataset / e["path"]
        source = path.read_text(encoding="utf-8", errors="replace")
        findings = reentrancy.analyze(source)
        if not findings:
            counts["no_finding"] += 1
            rows.append({"contract": e["name"], "result": "no_finding"})
            continue
        res = run_per_contract(source, findings[0], timeout=args.timeout)
        verdict = res["proof_verdict"]
        counts[verdict] += 1
        rows.append({"contract": e["name"], "result": verdict,
                     "halmos_status": res.get("halmos", {}).get("status"),
                     "reason": res.get("verdict_reason", "")[:160]})
        print(f"{e['name']}: {verdict} ({res.get('halmos', {}).get('status')})", flush=True)
    report = {"dataset": str(dataset), "category": "reentrancy",
              "contracts": len(entries), "counts": dict(counts),
              "elapsed_seconds": round(time.time() - start, 1), "rows": rows}
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"reentrancy per-contract Halmos: {dict(counts)} over {len(entries)} contracts "
          f"in {report['elapsed_seconds']}s -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
