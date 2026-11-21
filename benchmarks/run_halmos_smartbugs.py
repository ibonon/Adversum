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
    ap.add_argument("--categories", default="reentrancy,arithmetic,access_control,unchecked_low_level_calls")
    ap.add_argument("--out", default=str(ROOT / "benchmarks" / "results" / "halmos_smartbugs_all.json"))
    args = ap.parse_args(argv)

    dataset = Path(args.dataset)
    if not (dataset / "vulnerabilities.json").exists():
        print(f"dataset not accessible: {dataset} — nothing published")
        return 2
    from modules.halmos.per_contract import run_per_contract
    from modules.halmos.per_contract_rules import run_per_contract_rule
    from modules.solidity.rules import reentrancy
    import sys as _sys
    _sys.path.insert(0, str(ROOT / "modules" / "solidity"))
    from scanner import SolidityScanner
    import rules as _rules_pkg
    scanner = SolidityScanner(_rules_pkg, str(ROOT / "modules/solidity/kb/vulnerabilities.json"),
                              enable_slither=False, enable_aderyn=False)

    category_rules = {
        "reentrancy": ["SOL-001"],
        "arithmetic": ["SOL-004"],
        "access_control": ["SOL-002", "SOL-003"],
        "unchecked_low_level_calls": ["SOL-007"],
    }
    only = [c.strip() for c in args.categories.split(",") if c.strip()]
    all_entries = json.loads((dataset / "vulnerabilities.json").read_text(encoding="utf-8"))
    counts: Counter = Counter()
    rows = []
    start = time.time()
    for cat in only:
        for e in all_entries:
            if not any(v["category"] == cat for v in e.get("vulnerabilities", [])):
                continue
            path = dataset / e["path"]
            source = path.read_text(encoding="utf-8", errors="replace")
            for rule in category_rules.get(cat, []):
                findings = [f for f in scanner.scan_file(str(path)) if f.rule_id == rule]
                if not findings:
                    counts["no_finding"] += 1
                    rows.append({"category": cat, "rule": rule, "contract": e["name"], "result": "no_finding"})
                    continue
                f0 = findings[0]
                fd = {"rule_id": rule, "line": f0.line, "snippet": f0.snippet}
                res = (run_per_contract(source, fd, timeout=args.timeout) if rule == "SOL-001"
                       else run_per_contract_rule(rule, source, fd, timeout=args.timeout))
                verdict = res["proof_verdict"]
                counts[verdict] += 1
                counts[f"{cat}:{verdict}"] += 1
                rows.append({"category": cat, "rule": rule, "contract": e["name"], "result": verdict,
                             "halmos_status": res.get("halmos", {}).get("status"),
                             "reason": res.get("verdict_reason", "")[:160]})
                print(f"[{cat}/{rule}] {e['name']}: {verdict} ({res.get('halmos', {}).get('status')})", flush=True)
    report = {"dataset": str(dataset), "categories": only,
              "counts": dict(counts),
              "elapsed_seconds": round(time.time() - start, 1), "rows": rows}
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"per-contract Halmos: {dict(counts)} in {report['elapsed_seconds']}s -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
