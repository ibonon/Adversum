#!/usr/bin/env python3
"""Versioned anti-hallucination eval for the LLM layer (P2).

Recorded Nemotron hypotheses (including deliberately wrong line
numbers, as observed live in KNOWN_LIMITATIONS §8) are replayed
through the deterministic anchoring + Z3 pipeline. The LLM is never
trusted for positions: a hypothesis counts as correct only when the
anchor resolves it to the real line and Z3 returns the expected
verdict. Runs fully offline; ``--live`` additionally exercises the
real Nebius generation path when a key is configured.

    python benchmarks/run_llm_eval.py
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cases", default=str(ROOT / "benchmarks" / "llm_eval_cases.json"))
    ap.add_argument("--out", default=str(ROOT / "benchmarks" / "results" / "llm_eval.json"))
    ap.add_argument("--live", action="store_true", help="Also call the live Nebius hypothesis generator.")
    args = ap.parse_args(argv)

    from modules.formal_verification import z3_prover as z3p
    from modules.solidity.overflow_anchor import anchor_hypothesis

    cases = json.loads(Path(args.cases).read_text(encoding="utf-8"))
    results = []
    for case in cases:
        source = case.get("source")
        if source is None:
            source = (ROOT / case["file"]).read_text(encoding="utf-8")
        anchored = anchor_hypothesis(case["hypothesis"], source)
        verdict = None
        if anchored["anchor_status"] == "ANCRAGE_OK" and anchored.get("z3_finding"):
            verdict = z3p.prove_finding_in_source(anchored["z3_finding"], source)["verdict"]
        ok = anchored["anchor_status"] == case["expected_anchor_status"]
        if case.get("expected_resolved_line") is not None:
            ok = ok and anchored.get("resolved_line") == case["expected_resolved_line"]
        if case.get("expected_verdict") is not None:
            ok = ok and verdict == case["expected_verdict"]
        results.append({"id": case["id"], "ok": ok,
                        "anchor_status": anchored["anchor_status"],
                        "resolved_line": anchored.get("resolved_line"),
                        "verdict": verdict})
        print(f"{'PASS' if ok else 'FAIL'} {case['id']}: anchor={anchored['anchor_status']} "
              f"line={anchored.get('resolved_line')} verdict={verdict}")
    passed = sum(1 for r in results if r["ok"])
    report = {"cases": len(results), "passed": passed,
              "accuracy_percent": round(100.0 * passed / len(results), 1) if results else 0.0,
              "mode": "recorded-hypotheses (offline)" + (" + live" if args.live else ""),
              "results": results}
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"llm-eval: {passed}/{len(results)} ({report['accuracy_percent']}%) -> {args.out}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
