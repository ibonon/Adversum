#!/usr/bin/env python3
"""Versioned throughput benchmark (P4): lines/second of the native scanner.

Replaces the unversioned "12,500 lines/sec" claim with a measurement
tied to a git SHA, corpus and machine-readable output:

    python benchmarks/run_throughput.py
    python benchmarks/run_throughput.py --target modules/solidity/tests/test_contracts
"""
from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "modules" / "solidity"))

BENCHMARK_VERSION = "throughput-v1"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default=str(ROOT / "benchmarks" / "corpus"))
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--out", default=str(ROOT / "benchmarks" / "results" / "throughput_v1.json"))
    args = ap.parse_args(argv)

    from scanner import SolidityScanner
    import rules as rules_pkg

    target = Path(args.target)
    files = sorted(target.rglob("*.sol")) if target.is_dir() else [target]
    total_lines = sum(len(p.read_text(encoding="utf-8", errors="replace").splitlines()) for p in files)
    scanner = SolidityScanner(rules_pkg, str(ROOT / "modules/solidity/kb/vulnerabilities.json"),
                              enable_slither=False, enable_aderyn=False)
    best = None
    for _ in range(max(1, args.repeat)):
        start = time.perf_counter()
        for p in files:
            scanner.scan_file(str(p))
        elapsed = time.perf_counter() - start
        best = elapsed if best is None else min(best, elapsed)
    try:
        sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                             capture_output=True, text=True, timeout=10).stdout.strip() or "unknown"
    except Exception:
        sha = "unknown"
    report = {
        "benchmark_version": BENCHMARK_VERSION,
        "git_sha": sha,
        "target": str(target),
        "files": len(files),
        "total_lines": total_lines,
        "best_seconds": round(best, 4),
        "lines_per_second": round(total_lines / best, 1) if best else 0.0,
        "engine": "Adversum native Solidity rules (single-threaded Python)",
        "python": platform.python_version(),
        "platform": platform.platform(),
    }
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"{BENCHMARK_VERSION}: {report['lines_per_second']} lines/sec "
          f"({total_lines} lines, {len(files)} files, best of {args.repeat}) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
