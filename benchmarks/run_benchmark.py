#!/usr/bin/env python3
"""Reproducible SmartBugs / DAppSCAN-style benchmark for Adversum (P0).

Replays the native Solidity rules against a labelled dataset and emits
contract-level precision/recall/F1 per SmartBugs category *and* per CWE,
plus line-level recall. This replaces the historical, non-replayed
numbers in BENCHMARK.md: every figure published from now on must be
regenerable with:

    python benchmarks/run_benchmark.py
    python benchmarks/run_benchmark.py --dataset /path/to/smartbugs-curated
    python benchmarks/run_benchmark.py --dataset /path/to/dappscan --format dappscan

Dataset layouts supported:
- SmartBugs curated: ``vulnerabilities.json`` (list of
  ``{name, path, vulnerabilities: [{lines, category}]}``) + ``.sol`` files.
- DAppSCAN / generic manifest: ``labels.json`` (list of
  ``{file, vulnerabilities: [{lines, category}]}``) next to the files.
- Bundled smoke corpus (default when no external dataset is found):
  ``benchmarks/corpus`` + ``benchmarks/labels.json``. Small and fully
  offline so CI always replays *something* deterministic.

Exit code is 0 unless ``--fail-under-f1`` is given and macro-F1 is below
it. Engine under test: Adversum native rules only (Slither/Aderyn off),
so the result measures this repository, not external binaries.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "modules" / "solidity"))

CATEGORY_RULES = {
    "access_control": ["SOL-002", "SOL-003"],
    "arithmetic": ["SOL-004"],
    "bad_randomness": ["SOL-006", "SOL-011"],
    "denial_of_service": ["SOL-013"],
    "front_running": ["SOL-009"],
    "other": [],
    "reentrancy": ["SOL-001"],
    "short_addresses": [],
    "time_manipulation": ["SOL-006"],
    "unchecked_low_level_calls": ["SOL-007"],
}
CATEGORY_CWE = {
    "access_control": "CWE-284",
    "arithmetic": "CWE-190",
    "bad_randomness": "CWE-330",
    "denial_of_service": "CWE-770",
    "front_running": "CWE-362",
    "reentrancy": "CWE-841",
    "short_addresses": "CWE-371",
    "time_manipulation": "CWE-330",
    "unchecked_low_level_calls": "CWE-252",
    "other": "",
}


def _git_sha() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
            capture_output=True, text=True, timeout=10,
        ).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _load_kb_cwe() -> dict:
    kb = json.loads((ROOT / "modules/solidity/kb/vulnerabilities.json").read_text(encoding="utf-8"))
    return {v["id"]: v.get("cwe", "") for v in kb.get("vulnerabilities", [])}


def load_dataset(dataset: Path, fmt: str):
    """Return [{name, path(Path), vulnerabilities:[{lines, category}]}]."""
    if fmt == "smartbugs" or (dataset / "vulnerabilities.json").exists():
        raw = json.loads((dataset / "vulnerabilities.json").read_text(encoding="utf-8"))
        return [
            {"name": e["name"], "path": dataset / e["path"],
             "vulnerabilities": e.get("vulnerabilities", [])}
            for e in raw
        ]
    labels = dataset / "labels.json"
    if not labels.exists():
        labels = ROOT / "benchmarks" / "labels.json"
    raw = json.loads(labels.read_text(encoding="utf-8"))
    return [
        {"name": Path(e["file"]).name, "path": dataset / e["file"],
         "vulnerabilities": e.get("vulnerabilities", [])}
        for e in raw
    ]


def _prf(tp: int, fp: int, fn: int):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return round(p * 100, 1), round(r * 100, 1), round(f1 * 100, 1)


def evaluate(dataset: Path, fmt: str, tolerance: int) -> dict:
    from scanner import SolidityScanner  # modules/solidity on sys.path
    import rules as rules_pkg

    entries = load_dataset(dataset, fmt)
    kb_cwe = _load_kb_cwe()
    scanner = SolidityScanner(rules_pkg, str(ROOT / "modules/solidity/kb/vulnerabilities.json"),
                              enable_slither=False, enable_aderyn=False)
    per_cat = {c: {"tp": 0, "fp": 0, "fn": 0, "tn": 0,
                   "missed_contracts": [], "false_positive_contracts": []}
               for c in CATEGORY_RULES}
    per_cwe: dict = {}
    total_lines = matched_lines = 0
    flagged_any = matched_any = 0
    for entry in entries:
        path = entry["path"]
        if not path.exists():
            continue
        truth_cats = {v["category"] for v in entry["vulnerabilities"]}
        findings = scanner.scan_file(str(path))
        pred_rules = {f.rule_id for f in findings}
        if pred_rules:
            flagged_any += 1
        if truth_cats & {c for c, rs in CATEGORY_RULES.items() if pred_rules & set(rs)}:
            matched_any += 1
        for cat, rules in CATEGORY_RULES.items():
            pred = bool(pred_rules & set(rules))
            truth = cat in truth_cats
            cell = per_cat[cat]
            if pred and truth:
                cell["tp"] += 1
            elif pred and not truth:
                cell["fp"] += 1
                cell["false_positive_contracts"].append(entry["name"])
            elif truth and not pred:
                cell["fn"] += 1
                cell["missed_contracts"].append(entry["name"])
            else:
                cell["tn"] += 1
        # CWE level (contract granularity).
        truth_cwes = {CATEGORY_CWE[c] for c in truth_cats if CATEGORY_CWE.get(c)}
        pred_cwes = {kb_cwe.get(r, "") for r in pred_rules} - {""}
        for cwe in truth_cwes | pred_cwes:
            cell = per_cwe.setdefault(cwe, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
            if cwe in pred_cwes and cwe in truth_cwes:
                cell["tp"] += 1
            elif cwe in pred_cwes:
                cell["fp"] += 1
            elif cwe in truth_cwes:
                cell["fn"] += 1
            else:
                cell["tn"] += 1
        # Line level: a labelled line counts as found when a finding of a
        # mapped rule lands within +/- tolerance lines.
        for vuln in entry["vulnerabilities"]:
            rules = set(CATEGORY_RULES.get(vuln["category"], []))
            pred_lines = [f.line for f in findings if f.rule_id in rules]
            for ln in vuln.get("lines", []):
                total_lines += 1
                if any(abs(pl - ln) <= tolerance for pl in pred_lines):
                    matched_lines += 1
    for cell in list(per_cat.values()) + list(per_cwe.values()):
        p, r, f1 = _prf(cell["tp"], cell["fp"], cell["fn"])
        cell.update({"precision": p, "recall": r, "f1": f1})
    cats_with_truth = [c for c in per_cat.values() if c["tp"] + c["fn"] > 0]
    macro_f1 = round(sum(c["f1"] for c in cats_with_truth) / len(cats_with_truth), 1) if cats_with_truth else 0.0
    return {
        "dataset": str(dataset),
        "format": fmt,
        "engine": "Adversum native Solidity rules (Slither/Aderyn disabled)",
        "git_sha": _git_sha(),
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tolerance": tolerance,
        "totals": {
            "contracts": len(entries),
            "contracts_flagged_any_rule": flagged_any,
            "contracts_with_matched_category": matched_any,
            "line_level_recall": round(100.0 * matched_lines / total_lines, 1) if total_lines else 0.0,
            "lines_evaluated": total_lines,
            "macro_f1_categories_with_truth": macro_f1,
        },
        "per_category": per_cat,
        "per_cwe": per_cwe,
        "category_rules": CATEGORY_RULES,
    }


def render_md(report: dict) -> str:
    t = report["totals"]
    out = [
        "# Adversum — Reproducible benchmark (P0)",
        "",
        f"- Dataset: `{report['dataset']}` ({report['format']})",
        f"- Engine: {report['engine']}",
        f"- Git SHA: `{report['git_sha']}` · Generated: {report['generated_at_utc']}",
        f"- Contracts: {t['contracts']} · Flagged (any rule): {t['contracts_flagged_any_rule']}"
        f" · Matched category: {t['contracts_with_matched_category']}",
        f"- Line recall (±{report['tolerance']}): {t['line_level_recall']}% ({t['lines_evaluated']} lines)"
        f" · Macro-F1 (categories with truth): {t['macro_f1_categories_with_truth']}%",
        "",
        "## Per category (contract level)",
        "",
        "| Category | CWE | Rules | TP | FP | FN | Precision % | Recall % | F1 % |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for cat, c in sorted(report["per_category"].items()):
        out.append(f"| {cat} | {CATEGORY_CWE.get(cat, '')} | {', '.join(CATEGORY_RULES[cat]) or '—'} "
                   f"| {c['tp']} | {c['fp']} | {c['fn']} | {c['precision']} | {c['recall']} | {c['f1']} |")
    out += ["", "## Per CWE (contract level)", "",
            "| CWE | TP | FP | FN | Precision % | Recall % | F1 % |", "|---|---:|---:|---:|---:|---:|---:|"]
    for cwe, c in sorted(report["per_cwe"].items()):
        out.append(f"| {cwe} | {c['tp']} | {c['fp']} | {c['fn']} | {c['precision']} | {c['recall']} | {c['f1']} |")
    out += ["", "## Missed contracts (false negatives), by category", ""]
    for cat, c in sorted(report["per_category"].items()):
        if c["missed_contracts"]:
            out.append(f"- **{cat}** ({c['fn']}): " + ", ".join(f"`{m}`" for m in c["missed_contracts"][:25]))
    out += ["", "Regenerate: `python benchmarks/run_benchmark.py` (see benchmarks/README.md).", ""]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default=os.getenv("ADVERSUM_BENCHMARK_DATASET", ""))
    ap.add_argument("--format", choices=["auto", "smartbugs", "dappscan"], default="auto")
    ap.add_argument("--tolerance", type=int, default=3)
    ap.add_argument("--out-json", default=str(ROOT / "benchmarks/results/latest.json"))
    ap.add_argument("--out-md", default=str(ROOT / "benchmarks/results/latest.md"))
    ap.add_argument("--fail-under-f1", type=float, default=None,
                    help="Exit 1 when macro-F1 (categories with truth) is below this percent.")
    args = ap.parse_args(argv)
    dataset = Path(args.dataset) if args.dataset else None
    if dataset is None or not dataset.exists():
        external = Path(r"C:\Users\SMC-DXB\Projects\adversum-bench\smartbugs-curated")
        dataset = external if external.exists() else ROOT / "benchmarks" / "corpus"
    fmt = args.format
    if fmt == "auto":
        fmt = "smartbugs" if (dataset / "vulnerabilities.json").exists() else "dappscan"
    report = evaluate(dataset, fmt, args.tolerance)
    Path(args.out_json).write_text(json.dumps(report, indent=2), encoding="utf-8")
    Path(args.out_md).write_text(render_md(report), encoding="utf-8")
    t = report["totals"]
    print(f"contracts={t['contracts']} matched={t['contracts_with_matched_category']} "
          f"line_recall={t['line_level_recall']}% macro_f1={t['macro_f1_categories_with_truth']}%")
    for cat, c in sorted(report["per_category"].items()):
        if c["tp"] + c["fp"] + c["fn"]:
            print(f"  {cat:28s} P={c['precision']:5.1f} R={c['recall']:5.1f} F1={c['f1']:5.1f} (tp={c['tp']} fp={c['fp']} fn={c['fn']})")
    print(f"wrote {args.out_json} and {args.out_md}")
    if args.fail_under_f1 is not None and t["macro_f1_categories_with_truth"] < args.fail_under_f1:
        print(f"FAIL: macro-F1 {t['macro_f1_categories_with_truth']}% < {args.fail_under_f1}%")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
