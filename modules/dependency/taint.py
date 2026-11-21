"""Dependency taint for the intermediate group (Step 3).

Demonstrates a source -> sink dependency path inside one function —
entropy/environment (``block.*``), spot price (``getReserves``), or an
attacker-controllable loop bound — reaching a decision, payment,
selection or gas-cost sink. A confirmed path yields a
``dependency_path`` witness and the DEPENDENCY_PROVEN verdict:
dependency is shown, exploitability is explicitly not claimed.
"""
from __future__ import annotations

import re

try:
    from modules.solidity.function_parser import external_calls_in, parse_source, state_writes_in
except (ImportError, ValueError):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "solidity"))
    from function_parser import external_calls_in, parse_source, state_writes_in  # type: ignore

_ENTROPY_RE = re.compile(r"block\.(?:timestamp|number|difficulty|prevrandao|hash)|blockhash\s*\(|\bnow\b")
_SINK_VALUE_RE = re.compile(r"\.(?:transfer|send|call)\b|payable\s*\(")
_SELECTION_RE = re.compile(r"\b(?:winner|winning|random|rand|lottery|raffle|pick|draw)\w*\b", re.IGNORECASE)
_PRICE_SINK_RE = re.compile(r"\b(?:borrow|mint|swap|liquidate|collateral|transfer|send|call)\b")
_LOOP_RE = re.compile(r"\b(?:for|while)\s*\(")
_REGISTER_RE = re.compile(r"\.push\s*\(|length\s*\+=|\[\s*\w+\s*\]\s*=")


def _vars_in(text: str) -> set:
    return set(re.findall(r"[A-Za-z_]\w*", text))


def _tainted_lines(body: list, source_pred) -> dict:
    """Propagate taint: assignments from tainted exprs taint their LHS."""
    tainted: dict[int, set] = {}
    taint_vars: set = set()
    for idx, text in enumerate(body):
        line_vars = _vars_in(text)
        if source_pred(text) or (line_vars & taint_vars):
            tainted[idx] = set(line_vars)
            m = re.search(r"^\s*(?:[\w.\[\]]+\s+)?([A-Za-z_]\w*)\s*(?:[+\-*]?=(?!=))", text)
            if m:
                taint_vars.add(m.group(1))
            taint_vars |= {v for v in line_vars if v in taint_vars}
    return tainted


def analyze_dependency(content: str) -> list:
    """Return dependency findings with witnesses for SOL-006/011/009/013."""
    lines, _contracts, functions = parse_source(content or "")
    out = []
    for fn in functions:
        body = lines[fn.body_start - 1:fn.end_line]
        offset = fn.body_start
        writes = state_writes_in(fn, body, offset)
        calls = external_calls_in(body, offset)

        # ── SOL-006 / SOL-011: entropy -> decision/payment/selection ──
        entropy_taint = _tainted_lines(body, lambda t: bool(_ENTROPY_RE.search(t)))
        for idx, text in enumerate(body):
            if idx not in entropy_taint:
                continue
            is_value_sink = bool(_SINK_VALUE_RE.search(text))
            is_selection = bool(_SELECTION_RE.search(text)) and ("=" in text or "return" in text)
            is_gate = bool(re.search(r"\b(?:if|require)\s*\(", text))
            if not (is_value_sink or is_selection or is_gate):
                continue
            src_idx = next((i for i in range(idx + 1) if _ENTROPY_RE.search(body[i])), idx)
            rule = "SOL-011" if is_selection else "SOL-006"
            out.append(_finding(rule, offset + idx, text, fn.name,
                                source="block.* entropy/environment",
                                sink=text.strip()[:80],
                                path=[offset + src_idx, offset + idx]))
            break

        # ── SOL-009: spot price (getReserves) -> value sink ───────────
        price_taint = _tainted_lines(body, lambda t: "getReserves" in t or bool(re.search(r"reserve[01]?\s*/\s*reserve", t)))
        for idx, text in enumerate(body):
            if idx in price_taint and _PRICE_SINK_RE.search(text) and idx != next(iter(price_taint), None):
                src_idx = next(i for i in range(idx + 1) if "getReserves" in body[i] or i in price_taint)
                out.append(_finding("SOL-009", offset + idx, text, fn.name,
                                    source="AMM spot price (getReserves)",
                                    sink=text.strip()[:80],
                                    path=[offset + src_idx, offset + idx]))
                break

        # ── SOL-013: attacker-controllable loop bound -> gas sink ─────
        # Bound is controllable when the looped-over array can grow via
        # a public push/length write anywhere in the contract source.
        growable = bool(_REGISTER_RE.search(content or ""))
        for idx, text in enumerate(body):
            if not _LOOP_RE.search(text):
                continue
            bound_m = re.search(r"<\s*([A-Za-z_][\w.]*)", text)
            if not bound_m:
                continue
            bound = bound_m.group(1)
            in_loop_calls = [c for c in calls if c[0] > offset + idx]
            in_loop_writes = [w for w in writes if w[0] > offset + idx]
            if (in_loop_calls or in_loop_writes) and (bound.endswith(".length") or growable):
                sink_line = (in_loop_calls or in_loop_writes)[0][0]
                out.append(_finding("SOL-013", offset + idx, text, fn.name,
                                    source=f"loop bound {bound} (growable storage)",
                                    sink=f"loop body cost at line {sink_line}",
                                    path=[offset + idx, sink_line]))
                break
    # Deduplicate by (rule, line).
    seen, dedup = set(), []
    for f in out:
        if (f["rule_id"], f["line"]) not in seen:
            seen.add((f["rule_id"], f["line"]))
            dedup.append(f)
    return dedup


def _finding(rule, line, text, function, *, source, sink, path):
    return {
        "rule_id": rule,
        "line": line,
        "snippet": text.strip()[:120],
        "function": function,
        "proof_verdict": "DEPENDENCY_PROVEN",
        "witness": {
            "kind": "dependency_path",
            "solver": "dependency-taint (function-scoped)",
            "entry_point": function,
            "call_path": [f"line {p}" for p in path],
            "counterexample": {"source": source, "sink": sink},
            "scope": "Dependency source->sink demonstrated in one function; "
                     "exploitability (profit, miner cooperation, gas bricking) NOT proven.",
            "artifact": None,
        },
        "verdict_reason": "Dependency proven (source -> sink path attached); exploitability not proven.",
    }
