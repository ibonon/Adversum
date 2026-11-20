"""SOL-013 — Denial of service: external call / state write in a loop.

SWC-113 / CWE-770. Flags value-sending external calls inside a
``for``/``while`` body (one failing recipient blocks the loop) and
unbounded loops over storage arrays that write state (gas-limit DoS).
"""
import re

try:
    from ..function_parser import external_calls_in, parse_source
except (ImportError, ValueError):
    from function_parser import external_calls_in, parse_source  # type: ignore

_LOOP_RE = re.compile(r"\b(?:for|while)\s*\(")


def _loop_spans(body: list, offset: int):
    """[(start_line, end_line)] for loop bodies within function body lines."""
    spans = []
    depth = 0
    start = None
    for idx, text in enumerate(body):
        if _LOOP_RE.search(text):
            start = offset + idx
            depth = text.count("{") - text.count("}")
            if "{" not in text:
                spans.append((start, start + 1))  # single-statement loop (approx.)
                start = None
            continue
        if start is not None:
            depth += text.count("{") - text.count("}")
            if depth <= 0:
                spans.append((start, offset + idx))
                start = None
    if start is not None:
        spans.append((start, offset + len(body) - 1))
    return spans


def analyze(content: str) -> list:
    lines, _contracts, functions = parse_source(content or "")
    findings = []
    seen = set()
    for fn in functions:
        body = lines[fn.body_start - 1:fn.end_line]
        spans = _loop_spans(body, fn.body_start)
        if not spans:
            continue
        for call_line, snippet, _sends in external_calls_in(body, fn.body_start):
            if any(s <= call_line <= e for s, e in spans) and call_line not in seen:
                seen.add(call_line)
                findings.append({
                    "rule_id": "SOL-013", "line": call_line,
                    "snippet": snippet[:120], "function": fn.name,
                })
        # Gas-limit DoS: a loop over a user-controlled / storage length
        # (or a large constant bound) whose body grows or writes storage
        # can exceed the block gas limit and brick the function.
        try:
            from ..function_parser import state_writes_in
        except (ImportError, ValueError):
            from function_parser import state_writes_in  # type: ignore
        writes = state_writes_in(fn, body, fn.body_start)
        for start, end in spans:
            header = lines[start - 1] if start - 1 < len(lines) else ""
            bound = re.search(r"<\s*([A-Za-z_][\w.]*|\d+)", header)
            risky_bound = False
            if bound:
                tok = bound.group(1)
                risky_bound = tok.endswith(".length") or (tok.isdigit() and int(tok) >= 100) or not tok.isdigit()
            grows = any(start <= w[0] <= end for w in writes)
            if risky_bound and grows and start not in seen:
                seen.add(start)
                findings.append({
                    "rule_id": "SOL-013", "line": start,
                    "snippet": header.strip()[:120], "function": fn.name,
                })
    return findings
