"""SOL-001 — Reentrancy via per-function CEI analysis (P1).

Replaces the file-scoped heuristic (any ``nonReentrant`` anywhere in the
file suppressed every finding; any ``.transfer`` anywhere was flagged)
with a function-scoped Checks-Effects-Interactions check:

- the guard is evaluated on the enclosing function (modifier list,
  inherited ``ReentrancyGuard`` hook, or an explicit mutex), never on
  the whole file;
- a finding requires an external call *followed by* a state write in
  the same function body (the exploitable ordering), which is also the
  pair consumed by ``prove_reentrancy`` in Z3;
- read-only (view/pure) functions are not flagged.

Vyper is handled per function as well (``@nonreentrant`` on the
function, ``raw_call``/``extcall`` before a state write).
"""
import re

try:
    from ..function_parser import (
        external_calls_in,
        function_at,
        is_guarded_function,
        parse_source,
        state_writes_in,
        strip_comments_and_strings,
    )
except (ImportError, ValueError):  # direct-module import (tests)
    from function_parser import (  # type: ignore
        external_calls_in,
        function_at,
        is_guarded_function,
        parse_source,
        state_writes_in,
        strip_comments_and_strings,
    )

_VYPER_CALL_RE = re.compile(r"\b(?:raw_call|extcall)\b")
_VYPER_WRITE_RE = re.compile(r"^\s*(?:self\.)?[A-Za-z_][\w.\[\]]*\s*(?:\+=|-=|\*=|=)")


def _is_vyper(content: str) -> bool:
    return bool(
        re.search(r"#\s*@version", content)
        or re.search(r"^\s*@(?:external|internal|nonreentrant)\b", content, re.M)
    )


def _analyze_vyper(content: str) -> list:
    lines = strip_comments_and_strings(content).split("\n")
    findings = []
    # Split into def blocks (Vyper functions start at column 0).
    starts = [i for i, l in enumerate(lines) if re.match(r"^(?:@\w+.*\n?)*def\s+\w+\s*\(", l)] or \
             [i for i, l in enumerate(lines) if re.match(r"^def\s+\w+\s*\(", l)]
    bounds = starts + [len(lines)]
    # Decorators sit above def; scan a small window upward for @nonreentrant.
    for k, start in enumerate(starts):
        end = bounds[k + 1]
        window = "\n".join(lines[max(0, start - 4):end])
        if "@nonreentrant" in window.lower():
            continue
        body = lines[start:end]
        call_lines = [start + i + 1 for i, t in enumerate(body) if _VYPER_CALL_RE.search(t)]
        write_lines = [start + i + 1 for i, t in enumerate(body) if _VYPER_WRITE_RE.search(t)]
        for cl in call_lines:
            later = [w for w in write_lines if w > cl]
            if later:
                findings.append({
                    "rule_id": "SOL-001", "line": cl,
                    "snippet": lines[cl - 1].strip()[:120],
                    "call_line": cl, "update_line": later[0],
                    "guard_present": "none",
                })
    return findings


def analyze(content: str) -> list:
    if _is_vyper(content):
        return _analyze_vyper(content)
    lines, _contracts, functions = parse_source(content)
    findings = []
    seen = set()
    for fn in functions:
        if fn.kind in ("modifier",):
            continue
        if re.search(r"\b(?:view|pure)\b", fn.header):
            continue
        body = lines[fn.body_start - 1:fn.end_line]
        body_text = "\n".join(body)
        if is_guarded_function(fn, body_text):
            continue
        calls = external_calls_in(body, fn.body_start)
        writes = state_writes_in(fn, body, fn.body_start)
        if not calls or not writes:
            continue
        for call_line, snippet, _sends in calls:
            later = [w for w in writes if w[0] > call_line and w[1] not in ("locked", "_locked", "mutex")]
            if not later:
                continue
            # 2300-gas send/transfer cannot drive a state-changing reentry
            # on its own: only flag it when the value paid out is drawn
            # from a balance-like state variable updated after the call
            # (the classic drain accounting). Full-gas .call and external
            # token calls are always flagged on a CEI violation.
            is_low_gas = bool(re.search(r"\.(?:transfer|send)\s*\(", snippet)) and ".call" not in snippet
            if is_low_gas and not any(
                re.search(r"balance|credit|reward|fee|pot|amount|share|deposit", (w[1] + " " + w[2]), re.IGNORECASE)
                for w in later
            ):
                continue
            if call_line in seen:
                continue
            seen.add(call_line)
            findings.append({
                "rule_id": "SOL-001",
                "line": call_line,
                "snippet": snippet[:120],
                "function": fn.name,
                "call_line": call_line,
                "update_line": later[0][0],
                "guard_present": "none",
            })
    # ── Cross-function reentrancy (inter-procedural, 1 level) ──────────
    # A public function that checks a flag, calls an internal function
    # performing the external call, and only then sets the flag is
    # reentrant through the callee (e.g. getFirstWithdrawalBonus ->
    # withdrawReward -> recipient.call, flagged in SmartBugs).
    by_name = {}
    for fn in functions:
        body = lines[fn.body_start - 1:fn.end_line]
        if external_calls_in(body, fn.body_start):
            by_name.setdefault(fn.name, fn)
    modifiers = {f.name: f for f in functions if f.kind == "modifier"}
    for fn in functions:
        if fn.kind == "modifier" or re.search(r"\b(?:view|pure)\b", fn.header):
            continue
        body = lines[fn.body_start - 1:fn.end_line]
        body_text = "\n".join(body)
        if is_guarded_function(fn, body_text):
            continue
        writes = state_writes_in(fn, body, fn.body_start)
        # Modifier-mediated: a modifier that calls back into msg.sender
        # before `_;`, while the function body writes state.
        for mod_name, mod in modifiers.items():
            if not re.search(r"\b" + re.escape(mod_name) + r"\b", fn.header):
                continue
            mod_body = "\n".join(lines[mod.body_start - 1:mod.end_line])
            if re.search(r"\(\s*msg\.sender\s*\)\s*\.\w+\s*\(", mod_body) and writes:
                if fn.start_line not in seen:
                    seen.add(fn.start_line)
                    findings.append({
                        "rule_id": "SOL-001", "line": fn.start_line,
                        "snippet": fn.header.strip()[:120], "function": fn.name,
                        "call_line": fn.start_line, "update_line": writes[0][0],
                        "guard_present": "none",
                    })
        for idx, text in enumerate(body):
            line_no = fn.body_start + idx
            for callee_name in by_name:
                if callee_name == fn.name:
                    continue
                if re.search(r"\b" + re.escape(callee_name) + r"\s*\(", text):
                    later = [w for w in writes if w[0] > line_no]
                    if later and line_no not in seen:
                        seen.add(line_no)
                        findings.append({
                            "rule_id": "SOL-001", "line": line_no,
                            "snippet": text.strip()[:120], "function": fn.name,
                            "call_line": line_no, "update_line": later[0][0],
                            "guard_present": "none",
                        })
    return findings
