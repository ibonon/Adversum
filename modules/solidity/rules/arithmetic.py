"""SOL-004 — Integer overflow/underflow with scoped guards (P1).

Changes from the file-scoped regex (KNOWN_LIMITATIONS A6):

- ``using SafeMath`` no longer suppresses the whole file (or contract):
  in Solidity <0.8 it only makes ``a.add(b)`` safe; bare ``a + b``
  stays unsafe, and only the ``.add/.sub/.mul`` call lines are skipped.
- The SafeMath *library itself* is not flagged: its internal
  ``c = a + b; require(c >= a);`` is the guard implementation.
- A per-function overflow check (``require(result >= operand)``)
  suppresses only that function.
- Only arithmetic that can reach storage is flagged: assignments to a
  state variable, compound assignments on state, or a local result
  that later flows into a state write in the same function. Loop
  counters and constant/time arithmetic are not flagged.
"""
import re

try:
    from ..function_parser import function_at, parse_source, state_writes_in
except (ImportError, ValueError):
    from function_parser import function_at, parse_source, state_writes_in  # type: ignore

_ASSIGN_RE = re.compile(
    r"(?P<lhs>[A-Za-z_][\w.\[\]]*)\s*(?P<compound>[+\-*])?=(?!=)\s*(?P<rhs>[^;]+)"
)
_BINOP_RE = re.compile(r"(?P<a>[\w.\[\]()]+)\s*(?P<op>[+\-*])\s*(?P<b>[\w.\[\]()]+)")
_SAFEMATH_CALL = re.compile(r"\.(?:add|sub|mul|div|mod)\s*\(", re.IGNORECASE)
_TIME_RE = re.compile(r"\b(?:block\.timestamp|block\.number|now)\b")
_LITERAL_RE = re.compile(r"^(?:\d[\w.]*|[A-Z][A-Z0-9_]*)$")


def _is_literal(tok: str) -> bool:
    return bool(_LITERAL_RE.match(tok.strip()))


def _has_overflow_check(body: list, lhs_base: str, line_idx: int, state_vars: set) -> bool:
    """True if a *later* require checks this local result (SafeMath idiom).

    ``require(balanceOf[msg.sender] >= _value)`` before a subtraction is a
    balance check, not an overflow check on the assignment result, and
    must not suppress the finding.
    """
    if not lhs_base or lhs_base in state_vars:
        return False
    pat = re.compile(
        r"(?:require|assert)\s*\([^)]*\b" + re.escape(lhs_base) + r"\b[^)]*(?:>=|>)"
    )
    return any(pat.search(t) for t in body[line_idx + 1:])


def analyze(content: str) -> list:
    if not re.search(r"pragma\s+solidity\s+(?:[\^~>=<]*\s*)?0\.[0-7]\.", content or ""):
        return []
    lines, contracts, functions = parse_source(content)
    contract_by_name = {c.name: c for c in contracts}
    findings = []
    seen = set()
    in_unchecked = 0
    for fn in functions:
        if fn.kind in ("modifier",):
            continue
        contract = contract_by_name.get(fn.contract)
        # The SafeMath library implements the guard; never flag it.
        if contract is not None and contract.kind == "library" and "safemath" in contract.name.lower():
            continue
        body = lines[fn.body_start - 1:fn.end_line]
        body_text = "\n".join(body)
        writes = state_writes_in(fn, body, fn.body_start)
        write_texts = [w[2] for w in writes]
        state_vars = getattr(fn, "state_vars", set()) or set()
        for idx, text in enumerate(body):
            line_no = fn.body_start + idx
            stripped = text.strip()
            if not stripped or stripped.startswith("//"):
                continue
            if re.search(r"\bunchecked\b", stripped):
                in_unchecked += stripped.count("{") - stripped.count("}")
                continue
            if in_unchecked > 0:
                in_unchecked = max(0, in_unchecked + stripped.count("{") - stripped.count("}"))
                continue
            if stripped.startswith(("for", "while", "if", "return", "emit", "event")):
                continue
            if _SAFEMATH_CALL.search(stripped) and not re.search(r"[+\-*]\s*\w", stripped.split(".add")[0]):
                # Pure SafeMath call line; bare ops are handled separately.
                if not re.search(r"\w\s*[+\-*]\s*\w", re.sub(r"\.\w+\([^)]*\)", "", stripped)):
                    continue
            m = _ASSIGN_RE.search(stripped)
            if not m:
                continue
            lhs_base = re.split(r"[.\[]", m.group("lhs"))[0]
            if m.group("compound"):
                op = m.group("compound")
                rhs_toks = re.findall(r"[A-Za-z_][\w.]*|\d+", m.group("rhs"))
            else:
                b = _BINOP_RE.search(m.group("rhs"))
                if not b:
                    continue
                op = b.group("op")
                rhs_toks = [b.group("a"), b.group("b")]
            if _TIME_RE.search(stripped):
                continue
            if rhs_toks and all(_is_literal(t) for t in rhs_toks):
                continue
            if _has_overflow_check(body, lhs_base, idx, state_vars):
                continue
            # Underflow-guarded subtraction: an earlier require in this
            # function already proves LHS >= RHS, so `-`/`-=` cannot
            # underflow. (The paired `+=` on the recipient is a different
            # LHS and stays flagged.)
            if op == "-":
                guarded_sub = any(
                    re.search(r"(?:require|assert)\s*\(", t)
                    and lhs_base in t and ">=" in t
                    and any(tok in t for tok in rhs_toks)
                    for t in body[:idx]
                )
                if guarded_sub:
                    continue
            # Reachability-to-storage test (dataflow-lite).
            is_state_lhs = lhs_base in state_vars or bool(m.group("compound") and lhs_base in state_vars)
            flows_to_state = any(
                re.search(r"\b" + re.escape(lhs_base) + r"\b", wt) and lhs_base not in (
                    re.split(r"[.\[]", wt)[0] if wt else ""
                )
                for wt in write_texts
            ) if lhs_base not in state_vars else True
            # A local that is itself the LHS of a state write is state.
            if lhs_base in state_vars:
                flows_to_state = True
            involves_value = any(
                t in fn.params or re.split(r"[.\[]", t)[0] in state_vars or t.endswith(".length")
                for t in rhs_toks
            )
            if not (is_state_lhs or flows_to_state or (op == "*" and involves_value)):
                continue
            if line_no in seen:
                continue
            seen.add(line_no)
            findings.append({
                "rule_id": "SOL-004",
                "line": line_no,
                "snippet": stripped[:120],
                "function": fn.name,
                "operation": op,
            })
    return findings
