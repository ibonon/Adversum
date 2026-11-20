"""Function-scoped Solidity parsing shared by the native rules (P1).

The previous rules evaluated guards at *file* scope: one ``nonReentrant``
or one ``using SafeMath`` anywhere suppressed every finding in the file
(KNOWN_LIMITATIONS A6). This module provides the minimum structural
facts needed to evaluate guards and ordering *per function / per
contract* without a full Solidity compiler:

- comment/string-stripped source with stable line numbers,
- contract and function spans (brace matching),
- state-variable and local-variable names,
- SafeMath ``using ... for`` directives per contract,
- external-call and state-write locations inside a function body.

It is deliberately heuristic: it never invents a fact it cannot locate,
and callers fall back to conservative behaviour on unparsed code.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_TYPE = r"(?:address|bool|string|bytes\d{0,2}|uint\d{0,3}|int\d{0,3}|mapping\s*\([^)]*\)|[A-Z][\w]*(?:\[\])?)"
_STATE_DECL_RE = re.compile(
    r"^\s*(?:public|private|internal|constant|immutable|override|\s)*?"
    r"(?P<type>" + _TYPE + r")(?:\s+(?:public|private|internal|constant|immutable))*\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:=[^;]*)?;",
)
_FUNC_RE = re.compile(
    r"\b(?:function\s+(?P<name>[A-Za-z_]\w*)|(?P<kind>constructor|fallback|receive)\b)"
    r"\s*(?P<params>\([^)]*\))?(?P<tail>[^{;]*)",
)
_CONTRACT_RE = re.compile(r"\b(?P<kind>contract|library|interface)\s+(?P<name>[A-Za-z_]\w*)")
_USING_RE = re.compile(r"\busing\s+(?P<lib>[A-Za-z_]\w*)\s+for\s+(?P<type>[^;]+);")
_EXTERNAL_CALL_RES = [
    re.compile(r"\.call\s*\{"),
    re.compile(r"\.call\s*\("),
    re.compile(r"\.call\.value\s*\("),
    re.compile(r"\bcall\.value\s*\("),
    re.compile(r"\.delegatecall\s*\("),
    re.compile(r"\.staticcall\s*\("),
    re.compile(r"\.(?:transfer|send)\s*\("),
    re.compile(r"\braw_call\s*\("),
    re.compile(r"\bextcall\b"),
]
_VALUE_CALL_RE = re.compile(
    r"\.call\s*\{[^}]*value\s*:|\.call\.value\s*\(|\bcall\.value\s*\(|\.(?:transfer|send)\s*\("
)
_STATE_WRITE_RE = re.compile(
    r"(?P<lhs>[A-Za-z_][\w.\[\]]*)\s*(?:\+=|-=|\*=|/=|=(?!=))|"
    r"(?P<inc>[A-Za-z_][\w.\[\]]*)\s*(?:\+\+|--)|"
    r"\bdelete\s+(?P<del>[A-Za-z_][\w.\[\]]*)"
)


def strip_comments_and_strings(content: str) -> str:
    """Blank comments and string literals, preserving offsets/newlines."""
    out = list(content)
    i, n = 0, len(content)
    state = None  # None | 'line' | 'block' | quote char
    while i < n:
        c = content[i]
        nxt = content[i + 1] if i + 1 < n else ""
        if state is None:
            if c == "/" and nxt == "/":
                state = "line"; out[i] = out[i + 1] = " "; i += 2; continue
            if c == "/" and nxt == "*":
                state = "block"; out[i] = out[i + 1] = " "; i += 2; continue
            if c in ("'", '"'):
                state = c; out[i] = " "; i += 1; continue
            i += 1; continue
        if state == "line":
            if c == "\n":
                state = None
            else:
                out[i] = " "
            i += 1; continue
        if state == "block":
            if c == "*" and nxt == "/":
                out[i] = out[i + 1] = " "; i += 2; state = None; continue
            if c != "\n":
                out[i] = " "
            i += 1; continue
        # string literal
        if c == "\\":
            out[i] = " "
            if i + 1 < n and content[i + 1] != "\n":
                out[i + 1] = " "
            i += 2; continue
        if c == state:
            state = None
        if c != "\n":
            out[i] = " "
        i += 1
    return "".join(out)


@dataclass
class FunctionSpan:
    name: str
    kind: str  # function | constructor | fallback | receive | modifier
    start_line: int  # 1-based, header line
    body_start: int  # 1-based, line of '{' (== start_line if none)
    end_line: int  # 1-based, line of matching '}'
    header: str
    contract: str = ""
    params: list = field(default_factory=list)
    locals: set = field(default_factory=set)


@dataclass
class ContractSpan:
    name: str
    kind: str
    start_line: int
    end_line: int
    state_vars: set = field(default_factory=set)
    safemath_types: set = field(default_factory=set)  # types covered by using SafeMath
    uses_safemath: bool = False


def _brace_span(lines: list, start_idx: int):
    """Return (body_start_idx, end_idx) 0-based for first '{' at/after start."""
    depth = 0
    body_start = None
    for i in range(start_idx, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                if body_start is None:
                    body_start = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if body_start is not None and depth == 0:
                    return body_start, i
        if body_start is None and ";" in lines[i]:
            return start_idx, start_idx  # declaration without body (interface)
    return (body_start if body_start is not None else start_idx), len(lines) - 1


def parse_source(content: str):
    """Return (clean_lines, contracts, functions) with 1-based line facts."""
    clean = strip_comments_and_strings(content or "")
    lines = clean.split("\n")
    contracts: list[ContractSpan] = []
    for i, line in enumerate(lines):
        m = _CONTRACT_RE.search(line)
        if m:
            bs, be = _brace_span(lines, i)
            contracts.append(ContractSpan(m.group("name"), m.group("kind"), bs + 1, be + 1))
    functions: list[FunctionSpan] = []
    for i, line in enumerate(lines):
        m = _FUNC_RE.search(line)
        kind = None
        name = None
        if m and m.group("name"):
            kind, name = "function", m.group("name")
        elif m and m.group("kind"):
            kind, name = m.group("kind"), m.group("kind")
        elif re.search(r"\bmodifier\s+([A-Za-z_]\w*)", line):
            mm = re.search(r"\bmodifier\s+([A-Za-z_]\w*)", line)
            kind, name = "modifier", mm.group(1)
        if not name:
            continue
        # Join multi-line headers until '{' or ';' (max 4 lines).
        header = line
        j = i
        while "{" not in header and ";" not in header and j < min(i + 4, len(lines) - 1):
            j += 1
            header += " " + lines[j].strip()
        bs, be = _brace_span(lines, i)
        params = []
        pm = re.search(r"\(([^)]*)\)", header)
        if pm:
            for part in pm.group(1).split(","):
                toks = [t for t in re.split(r"\s+", part.strip())
                        if t and t not in ("memory", "calldata", "storage", "payable")]
                if toks:
                    params.append(toks[-1])
        contract = ""
        for c in contracts:
            if c.start_line <= i + 1 <= c.end_line:
                contract = c.name
        fn = FunctionSpan(name, kind, i + 1, bs + 1, be + 1, header, contract, params)
        functions.append(fn)
    # State vars + SafeMath scope per contract; locals per function.
    fn_starts = {f.start_line for f in functions}
    for c in contracts:
        for ln in range(c.start_line, c.end_line + 1):
            if ln in fn_starts:
                continue
            text = lines[ln - 1] if ln - 1 < len(lines) else ""
            um = _USING_RE.search(text)
            if um and "SafeMath" in um.group("lib"):
                c.uses_safemath = True
                c.safemath_types.add(um.group("type").strip())
            sm = _STATE_DECL_RE.search(text)
            if sm and "function" not in text:
                c.state_vars.add(sm.group("name"))
    state_by_contract = {c.name: c.state_vars for c in contracts}
    for f in functions:
        body = lines[f.body_start - 1:f.end_line]
        locals_ = set(f.params)
        for text in body:
            for dm in re.finditer(
                r"\b" + _TYPE + r"(?:\s*\[\])?(?:\s+(?:memory|calldata|storage))?\s+([A-Za-z_]\w*)\s*(?:[=;,\)])",
                text,
            ):
                locals_.add(dm.group(1))
        f.locals = locals_
        f_state = state_by_contract.get(f.contract, set())
        f.__dict__["state_vars"] = set(f_state)
    return lines, contracts, functions


def function_at(functions: list, line_no: int):
    """Innermost function whose body contains ``line_no`` (1-based)."""
    best = None
    for f in functions:
        if f.body_start <= line_no <= f.end_line:
            if best is None or (f.end_line - f.body_start) < (best.end_line - best.body_start):
                best = f
    return best


def is_guarded_function(fn: FunctionSpan, body_text: str) -> bool:
    """Per-function reentrancy guard (modifier, inheritance hook, mutex)."""
    hay = (fn.header + "\n" + body_text).lower()
    if "nonreentrant" in hay:
        return True
    if re.search(r"\breentrancyguard\b", hay):
        return True
    # Mutex idiom: a lock flag checked and set inside this function.
    if re.search(r"(?:locked|_locked|mutex|_guard)\s*=\s*true", body_text) and re.search(
        r"require\s*\(\s*!?\s*(?:locked|_locked|mutex)", body_text
    ):
        return True
    return False


def external_calls_in(body_lines: list, offset: int) -> list:
    """[(line_no, text, sends_value)] for external calls in body lines."""
    out = []
    for idx, text in enumerate(body_lines):
        if any(p.search(text) for p in _EXTERNAL_CALL_RES):
            out.append((offset + idx, text.strip(), bool(_VALUE_CALL_RE.search(text))))
    return out


def state_writes_in(fn: FunctionSpan, body_lines: list, offset: int) -> list:
    """[(line_no, base_var, text)] for writes to non-local storage vars."""
    state_vars = getattr(fn, "state_vars", set()) or set()
    out = []
    decl_re = re.compile(r"^\s*(?:" + _TYPE + r")(?:\s*\[\])?(?:\s+(?:memory|calldata|storage))?\s+[A-Za-z_]\w*\s*[=;,]")
    for idx, text in enumerate(body_lines):
        if decl_re.search(text):
            continue  # local declaration, not a storage write
        for m in _STATE_WRITE_RE.finditer(text):
            lhs = m.group("lhs") or m.group("inc") or m.group("del") or ""
            base = re.split(r"[.\[]", lhs)[0]
            if not base:
                continue
            if base in fn.locals and base not in state_vars:
                continue
            if base in ("if", "for", "while", "return", "require"):
                continue
            out.append((offset + idx, base, text.strip()))
    return out
