"""SOL-011 — Weak randomness from chain attributes (SWC-120 / CWE-330).

Flags block attributes used as entropy: inside a hash, modulo, array
indexing, or an assignment feeding a winner/random selection. Plain
deadline comparisons (``block.timestamp >= unlockTime``) are not
flagged — that is SOL-006 time manipulation, not randomness.
"""
import re

_ENTROPY_SRC = r"(?:block\.timestamp|block\.number|block\.difficulty|block\.prevrandao|blockhash\s*\([^)]*\)|\bnow\b)"
_HASH_USE = re.compile(r"(?:keccak256|sha256|sha3|abi\.encodePacked)\s*\([^)]*" + _ENTROPY_SRC, re.IGNORECASE)
_MOD_USE = re.compile(_ENTROPY_SRC + r"[^;\n]*%\s*[\w(]", re.IGNORECASE)
_INDEX_USE = re.compile(r"\[\s*[^\]]*" + _ENTROPY_SRC + r"[^\]]*\]", re.IGNORECASE)
_RANDOM_NAME = re.compile(r"\b(?:random|rand|winner|winning|lottery|raffle|draw|pick)\w*\s*(?:[+\-*]?=|\()", re.IGNORECASE)


def analyze(content: str) -> list:
    findings = []
    for i, raw in enumerate((content or "").split("\n")):
        stripped = raw.strip()
        if not stripped or stripped.startswith(("//", "*", "/*")):
            continue
        if not re.search(_ENTROPY_SRC, stripped, re.IGNORECASE):
            continue
        if _HASH_USE.search(stripped) or _MOD_USE.search(stripped) or _INDEX_USE.search(stripped):
            findings.append({"rule_id": "SOL-011", "line": i + 1, "snippet": stripped[:120]})
        elif _RANDOM_NAME.search(stripped) and re.search(_ENTROPY_SRC, stripped, re.IGNORECASE):
            findings.append({"rule_id": "SOL-011", "line": i + 1, "snippet": stripped[:120]})
    return findings
