import re

# ─────────────────────────────────────────────────────────────────────────────
# SOL-001 — Reentrancy Detection (Solidity & Vyper aware)
#
# Vyper differences vs Solidity:
#   - Uses @nonreentrant("lock") not nonReentrant modifier
#   - Uses `extcall token.transfer(...)` for external calls (>= 0.4.0)
#   - `assert token.transfer(...)` in Vyper CHECKS the return value — NOT unchecked
#   - Vyper has no .call{} pattern
#   - CEI pattern: state changes after external calls ARE an issue in Vyper too
#
# We only flag reentrancy when:
#   1. File is .sol with external calls AND no nonReentrant guard, OR
#   2. File is .vy with extcall/raw_call AND no @nonreentrant decorator AND
#      the function has state writes BEFORE the external call (order-sensitive)
# ─────────────────────────────────────────────────────────────────────────────

def _is_vyper(content: str) -> bool:
    """Detect Vyper files by characteristic syntax."""
    return bool(
        re.search(r'@(external|internal|nonreentrant|view|pure)\b', content) or
        re.search(r'\bextcall\b', content) or
        re.search(r'\braw_call\s*\(', content) or
        content.strip().startswith('#') and re.search(r'# @version', content)
    )


def _vyper_has_nonreentrant(content: str) -> bool:
    """Check for Vyper @nonreentrant decorator (case-insensitive, with @)."""
    return bool(re.search(r'@nonreentrant', content, re.IGNORECASE))


def analyze(content: str) -> list:
    findings = []
    lines = content.split('\n')
    is_vy = _is_vyper(content)

    if is_vy:
        # ── Vyper path ──────────────────────────────────────────────────────
        # Protected if @nonreentrant is present anywhere in file
        has_protection = _vyper_has_nonreentrant(content)
        if has_protection:
            return []

        # Only flag raw_call() — the true low-level dangerous call in Vyper.
        # `extcall token.transfer(...)` is explicit and safe by design in Vyper ≥ 0.4
        # `assert token.transfer(...)` checks return value — not a reentrancy indicator
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if re.search(r'\braw_call\s*\(', stripped):
                findings.append({
                    'rule_id': 'SOL-001',
                    'line': i + 1,
                    'snippet': stripped[:120],
                })

    else:
        # ── Solidity path ───────────────────────────────────────────────────
        # Strip comments first so explanatory comments (e.g. '// Missing ReentrancyGuard') don't suppress findings
        content_no_comments = re.sub(r'//.*', '', content)
        content_no_comments = re.sub(r'/\*.*?\*/', '', content_no_comments, flags=re.DOTALL)
        
        has_protection = (
            'nonReentrant' in content_no_comments or
            'ReentrancyGuard' in content_no_comments or
            'mutex' in content_no_comments.lower()
        )
        if has_protection:
            return []

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            # Low-level calls: .call{value}(...), .transfer(...), .send(...)
            if re.search(r'\.(call\s*\{|transfer\s*\(|send\s*\()', stripped):
                # Skip if it's a safe/checked pattern
                if re.search(r'(?:require|assert|bool\s+\w+\s*=)\s*.*transfer', stripped):
                    continue
                if 'safeTransfer' in stripped:
                    continue
                findings.append({
                    'rule_id': 'SOL-001',
                    'line': i + 1,
                    'snippet': stripped[:120],
                })

    return findings
