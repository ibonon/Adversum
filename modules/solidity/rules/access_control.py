import re

# ─────────────────────────────────────────────────────────────────────────────
# SOL-002 & SOL-003 — Access Control Analysis (Solidity & Vyper)
#
# Anti-False-Positive Rules:
# - SOL-002 (tx.origin):
#     - Flag when used for authorization: `tx.origin == owner`, `require(tx.origin == ...)`
#     - SKIP when used in anti-contract guard: `tx.origin == msg.sender` (legitimate EOA check)
#     - SKIP in logging/events: `emit Transaction(tx.origin, ...)`
#
# - SOL-003 (selfdestruct):
#     - Flag if selfdestruct/suicide is reachable without access control
#     - SKIP if enclosed in a function with onlyOwner, onlyRole, auth, @external + assert msg.sender
# ─────────────────────────────────────────────────────────────────────────────

def _is_safe_tx_origin_usage(line: str) -> bool:
    """Check if tx.origin is used safely (e.g. tx.origin == msg.sender for EOA check)."""
    stripped = line.strip()
    # tx.origin == msg.sender or msg.sender == tx.origin (EOA only check)
    if re.search(r'tx\.origin\s*==\s*msg\.sender|msg\.sender\s*==\s*tx\.origin', stripped):
        return True
    # Event or logging
    if stripped.startswith('emit ') or 'log' in stripped.lower():
        return True
    return False


def _has_access_control_guard(context_lines: str) -> bool:
    """Check if the function context contains access control modifiers or assertions."""
    guards = (
        'onlyOwner', 'onlyAdmin', 'onlyRole', 'requiresAuth', 'auth',
        'isOwner', 'whenNotPaused', 'require(msg.sender ==', 'require(owner == msg.sender',
        'require(_msgSender() ==', 'assert msg.sender ==', 'assert self.owner == msg.sender',
        'if (msg.sender !=', 'if (_msgSender() !='
    )
    return any(guard.lower() in context_lines.lower() for guard in guards)


def analyze(content: str) -> list:
    findings = []
    lines = content.split('\n')

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*'):
            continue

        # ── SOL-002: tx.origin for authentication ────────────────────────────
        if 'tx.origin' in stripped:
            if not _is_safe_tx_origin_usage(stripped):
                # Check if used in conditional or require/assert
                if re.search(r'(?:require|assert|if)\s*\(.*tx\.origin', stripped) or re.search(r'tx\.origin\s*(?:==|!=)', stripped):
                    findings.append({
                        'rule_id': 'SOL-002',
                        'line': i + 1,
                        'snippet': stripped[:120],
                    })

        # ── SOL-003: Unprotected selfdestruct / suicide ──────────────────────
        if re.search(r'\b(?:selfdestruct|suicide)\s*\(', stripped):
            # Check function context (20 lines before) for access control
            start_idx = max(0, i - 20)
            context = "\n".join(lines[start_idx:i + 1])
            if not _has_access_control_guard(context):
                findings.append({
                    'rule_id': 'SOL-003',
                    'line': i + 1,
                    'snippet': stripped[:120],
                })

    return findings

