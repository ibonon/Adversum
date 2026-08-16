import re

# ─────────────────────────────────────────────────────────────────────────────
# SOL-009 & SOL-006 — Price Oracle & Timestamp Manipulation
#
# Anti-False-Positive Rules:
# - SOL-009 (getReserves spot price manipulation):
#     - Only flag if getReserves() result is divided (r0/r1 or r1/r0) to derive a spot price
#     - SKIP if used strictly for AMM swap routing or liquidity invariant check (k = x * y)
# - SOL-006 (block.timestamp):
#     - Only flag if used as a source of randomness or exact comparison (==)
#     - SKIP standard time-lock delta checks: `require(block.timestamp >= unlockTime)`
# ─────────────────────────────────────────────────────────────────────────────

def analyze(content: str) -> list:
    findings = []
    lines = content.split('\n')

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*'):
            continue

        # ── SOL-009: Spot price manipulation via getReserves ─────────────────
        if 'getReserves()' in stripped:
            # Check if spot price derivation formula is on this line or nearby
            context = "\n".join(lines[max(0, i - 2):min(i + 5, len(lines))])
            if re.search(r'(?:price|rate|quote|collateral|valuation)\s*=', context, re.IGNORECASE) or re.search(r'\b(?:reserve0\s*\/\s*reserve1|reserve1\s*\/\s*reserve0)\b', context):
                findings.append({
                    'rule_id': 'SOL-009',
                    'line': i + 1,
                    'snippet': stripped[:120],
                })

        # ── SOL-006: block.timestamp as exact equality or pseudo-randomness ──
        if 'block.timestamp' in stripped:
            # Unsafe: equality check (miner manipulation window)
            if re.search(r'block\.timestamp\s*==', stripped) or re.search(r'==\s*block\.timestamp', stripped):
                findings.append({
                    'rule_id': 'SOL-006',
                    'line': i + 1,
                    'snippet': stripped[:120],
                })
            # Unsafe: used as seed for keccak256 (weak PRNG)
            elif re.search(r'keccak256\s*\(.*block\.timestamp', stripped):
                findings.append({
                    'rule_id': 'SOL-006',
                    'line': i + 1,
                    'snippet': stripped[:120],
                })

    return findings

