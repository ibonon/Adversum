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
#     - SKIP when block.timestamp is a non-dominant salt in a multi-input keccak256:
#         e.g. keccak256(_abi_encode(address, amount, block.timestamp)) → benign ID generation
#         A miner can skew the ID hash by ≤15s but gains no economic advantage; this is
#         not pseudo-randomness for security-critical decisions.
#     - FLAG when block.timestamp is the SOLE input or used with only trivially-guessable
#         values (e.g. keccak256(block.timestamp), abi.encodePacked(block.timestamp % N))
# ─────────────────────────────────────────────────────────────────────────────

# Patterns indicating legitimate unique, non-manipulable co-inputs that neutralise
# the timestamp-manipulation concern in keccak256 ID generation:
_UNIQUE_COINPUT_RE = re.compile(
    r'(?:msg\.sender|msg\.value|_[a-z_]*address|_[a-z_]*addr|_[a-z_]*amount|'
    r'_[a-z_]*hash|_[a-z_]*id|tx\.origin|tokenId|nonce|counter)',
    re.IGNORECASE
)

# Patterns that indicate the timestamp IS being used as randomness or decisive factor:
_RANDOMNESS_SINK_RE = re.compile(
    r'(?:%\s*\d|players\[|winner\s*=|random|rand|lottery|raffle|draw)',
    re.IGNORECASE
)


def _is_timestamp_keccak_fp(line: str, context_lines: list, line_idx: int) -> bool:
    """Return True if this keccak256+block.timestamp usage is a benign multi-input ID generator.
    
    Suppression criteria:
    1. The keccak result is assigned to an *_id or similar identifier variable.
    2. At least one unique non-manipulable co-input is present (msg.sender, address, amount…).
    3. No randomness sink pattern is found nearby (%, players[, winner=, lottery…).
    """
    # Get broader context (5 lines above/below) for sink detection
    ctx_start = max(0, line_idx - 3)
    ctx_end   = min(len(context_lines), line_idx + 3)
    context   = "\n".join(context_lines[ctx_start:ctx_end])

    # Must not be feeding into a randomness sink
    if _RANDOMNESS_SINK_RE.search(context):
        return False

    # Must be assigned to a clearly-named ID variable
    is_id_assignment = bool(re.search(
        r'(?:policy_id|claim_id|pattern_id|request_id|order_id|trade_id|tx_id|'
        r'record_id|event_id|batch_id|receipt_id|nonce_id|uid|uuid)\s*[=:]',
        context, re.IGNORECASE
    ))
    if not is_id_assignment:
        return False

    # Must have at least one strong unique co-input alongside timestamp
    has_unique_coinput = bool(_UNIQUE_COINPUT_RE.search(line))
    return has_unique_coinput


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

            # Unsafe: used in keccak256 — but only flag if NOT a benign multi-input ID generator
            elif re.search(r'keccak256\s*\(.*block\.timestamp', stripped):
                if not _is_timestamp_keccak_fp(stripped, lines, i):
                    findings.append({
                        'rule_id': 'SOL-006',
                        'line': i + 1,
                        'snippet': stripped[:120],
                    })
                # else: suppressed — benign multi-input ID generation (no exploitable entropy leak)

            # Unsafe: modulo PRNG — block.timestamp % N used for indexing/selection
            elif re.search(r'block\.timestamp\s*%\s*\d', stripped) or re.search(r'uint\s*\(\s*block\.timestamp\s*\)\s*%', stripped):
                findings.append({
                    'rule_id': 'SOL-006',
                    'line': i + 1,
                    'snippet': stripped[:120],
                })

    return findings
