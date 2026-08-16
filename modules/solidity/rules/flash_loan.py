import re

# ─────────────────────────────────────────────────────────────────────────────
# SOL-015 — Flash Loan Callback Validation
#
# Only flags unvalidated flash loan callbacks if:
# 1. Standard callback names (onFlashLoan, executeOperation, uniswapV2Call)
# 2. Function is present AND NO sender/initiator validation exists inside
# ─────────────────────────────────────────────────────────────────────────────

def _has_initiator_validation(context: str) -> bool:
    """Check for require/assert/revert on msg.sender, initiator, or pool."""
    indicators = (
        'msg.sender ==', '_initiator ==', 'initiator == address(this)',
        'require(msg.sender', 'assert msg.sender ==', 'if (msg.sender !=',
        'onlyLendingPool', 'onlyPool', 'onlyAave', 'onlyVault'
    )
    return any(ind in context for ind in indicators)


def analyze(content: str) -> list:
    findings = []
    lines = content.split('\n')
    flash_loan_callbacks = ('onFlashLoan', 'executeOperation', 'uniswapV2Call', 'pancakeCall')

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*'):
            continue

        for callback in flash_loan_callbacks:
            if f'function {callback}' in stripped or f'def {callback}' in stripped:
                # Inspect the callback function body (next 25 lines)
                context = "\n".join(lines[i:min(i + 25, len(lines))])
                if not _has_initiator_validation(context):
                    findings.append({
                        'rule_id': 'SOL-015',
                        'line': i + 1,
                        'snippet': stripped[:120],
                    })

    return findings

