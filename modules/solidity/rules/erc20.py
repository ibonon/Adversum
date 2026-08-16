import re

def analyze(content: str) -> list:
    """
    SOL-007 / SOL-009 — ERC20 unsafe transfer / approve front-running

    SOL-007: .transfer() call without checking return value
             Only flags token.transfer(), NOT native ETH .transfer() which always reverts.

    SOL-009: approve() front-running
             Only flags direct approve() on a token address (not SafeERC20.safeApprove,
             increaseAllowance, etc.) and skips internal _approve helper calls.
    """
    findings = []
    lines = content.split('\n')

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Skip comments
        if not stripped or stripped.startswith('//') or stripped.startswith('*'):
            continue

        # ── SOL-007: ERC20 transfer without return value check ──────────────
        # Matches patterns like:  token.transfer(to, amount)  or  IERC20(addr).transfer(...)
        # Does NOT match:  payable(to).transfer(amount)  or  address(this).transfer(...)
        # Does NOT match:  bool success = token.transfer(...)
        # Does NOT match:  require(token.transfer(...))
        if '.transfer(' in stripped:
            # Skip native ETH transfers (payable / address target)
            if re.search(r'(?:payable|address)\s*\(', stripped):
                pass
            # Skip safe usages: return value assigned or required
            elif re.search(r'(?:bool\s+\w+\s*=|require\s*\()', stripped):
                pass
            # Skip safeTransfer
            elif 'safeTransfer' in stripped:
                pass
            # Skip internal transfers or transfers from this contract
            elif re.search(r'this\.transfer\s*\(', stripped):
                pass
            else:
                findings.append({
                    'rule_id': 'SOL-007',
                    'line': i + 1,
                    'snippet': stripped[:120],
                })

        # ── SOL-009: approve() front-running ────────────────────────────────
        # Matches: token.approve(spender, amount)  or  IERC20(x).approve(...)
        # Does NOT match: _approve(...)  safeApprove(...)  increaseAllowance(...)
        if re.search(r'(?<!\w_)(?<!safe)approve\s*\(', stripped, re.IGNORECASE):
            # Skip internal/safe versions
            if re.search(r'(?:safeApprove|_approve|increaseAllowance|decreaseAllowance)\s*\(', stripped):
                pass
            # Skip comments
            elif stripped.startswith('//'):
                pass
            # Must look like an external call: identifier.approve(...)
            elif re.search(r'\w+\.approve\s*\(', stripped):
                findings.append({
                    'rule_id': 'SOL-009',
                    'line': i + 1,
                    'snippet': stripped[:120],
                })

    return findings
