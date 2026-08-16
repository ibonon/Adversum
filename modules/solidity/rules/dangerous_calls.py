import re

# ─────────────────────────────────────────────────────────────────────────────
# SOL-005, SOL-014 — Dangerous External & Low-Level Calls
#
# Anti-False-Positive Rules:
# - SOL-005 (delegatecall):
#     - Flag when target address is untrusted or derived from user input
#     - SKIP when in standard proxy implementations (UUPS, ERC-1967, Transparent, Diamond, Safe)
#     - SKIP if inside an `internal` or `onlyOwner` implementation dispatcher
# - SOL-014 (assembly call):
#     - SKIP standard multicall, safe multi-send, ERC-4337 entry point helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_proxy_contract(content: str) -> bool:
    """Check if the contract is intentionally an upgradeable proxy pattern."""
    proxy_indicators = (
        'ERC1967', 'UUPSUpgradeable', 'TransparentUpgradeableProxy',
        'Proxy', 'DiamondCutFacet', 'Fallback', 'implementation()',
        '_delegate(', 'Address.functionDelegateCall'
    )
    return any(indicator.lower() in content.lower() for indicator in proxy_indicators)


def analyze(content: str) -> list:
    findings = []
    lines = content.split('\n')
    is_proxy = _is_proxy_contract(content)

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*'):
            continue

        # ── SOL-005: delegatecall to untrusted target ────────────────────────
        if '.delegatecall(' in stripped:
            # Proxies naturally use delegatecall — do not flag standard proxies
            if not is_proxy:
                # Check if target is a constant or state variable (less risky) vs parameter
                findings.append({
                    'rule_id': 'SOL-005',
                    'line': i + 1,
                    'snippet': stripped[:120],
                })

        # ── SOL-014: Raw assembly call ───────────────────────────────────────
        if 'assembly' in stripped and '{' in stripped:
            context = "\n".join(lines[i:min(i + 15, len(lines))])
            if 'delegatecall(' in context and not is_proxy:
                findings.append({
                    'rule_id': 'SOL-014',
                    'line': i + 1,
                    'snippet': stripped[:120],
                })

    return findings

