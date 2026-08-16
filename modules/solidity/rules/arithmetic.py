import re

# Patterns that strongly suggest arithmetic is actually being used on values
# (not just comparisons, string concatenation, or comments)
_ARITH_PATTERN = re.compile(r'(?<!\w)([\w.]+)\s*[\+\-\*\/](?!=)\s*([\w.(])')

# Unsafe patterns: integer result of arithmetic stored or used directly
_UNSAFE_ADD  = re.compile(r'\b\w+\s*\+\s*\w+', re.ASCII)
_UNSAFE_SUB  = re.compile(r'\b\w+\s*-\s*\w+', re.ASCII)
_UNSAFE_MUL  = re.compile(r'\b\w+\s*\*\s*\w+', re.ASCII)

# Lines to skip: comments, string literals, event/error definitions, pure comparisons
_SKIP = re.compile(r'^\s*(//)|(\".*\")|(\'.*\')|(emit\s)|(event\s)|(error\s)|(import\s)')
_SAFEMATH_CALL = re.compile(r'\.(add|sub|mul|div|mod)\s*\(', re.IGNORECASE)
_UNCHECKED_BLOCK = re.compile(r'\bunchecked\b')


def analyze(content: str) -> list:
    """
    SOL-004 — Integer Overflow/Underflow (pre-Solidity 0.8.0)

    Only reports if:
    1. Pragma is explicitly < 0.8.x (no SafeMath built-in)
    2. SafeMath is NOT imported / used globally
    3. The arithmetic happens on a storage/state variable (assignment context)
    4. The line is not in an unchecked{} block (0.8+ explicit opt-in)
    """
    findings = []

    # Only trigger on pre-0.8 contracts
    pragma_match = re.search(r'pragma\s+solidity\s+[\^~]?0\.[0-7]\.', content)
    if not pragma_match:
        return findings

    # If SafeMath is imported and used, risk is mitigated — skip file
    if 'SafeMath' in content and 'using SafeMath' in content:
        return findings

    lines = content.split('\n')

    # Track whether we're inside an unchecked{} block
    in_unchecked = 0

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Skip blank lines and comments
        if not stripped or stripped.startswith('//') or stripped.startswith('*'):
            continue
        if _SKIP.search(stripped):
            continue

        # Track unchecked blocks
        if _UNCHECKED_BLOCK.search(stripped):
            in_unchecked += stripped.count('{') - stripped.count('}')
            continue
        if in_unchecked > 0:
            in_unchecked += stripped.count('{') - stripped.count('}')
            in_unchecked = max(0, in_unchecked)
            continue

        # Only flag lines that are assignments (=) with arithmetic
        # e.g.  balance = balance + amount;   totalSupply -= value;
        if '=' not in stripped:
            continue

        # Must contain an arithmetic operator next to identifiers
        if not (_UNSAFE_ADD.search(stripped) or _UNSAFE_SUB.search(stripped) or _UNSAFE_MUL.search(stripped)):
            continue

        # Skip if it's a comparison (==, !=, <=, >=)
        if re.search(r'(==|!=|<=|>=)', stripped):
            # Still flag if there's also arithmetic on the right side
            if not re.search(r'=\s*[\w.]+\s*[+\-*]', stripped):
                continue

        # Skip SafeMath calls (already safe)
        if _SAFEMATH_CALL.search(stripped):
            continue

        findings.append({
            'rule_id': 'SOL-004',
            'line': i + 1,
            'snippet': stripped[:120],
        })

    return findings
