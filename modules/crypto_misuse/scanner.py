#!/usr/bin/env python3
"""
Adversum Crypto Misuse Scanner - v3.0 (Enterprise-Grade False Positive Filters)

5 layers of intelligent false positive reduction:
  Layer 1 - File-level  : Skip test/spec/fixture/mock files entirely for CRYPTO-004
  Layer 2 - Value-level : Skip sentinel/mock/placeholder/masking values
  Layer 3 - Context-level: Skip lines used for assertion/logging/redaction/URL-parsing
  Layer 4 - SHA-1 context: Only flag SHA-1 when used for security (not cache/checksum)
  Layer 5 - Format check : Require realistic-looking credential format (min length, prefix)
"""
import os
import re
import json
import bisect

# ---------------------------------------------------------------------------
# Layer 1 — File classification: Test vs Script vs Production
# ---------------------------------------------------------------------------
TEST_FILE_PATTERNS = re.compile(
    r'(?:\.test\.|\.spec\.|\.e2e\.|_test\.|/test/|/tests/|/__tests__/|/test-helpers?/|'
    r'test-support|\.fixture\.|/fixture|/mock|/fake|/stub|/harness|/sandbox)',
    re.IGNORECASE,
)
SCRIPT_FILE_PATTERNS = re.compile(
    r'(?:/scripts?/|/tools?/|/bench(?:mark)?s?/)',
    re.IGNORECASE,
)

def _classify_file(path: str) -> str:
    """Returns 'test', 'script', or 'production'."""
    normalized = path.replace('\\', '/')
    if TEST_FILE_PATTERNS.search(normalized):
        return 'test'
    if SCRIPT_FILE_PATTERNS.search(normalized):
        return 'script'
    return 'production'

# ---------------------------------------------------------------------------
# Layer 4 — SHA-1 safe context: non-security uses (cache, checksum, npm shasum)
# ---------------------------------------------------------------------------
SHA1_SAFE_CONTEXT_PATTERNS = re.compile(
    r'(?:shasum|checksum|cache|fingerprint|etag|content.address|artifact|'
    r'\.slice\s*\(\s*0\s*,|npm.*sha|sha.*npm|bundle.*hash|hash.*bundle|'
    r'write.*metadata|startup.*metadata|cli.*startup|file.*digest|digest.*file)',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Patterns for CRYPTO-001 — Weak hash functions
# ---------------------------------------------------------------------------
WEAK_HASH_PATTERNS = [
    re.compile(r'\bhashlib\.md5\s*\(', re.IGNORECASE),
    re.compile(r'\bhashlib\.sha1\s*\(', re.IGNORECASE),
    re.compile(r'\bMD5\s*\(', re.IGNORECASE),
    re.compile(r'\bSHA1\s*\(', re.IGNORECASE),
    re.compile(r'new\s+MD5\s*\(', re.IGNORECASE),
    re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', re.IGNORECASE),
    re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']SHA-1["\']', re.IGNORECASE),
    re.compile(r'createHash\s*\(\s*["\']md5["\']', re.IGNORECASE),
    re.compile(r'createHash\s*\(\s*["\']sha1["\']', re.IGNORECASE),
]

import bisect

# Patterns for CRYPTO-004 — Hardcoded secrets / cryptographic keys
HARDCODED_SECRET_PATTERNS = [
    # Python: AES_KEY = b"..."  /  secret = "..."  /  password = '...'
    # High-specificity key names with realistic value length (>= 10 chars)
    re.compile(
        r'(?:AES_KEY|SECRET_?KEY|PRIVATE_?KEY|API_?SECRET|SIGNING_?KEY|HMAC_?KEY|JWT_?SECRET)\s*=\s*[bBfF]?["\'][^"\']{10,}["\']',
        re.IGNORECASE,
    ),
    # JS/TS: const privateKey / secretKey / hmacKey = "..." (NOT generic "token" or "password")
    re.compile(
        r'(?:const|let|var)\s+(?:privateKey|secretKey|aesKey|hmacKey|signingKey|apiSecret|jwtSecret)\s*=\s*[`"\']\s*[^`"\']{10,}[`"\']',
        re.IGNORECASE,
    ),
    # Generic: api_key = "..." / access_token = "..." (min 12 chars to avoid short stubs)
    re.compile(
        r'\b(?:api_key|apikey|access_token)\s*=\s*["\'][^"\']{12,}["\']',
        re.IGNORECASE,
    ),
    # .env-style file entries: KEY=<long value, no quotes>
    re.compile(
        r'^(?:SECRET|PRIVATE_KEY|API_SECRET|SIGNING_KEY|AES_KEY|JWT_SECRET)\s*=\s*\S{16,}$',
        re.MULTILINE | re.IGNORECASE,
    ),
    # Hardcoded 32+ char hex key (actual cryptographic material)
    re.compile(
        r'\b(?:private_?key|secret_?key|aes_?key)\s*=\s*(?:0x)?[0-9a-fA-F]{32,}',
        re.IGNORECASE,
    ),
    # Layer 5 — Real API key formats by prefix (very high precision)
    re.compile(
        r'["\'](?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36,}|gho_[a-zA-Z0-9]{36,}|'
        r'glpat-[a-zA-Z0-9]{20,}|xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]{24,}|'
        r'AKIA[0-9A-Z]{16,}|AIza[0-9A-Za-z_-]{35,})["\']',
    ),
]

# ---------------------------------------------------------------------------
# Layer 2 — Value-level: mock / sentinel / placeholder / masking detection
# If the assigned VALUE matches these, it is NOT a real credential.
# ---------------------------------------------------------------------------
_MOCK_VALUE_PATTERN = re.compile(
    r'(?:'
    r'["\'](?:test-\w|mock-\w|fake-\w|fixture-\w|stub-\w|dummy-\w|sample-\w|example-\w)["\']|'  # labelled test values
    r'["\'](?:redacted|REDACTED|censored|masked|removed|hidden)["\']|'  # masking/redaction
    r'["\'](?:your-\w|<YOUR_|INSERT_HERE|REPLACE_THIS|xxx+|aaa+)["\']|'  # placeholders
    r'["\'](?:HEARTBEAT_OK|NO_REPLY|ANNOUNCE_SKIP|REPLY_SKIP)["\']|'     # sentinels
    r'["\'][a-zA-Z0-9_-]{1,8}["\'](?!\s*\+)'                            # too-short strings
    r')',
    re.IGNORECASE,
)

def _value_is_mock(line: str) -> bool:
    """Layer 2: True if the string VALUE on this line looks like a test fixture, not a real secret."""
    return bool(_MOCK_VALUE_PATTERN.search(line))

# ---------------------------------------------------------------------------
# Layer 3 — Context-level: lines that are ABOUT secrets, not STORING them
# ---------------------------------------------------------------------------
EXCLUSION_PATTERNS = [
    # Standard comments
    re.compile(r'^\s*#'),
    re.compile(r'^\s*//'),
    re.compile(r'^\s*\*'),
    re.compile(r'^\s*/\*'),
    # Environment variable references
    re.compile(r'\$\{'),
    re.compile(r'process\.env\.'),
    re.compile(r'os\.environ'),
    re.compile(r'os\.getenv'),
    re.compile(r'getenv\('),
    re.compile(r'System\.getenv'),
    re.compile(r'config\['),
    re.compile(r'settings\.'),
    # Template markers
    re.compile(r'<YOUR_'),
    re.compile(r'INSERT_'),
    re.compile(r'REPLACE_'),
    re.compile(r'\{\{'),
    # Test assertions (testing FOR secret handling, not STORING secrets)
    re.compile(r'\bexpect\s*\('),
    re.compile(r'\bassertIn\s*\('),
    re.compile(r'\bassertEqual\s*\('),
    re.compile(r'\btoContain\s*\('),
    re.compile(r'\bnot\.toContain\s*\('),
    re.compile(r'\btoEqual\s*\('),
    re.compile(r'\btoMatchObject\s*\('),
    # Logging
    re.compile(r'\bconsole\.(log|warn|error|debug)\s*\('),
    re.compile(r'\bprint\s*\('),
    re.compile(r'\blogger\.(info|warn|error|debug)\s*\('),
    # Redaction / masking operations
    re.compile(r'\.password\s*=\s*["\']redacted["\']', re.IGNORECASE),
    re.compile(r'\bredact\b', re.IGNORECASE),
    re.compile(r'\bcensor\b', re.IGNORECASE),
    # String-search / parse operations (detecting secrets in other strings)
    re.compile(r'\.includes\s*\('),
    re.compile(r'\.contains\s*\('),
    re.compile(r'\.indexOf\s*\('),
    re.compile(r'\.startsWith\s*\('),
    re.compile(r'\.endsWith\s*\('),
    re.compile(r'\.slice\s*\('),
    re.compile(r'\.replace\s*\('),
    re.compile(r'not\.toContain'),
    # Developer suppression annotations
    re.compile(r'pragma:\s*allowlist\s*secret', re.IGNORECASE),
    re.compile(r'\bnosec\b', re.IGNORECASE),
    re.compile(r'\bnoqa\b', re.IGNORECASE),
    # Platform internal tokens (not user credentials)
    re.compile(r'OPENCLAW_', re.IGNORECASE),
]

# File extensions that are worth scanning (skip binary / generated / docs)
SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.sol', '.go', '.java', '.rb',
    '.php', '.cs', '.cpp', '.c', '.h', '.rs', '.swift', '.kt',
    '.env', '.cfg', '.ini', '.yaml', '.yml', '.toml', '.json',
    '.sh', '.bash', '.zsh',
}

# Fast prefilter: skip files that don't mention any relevant crypto keyword
_PREFILTER_PATTERN = re.compile(
    r'(?:secret_key|secretkey|api_key|apikey|private_key|privatekey|signing_key|'
    r'hmac_key|aes_key|passphrase|auth_token|access_token|jwt_secret|'
    r'hashlib|createHash|MessageDigest|sk-[a-z]|ghp_|AKIA)',
    re.IGNORECASE,
)
_HASH_PREFILTER = re.compile(
    r'(?:md5|sha1|sha-1|MessageDigest|createHash|hashlib)',
    re.IGNORECASE,
)


def _line_is_excluded(line: str) -> bool:
    return any(p.search(line) for p in EXCLUSION_PATTERNS)


def _get_surrounding_lines(lines: list, lineno: int, window: int = 5) -> str:
    start = max(0, lineno - 1 - window)
    end = min(len(lines), lineno + window)
    return '\n'.join(lines[start:end])


def _build_line_index(content: str) -> list:
    offsets = [0]
    for idx, c in enumerate(content):
        if c == '\n':
            offsets.append(idx + 1)
    return offsets


def _scan_secrets(content: str, lines: list, patterns: list,
                  rule_id: str, rule: dict, path: str, file_class: str) -> list:
    """CRYPTO-004 scanner: applies all 5 false positive filter layers."""
    findings = []
    seen_lines = set()
    line_offsets = _build_line_index(content)

    # Layer 1: Skip test files entirely for secret detection
    if file_class == 'test':
        return []

    for pattern in patterns:
        for match in pattern.finditer(content):
            start_pos = match.start()
            lineno = bisect.bisect_right(line_offsets, start_pos)
            if lineno in seen_lines or lineno > len(lines):
                continue
            line = lines[lineno - 1]

            # Layer 3: skip lines used for assertion/logging/redaction/URL-parsing
            if _line_is_excluded(line):
                continue

            # Layer 2: skip lines whose VALUE is a mock/sentinel/placeholder
            if _value_is_mock(line):
                continue

            seen_lines.add(lineno)
            severity = rule.get('severity', 'CRITICAL')
            # Script files: downgrade CRITICAL → HIGH
            if file_class == 'script' and severity == 'CRITICAL':
                severity = 'HIGH'

            findings.append({
                'rule_id': rule_id,
                'severity': severity,
                'cwe': rule.get('cwe', ''),
                'title': rule.get('title', ''),
                'description': rule.get('description', ''),
                'file': path,
                'line': lineno,
                'snippet': line.strip()[:120],
                'recommendation': rule.get('recommendation', ''),
                'cvss_score': rule.get('cvss_score', 10.0),
            })
    return findings


def _scan_hashes(content: str, lines: list, patterns: list,
                 rule_id: str, rule: dict, path: str) -> list:
    """CRYPTO-001 scanner: applies Layer 4 (SHA-1 safe context) filtering."""
    findings = []
    seen_lines = set()
    line_offsets = _build_line_index(content)

    for pattern in patterns:
        for match in pattern.finditer(content):
            start_pos = match.start()
            lineno = bisect.bisect_right(line_offsets, start_pos)
            if lineno in seen_lines or lineno > len(lines):
                continue
            line = lines[lineno - 1]

            # Layer 3: standard comment/assertion exclusions
            if _line_is_excluded(line):
                continue

            # Layer 4: SHA-1 used for caching / checksums is NOT a security issue
            surrounding = _get_surrounding_lines(lines, lineno)
            if SHA1_SAFE_CONTEXT_PATTERNS.search(line) or SHA1_SAFE_CONTEXT_PATTERNS.search(surrounding):
                continue

            seen_lines.add(lineno)
            findings.append({
                'rule_id': rule_id,
                'severity': rule.get('severity', 'MEDIUM'),
                'cwe': rule.get('cwe', ''),
                'title': rule.get('title', ''),
                'description': rule.get('description', ''),
                'file': path,
                'line': lineno,
                'snippet': line.strip()[:120],
                'recommendation': rule.get('recommendation', ''),
                'cvss_score': rule.get('cvss_score', 5.3),
            })
    return findings


class CryptoMisuseScanner:
    def __init__(self):
        kb_path = os.path.join(os.path.dirname(__file__), 'kb', 'crypto_rules.json')
        with open(kb_path, 'r', encoding='utf-8') as f:
            self.kb = json.load(f)['rules']
        self.kb_map = {v['id']: v for v in self.kb}

    def scan_file(self, path: str):
        _, ext = os.path.splitext(path)
        if ext.lower() not in SCANNABLE_EXTENSIONS:
            return []

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return []

        file_class = _classify_file(path)
        findings = []
        lines = content.splitlines()

        # --- CRYPTO-001: Weak hash (with SHA-1 safe-context Layer 4 filter) ---
        if _HASH_PREFILTER.search(content):
            rule_001 = self.kb_map.get('CRYPTO-001', {
                'severity': 'MEDIUM', 'cwe': 'CWE-327',
                'title': 'Weak Hash Function (MD5/SHA1)',
                'description': 'MD5 and SHA1 are cryptographically broken and must not be used for security.',
                'recommendation': 'Use SHA-256 or SHA-3. For passwords, use bcrypt/argon2/scrypt.',
                'cvss_score': 5.3,
            })
            findings.extend(_scan_hashes(content, lines, WEAK_HASH_PATTERNS, 'CRYPTO-001', rule_001, path))

        # --- CRYPTO-004: Hardcoded secrets (all 5 layers active) ---
        if _PREFILTER_PATTERN.search(content):
            rule_004 = self.kb_map.get('CRYPTO-004', {
                'severity': 'CRITICAL', 'cwe': 'CWE-798',
                'title': 'Hardcoded Cryptographic Key or Secret',
                'description': 'A real secret value is hardcoded in production source code.',
                'recommendation': 'Use an HSM or key management system (AWS KMS, HashiCorp Vault).',
                'cvss_score': 10.0,
            })
            findings.extend(_scan_secrets(
                content, lines, HARDCODED_SECRET_PATTERNS,
                'CRYPTO-004', rule_004, path, file_class
            ))

        return findings


def main():
    pass


if __name__ == '__main__':
    main()

