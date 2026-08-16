#!/usr/bin/env python3
"""
Adversum Crypto Misuse Scanner
Detects real cryptographic misuse patterns in source code.
"""
import os
import re
import json

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
    re.compile(
        r'(?:AES_KEY|SECRET_?KEY|PRIVATE_?KEY|API_?SECRET|PASSWORD|PASSWD|PASSPHRASE|HMAC_?KEY|SIGNING_?KEY|AUTH_?TOKEN)\s*=\s*[bBfF]?["\'][^"\']{6,}["\']',
        re.IGNORECASE,
    ),
    # JS/TS const / let / var: const secret = "value"
    re.compile(
        r'(?:const|let|var)\s+(?:secret|apiSecret|privateKey|aesKey|hmacKey|signingKey|password|passwd|authToken|accessToken|secretKey)\s*=\s*[`"\'][^`"\']{6,}[`"\']',
        re.IGNORECASE,
    ),
    # Generic: secret_key = "..." in any language
    re.compile(
        r'\b(?:secret_key|secretkey|api_key|apikey|access_token|auth_token)\s*=\s*["\'][^"\']{8,}["\']',
        re.IGNORECASE,
    ),
    # Solidity / env: hardcoded hex 32-byte keys
    re.compile(
        r'\b(?:private_?key|secret_?key|aes_?key)\s*=\s*(?:0x)?[0-9a-fA-F]{32,}',
        re.IGNORECASE,
    ),
    # .env style: KEY=value (no quotes, long string)
    re.compile(
        r'^(?:SECRET|PRIVATE_KEY|API_SECRET|SIGNING_KEY|AES_KEY|JWT_SECRET)\s*=\s*\S{12,}',
        re.MULTILINE | re.IGNORECASE,
    ),
]

# Exclusion: skip lines that are clearly comments, placeholder templates, or env-var references
EXCLUSION_PATTERNS = [
    re.compile(r'^\s*#'),            # Python comment
    re.compile(r'^\s*//'),           # JS/TS/Solidity comment
    re.compile(r'^\s*\*'),           # JSDoc / block comment
    re.compile(r'\$\{'),             # template variable ${VAR}
    re.compile(r'process\.env\.'),   # Node.js env var
    re.compile(r'os\.environ'),      # Python env var
    re.compile(r'os\.getenv'),       # Python env var
    re.compile(r'getenv\('),         # C / PHP env var
    re.compile(r'System\.getenv'),   # Java env var
    re.compile(r'<YOUR_'),           # placeholder
    re.compile(r'INSERT_'),          # placeholder
    re.compile(r'REPLACE_'),         # placeholder
    re.compile(r'example', re.IGNORECASE),   # example strings
    re.compile(r'placeholder', re.IGNORECASE),
    re.compile(r'TODO', re.IGNORECASE),
    re.compile(r'FIXME', re.IGNORECASE),
    re.compile(r'xxxxxxx', re.IGNORECASE),
    re.compile(r'test.*key', re.IGNORECASE),  # explicit test keys in tests
]

# File extensions that are worth scanning (skip binary / generated / docs)
SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.sol', '.go', '.java', '.rb',
    '.php', '.cs', '.cpp', '.c', '.h', '.rs', '.swift', '.kt',
    '.env', '.cfg', '.ini', '.yaml', '.yml', '.toml', '.json',
    '.sh', '.bash', '.zsh',
}

# Extensions that are test files — downgrade confidence
TEST_FILE_INDICATORS = ('.test.', '.spec.', '_test.', 'test_', 'tests/')

# Fast prefilter pattern: if none of these keywords exist in content, skip entire file instantly
_PREFILTER_PATTERN = re.compile(
    r'(?:secret_key|secretkey|api_key|apikey|private_key|privatekey|signing_key|hmac_key|aes_key|password|passwd|passphrase|auth_token|access_token|jwt|hashlib|md5|sha1|MessageDigest|createHash)',
    re.IGNORECASE,
)


def _is_test_file(path: str) -> bool:
    normalized = path.replace('\\', '/')
    return any(ind in normalized for ind in TEST_FILE_INDICATORS)


def _line_is_excluded(line: str) -> bool:
    return any(p.search(line) for p in EXCLUSION_PATTERNS)


def _scan_for_pattern_matches(content: str, lines: list, patterns: list, rule_id: str, rule: dict, path: str) -> list:
    findings = []
    is_test = _is_test_file(path)
    seen_lines = set()

    # Precalculate newline offsets for fast binary search line lookup
    line_offsets = [0]
    for idx, c in enumerate(content):
        if c == '\n':
            line_offsets.append(idx + 1)

    for pattern in patterns:
        for match in pattern.finditer(content):
            start_pos = match.start()
            lineno = bisect.bisect_right(line_offsets, start_pos)
            if lineno in seen_lines or lineno > len(lines):
                continue
            line = lines[lineno - 1]
            if _line_is_excluded(line):
                continue
            seen_lines.add(lineno)
            snippet = line.strip()[:120]
            # In test files, lower severity (HIGH instead of CRITICAL for CRYPTO-004)
            severity = rule.get('severity', 'MEDIUM')
            if is_test and severity == 'CRITICAL':
                severity = 'HIGH'
            findings.append({
                'rule_id': rule_id,
                'severity': severity,
                'cwe': rule.get('cwe', ''),
                'title': rule.get('title', ''),
                'description': rule.get('description', ''),
                'file': path,
                'line': lineno,
                'snippet': snippet,
                'recommendation': rule.get('recommendation', ''),
                'cvss_score': rule.get('cvss_score', 5.0),
            })
    return findings



class CryptoMisuseScanner:
    def __init__(self):
        kb_path = os.path.join(os.path.dirname(__file__), 'kb', 'crypto_rules.json')
        with open(kb_path, 'r', encoding='utf-8') as f:
            self.kb = json.load(f)['rules']
        self.kb_map = {v['id']: v for v in self.kb}

    def scan_file(self, path: str):
        # Only scan known source file types
        _, ext = os.path.splitext(path)
        if ext.lower() not in SCANNABLE_EXTENSIONS:
            return []

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return []

        # FAST PREFILTER: 99.9% of files do not contain any crypto keyword -> return in 0.0001ms
        if not _PREFILTER_PATTERN.search(content):
            return []

        lines = content.splitlines()
        findings = []

        # --- CRYPTO-001: Weak hash functions ---
        rule_001 = self.kb_map.get('CRYPTO-001', {
            'severity': 'MEDIUM', 'cwe': 'CWE-327',
            'title': 'Weak Hash Function (MD5/SHA1)',
            'description': 'MD5 and SHA1 are cryptographically broken.',
            'recommendation': 'Use SHA-256 or SHA-3.',
            'cvss_score': 5.3,
        })
        findings.extend(
            _scan_for_pattern_matches(content, lines, WEAK_HASH_PATTERNS, 'CRYPTO-001', rule_001, path)
        )

        # --- CRYPTO-004: Hardcoded secrets ---
        rule_004 = self.kb_map.get('CRYPTO-004', {
            'severity': 'CRITICAL', 'cwe': 'CWE-798',
            'title': 'Hardcoded Cryptographic Key or Secret',
            'description': 'A secret value is hardcoded directly in source code.',
            'recommendation': 'Use an HSM or key management system (AWS KMS, HashiCorp Vault).',
            'cvss_score': 10.0,
        })
        findings.extend(
            _scan_for_pattern_matches(content, lines, HARDCODED_SECRET_PATTERNS, 'CRYPTO-004', rule_004, path)
        )

        return findings



def main():
    pass


if __name__ == '__main__':
    main()
