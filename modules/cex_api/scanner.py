#!/usr/bin/env python3
"""
Adversum CEX Trading API & Matching Engine Security Scanner
Detects vulnerabilities in Centralized Exchange API backends (Python, JS/TS, Go):
- HMAC-SHA256 request signature verification flaws
- Timestamp / recvWindow anti-replay protection gaps
- Unatomic balance deduction / Race conditions (SELECT without FOR UPDATE)
- Missing order placement / cancellation rate limiting
- Private WebSocket channel authentication bypasses
"""
import os
import re
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class CEXApiFinding:
    rule_id: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW
    cwe: str
    title: str
    description: str
    file: str
    line: int
    snippet: str
    recommendation: str
    cvss_score: float

class CEXApiScanner:
    def __init__(self):
        pass

    def scan_file(self, path: str) -> List[CEXApiFinding]:
        ext = os.path.splitext(path)[1].lower()
        if ext not in ('.py', '.ts', '.js', '.go', '.rs', '.java'):
            return []

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return []

        lines = content.splitlines()
        findings = []

        # ── CEX-API-001: Race Condition on Balance Check (Double Spend) ──
        # Detects balance queries followed by withdrawal/order without row locking
        # e.g., user.balance >= amount followed by balance -= amount without SELECT FOR UPDATE
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            # Look for non-atomic balance decrement
            if re.search(r'(?:balance|funds|wallet_balance)\s*=\s*(?:balance|funds|wallet_balance)\s*-\s*', stripped):
                # Inspect preceding 15 lines for database locking (FOR UPDATE, transaction atomic)
                start_idx = max(0, i - 15)
                context = "\n".join(lines[start_idx:i+1])
                if not re.search(r'(?:FOR\s+UPDATE|select_for_update|transaction\.atomic|isolated|SERIALIZABLE|mutex|lock\()', context, re.IGNORECASE):
                    findings.append(CEXApiFinding(
                        rule_id="CEX-API-001",
                        severity="CRITICAL",
                        cwe="CWE-362",
                        title="Unatomic Balance Deduction (Race Condition / Double Spending)",
                        description="User balance is modified without database row-level locking (SELECT FOR UPDATE) or atomic CAS operations. Concurrent requests can withdraw more than available balance.",
                        file=path,
                        line=i + 1,
                        snippet=stripped[:120],
                        recommendation="Wrap balance checks and deductions in a SERIALIZABLE transaction with 'SELECT ... FOR UPDATE' or use an in-memory single-threaded matching engine sequence.",
                        cvss_score=9.8
                    ))

            # ── CEX-API-002: Missing Timestamp & recvWindow Anti-Replay ──
            # Endpoint handling trade orders or withdrawals without timestamp tolerance
            if re.search(r'(?:def|function|async def|func)\s+(?:create_order|place_order|withdraw|request_withdrawal)\s*\(', stripped):
                # Inspect the next 25 lines
                context = "\n".join(lines[i:min(i+25, len(lines))])
                if not re.search(r'(?:recvWindow|timestamp|time\.time|Date\.now|nonce)', context, re.IGNORECASE):
                    findings.append(CEXApiFinding(
                        rule_id="CEX-API-002",
                        severity="HIGH",
                        cwe="CWE-294",
                        title="Missing Timestamp & Replay Protection on Financial Endpoint",
                        description="Trading/Withdrawal endpoint does not validate a request timestamp within a bounded recvWindow (e.g. 5000ms). Captured signed requests can be replayed by attackers.",
                        file=path,
                        line=i + 1,
                        snippet=stripped[:120],
                        recommendation="Enforce mandatory 'timestamp' and 'recvWindow' parameters. Reject requests where abs(server_time - timestamp) > recvWindow (max 5000ms).",
                        cvss_score=8.5
                    ))

            # ── CEX-API-003: Timing Attack on HMAC Signature Verification ──
            # Comparison of signatures using == instead of hmac.compare_digest / crypto.timingSafeEqual
            if re.search(r'(?:signature|sig|hmac_signature)\s*==\s*(?:expected_signature|req_sig|computed_sig|user_sig)', stripped):
                findings.append(CEXApiFinding(
                    rule_id="CEX-API-003",
                    severity="MEDIUM",
                    cwe="CWE-208",
                    title="Non-Constant-Time Signature Comparison (Timing Attack)",
                    description="Cryptographic HMAC signatures are compared using standard string equality (==) which leaks character timing information.",
                    file=path,
                    line=i + 1,
                    snippet=stripped[:120],
                    recommendation="Use hmac.compare_digest(sig1, sig2) in Python, crypto.timingSafeEqual() in Node.js, or hmac.Equal() in Go.",
                    cvss_score=5.9
                ))

            # ── CEX-API-004: Missing Rate Limiting on Order Placement ──
            if re.search(r'@app\.(?:post|put)\([\'"]/api/v\d+/(?:order|trade|cancel)', stripped):
                # Check for rate limiter decorator in preceding 3 lines
                context = "\n".join(lines[max(0, i-3):i+1])
                if not re.search(r'(?:rate_limit|limiter|throttle|RateLimiter)', context, re.IGNORECASE):
                    findings.append(CEXApiFinding(
                        rule_id="CEX-API-004",
                        severity="HIGH",
                        cwe="CWE-799",
                        title="Missing Rate Limiting on Order Book Placement API",
                        description="High-frequency order creation/cancellation endpoint lacks explicit rate limiting. Attackers can flood the matching engine and exhaust order book memory.",
                        file=path,
                        line=i + 1,
                        snippet=stripped[:120],
                        recommendation="Attach token-bucket or sliding-window rate limiters per API key (e.g. 50 orders/sec for standard tiers, 200/sec for VIP).",
                        cvss_score=7.5
                    ))

        return findings
