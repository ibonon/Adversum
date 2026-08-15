JWT_VULN_PATTERNS = [
    (r'algorithm\s*=\s*["\']none["\']', 'JWT alg=none allows forged tokens', 'CWE-347', 'CRITICAL', 9.1),
    (r'options\s*=\s*\{[^}]*verify_signature.*False', 'JWT signature verification disabled', 'CWE-347', 'CRITICAL', 9.1),
    (r'verify\s*=\s*False', 'JWT verification disabled', 'CWE-347', 'CRITICAL', 9.1),
    (r'jwt\.decode\([^)]+,\s*["\']([\w]{1,12})["\']', 'JWT secret appears too short (<12 chars)', 'CWE-521', 'HIGH', 7.5),
    (r'\.sign\([^,]+,\s*["\']([^"\']*)\1["\']', 'Potential hardcoded JWT secret', 'CWE-798', 'CRITICAL', 9.0),
]
