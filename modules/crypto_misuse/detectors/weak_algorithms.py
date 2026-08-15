WEAK_ALGO_PATTERNS = [
    # Python hashlib
    (r'hashlib\.md5\(', 'CRYPTO-001', 'MD5 usage detected', 'CWE-327', 'MEDIUM', 5.3),
    (r'hashlib\.sha1\(', 'CRYPTO-001b', 'SHA-1 usage detected', 'CWE-327', 'MEDIUM', 5.3),
    (r'DES\.new\(', 'CRYPTO-002', 'DES cipher (56-bit) is cryptographically broken', 'CWE-326', 'HIGH', 7.5),
    (r'AES\.new\(.*MODE_ECB', 'CRYPTO-003', 'AES-ECB mode leaks plaintext patterns', 'CWE-327', 'HIGH', 7.4),
    # JS crypto
    (r'createCipheriv\(["\']des', 'CRYPTO-002', 'DES cipher detected', 'CWE-326', 'HIGH', 7.5),
    (r'createHash\(["\']md5', 'CRYPTO-001', 'MD5 hash function detected', 'CWE-327', 'MEDIUM', 5.3),
    # Java
    (r'MessageDigest\.getInstance\(["\']MD5', 'CRYPTO-001', 'MD5 usage in Java', 'CWE-327', 'MEDIUM', 5.3),
    (r'Cipher\.getInstance\(["\']DES', 'CRYPTO-002', 'DES cipher in Java', 'CWE-326', 'HIGH', 7.5),
]
