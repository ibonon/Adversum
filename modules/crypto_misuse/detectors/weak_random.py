WEAK_RANDOM_PATTERNS = [
    (r'random\.random\(\)', 'Non-cryptographic PRNG random.random() for security use', 'CWE-338', 'HIGH'),
    (r'random\.randint\(', 'Non-cryptographic PRNG for sensitive data', 'CWE-338', 'HIGH'),
    (r'Math\.random\(\)', 'Math.random() is not cryptographically secure', 'CWE-338', 'HIGH'),
    (r'new Random\(\)', 'java.util.Random is not cryptographically secure', 'CWE-338', 'HIGH'),
    # OK patterns à ignorer
    (r'secrets\.token_bytes', None, None, None),  # whitelist
    (r'os\.urandom', None, None, None),           # whitelist
]
