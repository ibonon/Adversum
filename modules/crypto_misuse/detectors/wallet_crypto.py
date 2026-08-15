WALLET_PATTERNS = [
    # Seed phrase en dur
    (r'mnemonic\s*=\s*["\'][\w\s]{30,}["\']', 'Hardcoded mnemonic seed phrase', 'CWE-798', 'CRITICAL', 10.0),
    # Clé privée Ethereum format
    (r'0x[0-9a-fA-F]{64}', 'Potential hardcoded Ethereum private key', 'CWE-798', 'CRITICAL', 10.0),
    # WIF Bitcoin format
    (r'[5KL][1-9A-HJ-NP-Za-km-z]{50,51}', 'Potential Bitcoin WIF private key', 'CWE-798', 'CRITICAL', 10.0),
    # PBKDF2 faible
    (r'PBKDF2.*iterations\s*=\s*(\d+)', 'PBKDF2 with insufficient iterations', 'CWE-916', 'HIGH', 7.5),
]
