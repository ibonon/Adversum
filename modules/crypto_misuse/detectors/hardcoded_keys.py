import math, re

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not data:
        return 0.0
    entropy = 0
    for x in set(data):
        p = data.count(x) / len(data)
        entropy -= p * math.log2(p)
    return entropy

# Variables suspectes par nom
SUSPECT_VAR_NAMES = [
    'private_key', 'secret_key', 'api_key', 'aws_secret', 'mnemonic',
    'seed_phrase', 'wallet_key', 'signing_key', 'encryption_key',
    'jwt_secret', 'hmac_key', 'rsa_private', 'eth_key'
]

# Pattern : variable = "valeur" haute entropie
HARDCODED_PATTERN = r'(?:' + '|'.join(SUSPECT_VAR_NAMES) + r')\s*=\s*["\']([^"\']{8,})["\']'
