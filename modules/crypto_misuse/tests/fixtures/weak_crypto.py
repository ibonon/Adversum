# Simule le backend d'un CEX avec mauvaises pratiques crypto
import hashlib
from Crypto.Cipher import AES, DES
import random

# CWE-798 : Clé hardcodée
AES_KEY = b"mysecretkey12345"  # VULN: hardcoded key
DES_KEY = b"weakkey1"          # VULN: DES + hardcoded

def hash_transaction(tx_data: str) -> str:
    # VULN: MD5 pour hash de transaction
    return hashlib.md5(tx_data.encode()).hexdigest()

def generate_session_token() -> str:
    # VULN: random non-crypto pour token de session
    return str(random.randint(100000, 999999))

def encrypt_withdrawal(amount: float, address: str) -> bytes:
    # VULN: AES en mode ECB
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    data = f"{amount}:{address}".encode().ljust(16)
    return cipher.encrypt(data)
