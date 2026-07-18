from cryptography.fernet import Fernet
from ..config.settings import settings

# Initialize Fernet with the key
# If key is invalid, this will crash startup (Good, Fail Safe)
cipher = Fernet(settings.DATA_ENCRYPTION_KEY.encode())

def encrypt_data(data: str) -> str:
    """
    Encrypts a string using AES (Fernet).
    Returns URL-safe base64 encoded bytes as string.
    """
    if data is None: 
        return None
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(token: str) -> str:
    """
    Decrypts the token back to original string.
    """
    if token is None: 
        return None
    try:
        return cipher.decrypt(token.encode()).decode()
    except Exception:
        # If decryption fails (tampering/key rotation), return indicator
        return "[ENCRYPTED/CORRUPTED]"
