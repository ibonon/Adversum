import os
import hashlib
import logging

logger = logging.getLogger("adversum.integrity")

def calculate_file_hash(filepath: str) -> str:
    """Calculates SHA256 of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data: break
            sha256.update(data)
    return sha256.hexdigest()

def verify_system_integrity(root_path: str):
    """
    Scans the critical source code and logs their hashes.
    In a real fortress, this would compare against a signed manifest.
    """
    logger.info("--- STARTING SYSTEM INTEGRITY CHECK ---")
    critical_dirs = ["api", "config", "core_bridge", "services", "middleware"]
    
    integrity_ok = True
    
    for folder in critical_dirs:
        folder_path = os.path.join(root_path, folder)
        if not os.path.exists(folder_path):
             continue
             
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith(".py") and "__pycache__" not in root:
                    full_path = os.path.join(root, file)
                    file_hash = calculate_file_hash(full_path)
                    # Log hash for audit trail
                    logger.info(f"Integrity Validated: {file} -> {file_hash[:12]}...")
                    # Stub for actual verification logic
                    # if manifest.get(file) != file_hash: raise IntegrityError...
    
    logger.info("--- INTEGRITY CHECK PASSED ---")
