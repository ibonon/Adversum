import os
import re
from fastapi import HTTPException

# Regex for very basic strict filename validation if needed, 
# but mostly we care about path traversal and system directories.
SUSPICIOUS_PATH_PATTERN = re.compile(r"(\.\./|\.\.\\|~)")

def validate_project_path(path: str) -> str:
    """
    Sanitizes and validates the project path.
    1. Must exist.
    2. Must be a directory.
    3. Must be absolute (converts if relative).
    4. Must NOT be a sensitive system directory (C:\Windows, /etc, etc).
    """
    # 1. Resolve absolute
    abs_path = os.path.abspath(path)
    
    # 2. Check existence
    if not os.path.exists(abs_path):
        raise HTTPException(status_code=400, detail="Path does not exist.")
    
    if not os.path.isdir(abs_path):
        raise HTTPException(status_code=400, detail="Path is not a directory.")

    # 3. Block sensitive paths (basic heuristic for Windows/Linux)
    # This prevents scanning the entire OS by mistake
    sensitive_roots = [
        "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
        "/etc", "/usr", "/var", "/bin", "/sbin"
    ]
    
    for sensitive in sensitive_roots:
        if abs_path.startswith(sensitive):
             raise HTTPException(status_code=403, detail=f"Scanning system directory '{sensitive}' is forbidden.")

    return abs_path
