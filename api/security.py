"""
Security utilities for validating and sanitizing user inputs.

This module provides functions to prevent common security vulnerabilities
like path traversal attacks.
"""

from pathlib import Path
from typing import List
from fastapi import HTTPException
import os

# Dynamic default root based on repository location
DEFAULT_ROOT = str(Path(__file__).resolve().parent.parent)

# Whitelist of allowed base directories for scanning
# Can be configured via environment variable
ALLOWED_BASES: List[Path] = [
    Path(os.getenv("ALLOWED_SCAN_DIR", DEFAULT_ROOT)).resolve(),
    Path(".").resolve() / "temp_test_project",
    Path(".").resolve() / "tests",
]

def validate_scan_path(path_str: str) -> Path:
    """
    Validate and sanitize a user-provided path to prevent directory traversal attacks.
    Explicitly handles Windows path normalization.
    """
    try:
        # Normalize and resolve to absolute path
        p = Path(path_str)
        if not p.is_absolute():
            # If relative, we assume it's relative to the first allowed base or CWD
            # but to be safe we enforce absolute paths from the client for now.
            # Actually, let's allow relative to Adversum root for convenience in dev.
            base = Path(os.getenv("ADVERSUM_ROOT", DEFAULT_ROOT)).resolve()
            requested_path = (base / p).resolve()
        else:
            requested_path = p.resolve()
            
    except (ValueError, OSError) as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid path format: {e}"
        )
    
    # Check if path exists
    if not requested_path.exists():
        raise HTTPException(
            status_code=400,
            detail=f"Path does not exist: {requested_path}"
        )
    
    # Check if path is a directory (we only scan directories)
    if not requested_path.is_dir():
        raise HTTPException(
            status_code=400,
            detail=f"Path must be a directory: {requested_path}"
        )
    
    # Security: Check against whitelist
    is_allowed = False
    
    # We re-evaluate ALLOWED_BASES here to pick up env changes
    dynamic_bases = [
        Path(os.getenv("ALLOWED_SCAN_DIR", DEFAULT_ROOT)).resolve(),
        Path(".").resolve() / "temp_test_project",
    ]
    
    for allowed_base in dynamic_bases:
        try:
            # Check if requested_path is within allowed_base
            requested_path.relative_to(allowed_base)
            is_allowed = True
            break
        except ValueError:
            continue
    
    if not is_allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied. Path '{requested_path}' is outside restricted zones."
        )
    
    return requested_path


def is_safe_filename(filename: str) -> bool:
    """
    Check if a filename is safe (no path traversal attempts).
    
    Args:
        filename: Filename to check
        
    Returns:
        True if safe, False otherwise
    """
    # Reject filenames containing path separators or parent directory references
    dangerous_patterns = ["..", "/", "\\\\", "\0"]
    return not any(pattern in filename for pattern in dangerous_patterns)

def is_git_url(path_str: str) -> bool:
    """
    Check if the provided string is a likely Git URL.
    """
    return path_str.startswith("http://") or path_str.startswith("https://") or path_str.startswith("git@") or path_str.endswith(".git")
