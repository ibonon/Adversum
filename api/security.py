"""
Security utilities for validating and sanitizing user inputs.

This module provides functions to prevent common security vulnerabilities
like path traversal attacks.
"""

from pathlib import Path
from typing import List
from fastapi import HTTPException
from urllib.parse import urlparse
import os

# Dynamic default root based on repository location
DEFAULT_ROOT = str(Path(__file__).resolve().parent.parent)

# Whitelist of allowed base directories for scanning
# Can be configured via environment variable
ALLOWED_BASES: List[Path] = [
    Path(os.getenv("ALLOWED_SCAN_DIR", DEFAULT_ROOT)).resolve(),
    Path(DEFAULT_ROOT).resolve() / "temp_test_project",
    Path(DEFAULT_ROOT).resolve() / "tests",
]

# Hosts allowed for remote git cloning. Override with ALLOWED_GIT_HOSTS
# (comma-separated) when self-hosting on a private Git server.
ALLOWED_GIT_HOSTS = {
    h.strip().lower()
    for h in os.getenv("ALLOWED_GIT_HOSTS", "github.com,gitlab.com,bitbucket.org").split(",")
    if h.strip()
}

# Hardening flags prepended to every `git clone` invocation.
#  - protocol.ext.allow=never  -> blocks `ext::` command execution (RCE)
#  - protocol.file.allow=never -> blocks `file://` local reads via git
#  - gc.auto=0                 -> prevents surprise repacking during scans
GIT_SAFE_ARGS: List[str] = [
    "-c", "protocol.ext.allow=never",
    "-c", "protocol.file.allow=never",
    "-c", "gc.auto=0",
    "-c", "credential.helper=",
]


def git_safe_env(base: dict | None = None) -> dict:
    """Environment for git subprocesses: no prompts, no exotic transports."""
    env = dict(os.environ if base is None else base)
    env["GIT_TERMINAL_PROMPT"] = "0"
    # Belt-and-braces with the -c flags above.
    env["GIT_ALLOW_PROTOCOL"] = "https"
    return env

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
    
    # We re-evaluate ALLOWED_BASES here to pick up env changes.
    # NOTE: all bases are anchored on the project root, never on the process
    # CWD (which differs between `uvicorn api.main:app` and a CLI invocation).
    dynamic_bases = [
        Path(os.getenv("ALLOWED_SCAN_DIR", DEFAULT_ROOT)).resolve(),
        Path(DEFAULT_ROOT).resolve() / "temp_test_project",
        Path(DEFAULT_ROOT).resolve() / "tests",
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


def is_git_url(path_str: str) -> bool:
    """
    Check if the provided string refers to a remote git repository
    (as opposed to a local filesystem path).
    """
    value = (path_str or "").strip().lower()
    return (
        value.startswith("http://")
        or value.startswith("https://")
        or value.startswith("git@")
        or value.startswith("ssh://")
        or value.endswith(".git")
    )


def validate_repo_url(url: str) -> str:
    """
    Validate a user-supplied git URL before it reaches `git clone`.

    Blocks, in order:
      * empty / over-long values
      * whitespace, control characters and newlines (argument injection)
      * values starting with '-' (git would parse them as options)
      * non-HTTPS transports, including git's `ext::` helper (command execution)
      * hosts outside ALLOWED_GIT_HOSTS (prevents SSRF to internal services
        and cloud metadata endpoints such as 169.254.169.254)
      * embedded credentials (``https://token@host/...``)
      * path traversal / option-smuggling inside the path or query

    Returns the trimmed URL on success, raises HTTPException otherwise.
    """
    if not url or not isinstance(url, str):
        raise HTTPException(status_code=400, detail="repo_url is required")

    value = url.strip()

    if len(value) > 500:
        raise HTTPException(status_code=400, detail="repo_url too long (max 500 chars)")
    if any(c.isspace() for c in value) or any(ord(c) < 32 for c in value):
        raise HTTPException(status_code=400, detail="repo_url must not contain whitespace or control characters")
    if value.startswith("-"):
        raise HTTPException(status_code=400, detail="repo_url must not start with '-'")
    if "::" in value:
        # git transport helpers: ext::, fd::, etc. -> arbitrary command execution
        raise HTTPException(status_code=400, detail="repo_url uses a forbidden git transport")

    parsed = urlparse(value)
    if parsed.scheme.lower() != "https":
        raise HTTPException(
            status_code=400,
            detail="repo_url must use HTTPS (http, ssh, git and file transports are disabled)",
        )
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        raise HTTPException(status_code=400, detail="repo_url must not embed credentials")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="repo_url has no host")

    host = parsed.hostname.lower()
    if host not in ALLOWED_GIT_HOSTS:
        raise HTTPException(
            status_code=403,
            detail=f"Host '{host}' is not allowed. Allowed: {', '.join(sorted(ALLOWED_GIT_HOSTS))}",
        )

    if ".." in parsed.path:
        raise HTTPException(status_code=400, detail="repo_url path must not contain '..'")

    return value
