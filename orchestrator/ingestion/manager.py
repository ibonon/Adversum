import subprocess
import os
import re
import shutil
from dataclasses import dataclass
from typing import List, Optional
from contextlib import contextmanager

# Hardening flags prefixed to every git invocation (see api/security.py).
_GIT_SAFE_ARGS = [
    "-c", "protocol.ext.allow=never",
    "-c", "protocol.file.allow=never",
    "-c", "gc.auto=0",
]

# Guard rails against resource exhaustion on hostile / gigantic repositories.
MAX_FILES = int(os.getenv("MAX_REPO_FILES", "50000"))
MAX_TOTAL_BYTES = int(os.getenv("MAX_REPO_BYTES", str(512 * 1024 * 1024)))  # 512 MB
CLONE_TIMEOUT_S = int(os.getenv("GIT_CLONE_TIMEOUT_S", "600"))


class CloneError(RuntimeError):
    """Raised when a remote repository cannot be materialised locally."""


def _git_env() -> dict:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "echo"
    env["GIT_ALLOW_PROTOCOL"] = "https"
    return env


def _safe_repo_name(url: str) -> str:
    """Derives a filesystem-safe directory name from a repository URL."""
    tail = url.rstrip("/").split("/")[-1]
    tail = tail[:-4] if tail.endswith(".git") else tail
    tail = re.sub(r"[^A-Za-z0-9._-]", "_", tail)
    if not tail or tail in {".", ".."}:
        tail = "repo"
    return tail[:64]


@dataclass
class SourceFile:
    path: str
    content: str
    language: str

@dataclass
class RepoContext:
    url: str
    local_path: str
    files: List[SourceFile]

def clone_repository(url: str, target_base_dir: str = "./tmp_repos") -> RepoContext:
    """
    Clones a repository and returns its context.

    Raises CloneError if the clone fails — silently producing an empty
    directory here used to turn a failed clone into a "0 findings" success,
    which is the worst possible failure mode for a security scanner.
    """
    import uuid
    repo_name = _safe_repo_name(url)
    unique_id = str(uuid.uuid4())[:8]
    target_dir = os.path.join(target_base_dir, f"{repo_name}_{unique_id}")

    if os.path.exists(target_dir):
        shutil.rmtree(target_dir, ignore_errors=True)  # Clean start

    print(f"Cloning {url} to {target_dir}...")
    try:
        subprocess.check_call(
            ["git", *_GIT_SAFE_ARGS, "clone", "--depth", "1", url, target_dir],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=CLONE_TIMEOUT_S,
            env=_git_env(),
        )
    except FileNotFoundError as exc:
        raise CloneError("git executable not found on this host") from exc
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(target_dir, ignore_errors=True)
        raise CloneError(f"git clone timed out after {CLONE_TIMEOUT_S}s") from exc
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(target_dir, ignore_errors=True)
        stderr = (exc.stderr or b"").decode("utf-8", "replace").strip()
        raise CloneError(f"git clone failed: {stderr[:500] or 'unknown error'}") from exc

    # Collect files
    files = []
    total_bytes = 0
    for root, _, filenames in os.walk(target_dir):
        if ".git" in root:
            continue
        for f in filenames:
            ext = os.path.splitext(f)[1]
            if ext in [".py", ".rs", ".js", ".ts", ".sol", ".c", ".cpp", ".java"]:
                full_path = os.path.join(root, f)
                try:
                    size = os.path.getsize(full_path)
                    if total_bytes + size > MAX_TOTAL_BYTES or len(files) >= MAX_FILES:
                        raise CloneError(
                            f"repository exceeds ingestion limits "
                            f"({MAX_FILES} files / {MAX_TOTAL_BYTES // (1024 * 1024)} MB)"
                        )
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as file_obj:
                        content = file_obj.read()
                    total_bytes += size
                    files.append(SourceFile(path=full_path, content=content, language=ext[1:]))
                except OSError as e:
                    print(f"Skipping {f}: {e}")

    return RepoContext(url=url, local_path=target_dir, files=files)

def cleanup_repository(repo_context: RepoContext) -> None:
    """Safely cleans up the cloned repository directory to prevent disk exhaustion."""
    if repo_context and repo_context.local_path and os.path.exists(repo_context.local_path):
        try:
            shutil.rmtree(repo_context.local_path, ignore_errors=True)
        except Exception as e:
            print(f"Warning: Failed to clean up {repo_context.local_path}: {e}")

@contextmanager
def managed_repository(url: str, target_base_dir: str = "./tmp_repos"):
    """Context manager that clones and automatically cleans up temporary repositories."""
    ctx = clone_repository(url, target_base_dir)
    try:
        yield ctx
    finally:
        cleanup_repository(ctx)

def detect_languages(repo_path: str) -> List[str]:
    """Detects languages in the repository."""
    langs = set()
    for root, _, filenames in os.walk(repo_path):
        if ".git" in root: continue
        for f in filenames:
            ext = os.path.splitext(f)[1]
            if ext == ".py": langs.add("python")
            elif ext == ".rs": langs.add("rust")
            elif ext in [".js", ".ts", ".jsx", ".tsx"]: langs.add("javascript")
            elif ext == ".sol": langs.add("solidity")
    return list(langs)
