import subprocess
import os
import shutil
from dataclasses import dataclass
from typing import List, Optional
from contextlib import contextmanager

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
    """Clones a repository and returns its context."""
    import uuid
    repo_name = url.split("/")[-1].replace(".git", "")
    # Append UUID to ensure unique path for every scan
    unique_id = str(uuid.uuid4())[:8]
    target_dir = os.path.join(target_base_dir, f"{repo_name}_{unique_id}")
    
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir, ignore_errors=True) # Clean start
    
    print(f"Cloning {url} to {target_dir}...")
    try:
        subprocess.check_call(
            ["git", "clone", "--depth", "1", url, target_dir], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("Notice: Git clone failed or Git not found. Ensuring target directory exists.")
        os.makedirs(target_dir, exist_ok=True)
    
    # Collect files
    files = []
    for root, _, filenames in os.walk(target_dir):
        if ".git" in root:
            continue
        for f in filenames:
            ext = os.path.splitext(f)[1]
            if ext in [".py", ".rs", ".js", ".ts", ".sol", ".c", ".cpp", ".java"]:
                full_path = os.path.join(root, f)
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as file_obj:
                        content = file_obj.read()
                    files.append(SourceFile(path=full_path, content=content, language=ext[1:]))
                except Exception as e:
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
