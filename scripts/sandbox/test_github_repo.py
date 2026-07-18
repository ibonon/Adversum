import os
import sys
import shutil
import subprocess
from pathlib import Path

# Add adversum to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from orchestrator.scanner.project_scanner import ProjectScanner
from orchestrator.core_bridge.core_wrapper import CoreWrapper

REPO_URL = "https://github.com/ierox/omnirepurpose-ai-studio.git"
TARGET_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../tmp_repos/omnirepurpose'))

def main():
    if os.path.exists(TARGET_DIR):
        print(f"Cleaning up old repo dir: {TARGET_DIR}")
        import stat
        def remove_readonly(func, path, excinfo):
            os.chmod(path, stat.S_IWRITE)
            func(path)
        shutil.rmtree(TARGET_DIR, onerror=remove_readonly)
    
    print(f"Cloning {REPO_URL} into {TARGET_DIR}...")
    subprocess.run(["git", "clone", REPO_URL, TARGET_DIR], check=True)
    
    print("\nScanning project...")
    scanner = ProjectScanner(TARGET_DIR)
    files = scanner.scan()
    print(f"Found {len(files)} source files.")
    
    print("\nRunning CoreWrapper (Fallback Mode)...")
    core = CoreWrapper()
    findings, hashes, score = core._analyze_fallback(files)
    
    print(f"\nAnalysis complete! Found {len(findings)} potential issues. Robustness Score: {score}")
    
    # Sort and group by severity
    findings.sort(key=lambda x: (x.severity, x.file_path, x.line))
    
    for item in findings:
        file_name = os.path.relpath(item.file_path, TARGET_DIR)
        print(f"[{item.severity}] {item.id} at {file_name}:{item.line}")
        print(f"  > {item.message}")
        print(f"  > Snippet: {item.snippet.strip()[:100]}")
        print("-" * 40)

if __name__ == "__main__":
    main()
