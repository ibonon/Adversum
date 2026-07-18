import os
import sys
import shutil
import subprocess
import re
import hashlib

REPO_URL = "https://github.com/ierox/omnirepurpose-ai-studio.git"
TARGET_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../tmp_repos/omnirepurpose'))

def scan_file(path, patterns):
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        
        lines = content.split('\n')
        for i, line in enumerate(lines):
            for pat, rule_id, severity, msg in patterns:
                if re.search(pat, line):
                    findings.append({
                        "file_path": path,
                        "line": i + 1,
                        "snippet": line.strip(),
                        "id": rule_id,
                        "severity": severity,
                        "message": msg
                    })
    except Exception as e:
        pass
    return findings

def main():
    print(f"--- ADVERSUM STANDALONE SCANNER (Dependency-Free Mode) ---\n")
    if os.path.exists(TARGET_DIR):
        print(f"Cleaning up old repo dir: {TARGET_DIR}")
        import stat
        def remove_readonly(func, path, excinfo):
            os.chmod(path, stat.S_IWRITE)
            func(path)
        shutil.rmtree(TARGET_DIR, onerror=remove_readonly)
    
    print(f"Cloning {REPO_URL} into {TARGET_DIR}...")
    try:
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL, TARGET_DIR], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to clone: {e.stderr.decode()}")
        return
        
    patterns = [
        (r"AWS_ACCESS_KEY\s*=\s*['\"](AKIA[0-9A-Z]{16})['\"]", "HARDCODED_SECRET", "CRITICAL", "Hardcoded AWS Access Key detected"),
        (r"subprocess\.run\(.*shell=True.*\)", "COMMAND_INJECTION", "CRITICAL", "Command Injection risk: subprocess with shell=True"),
        (r"\beval\(", "CODE_INJECTION", "CRITICAL", "Usage of eval() is extremely dangerous"),
        (r"execute\(.*['\"]\s*\+\s*\w+", "SQL_INJECTION", "HIGH", "Potential SQL Injection: String concatenation in query"),
        (r"open\(.*f['\"].*\{.*\}", "PATH_TRAVERSAL", "HIGH", "Potential Path Traversal: User input in file path")
    ]
    
    all_findings = []
    
    print("\nScanning project files...")
    for root, _, files in os.walk(TARGET_DIR):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                all_findings.extend(scan_file(path, patterns))
                
    print(f"\nAnalysis complete! Found {len(all_findings)} potential issues.")
    
    all_findings.sort(key=lambda x: (x["severity"], x["file_path"], x["line"]))
    
    if len(all_findings) == 0:
        print("\nNo critical findings detected by the SAST engine.")
    
    for item in all_findings:
        file_name = os.path.relpath(item["file_path"], TARGET_DIR)
        print(f"[{item['severity']}] {item['id']} at {file_name}:{item['line']}")
        print(f"  > {item['message']}")
        print(f"  > Snippet: {item['snippet'][:100]}")
        print("-" * 40)

if __name__ == "__main__":
    main()
