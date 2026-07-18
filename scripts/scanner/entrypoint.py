#!/usr/bin/env python3
"""
Adversum SAST Scanner — Docker Entrypoint
==========================================
Reads environment variables:
  REPO_URL     : GitHub repo to clone and scan (required)
  OUTPUT_FORMAT: "json" or "text"                (default: json)
  GITHUB_TOKEN : Optional PAT for private repos

Outputs results to stdout (captured by Docker/API caller).
"""

import os
import sys
import re
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

# ── Security Rules ──────────────────────────────────────────────────────────
RULES = [
    # Secrets
    (r"(?i)(api[_-]?key|api[_-]?secret|secret[_-]?key|password|token|auth)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]",
     "HARDCODED_SECRET", "CRITICAL", "Hardcoded credential detected"),
    (r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
     "EXPOSED_JWT", "CRITICAL", "Hardcoded JWT token — exposed credential"),
    (r"AKIA[0-9A-Z]{16}",
     "AWS_KEY_EXPOSED", "CRITICAL", "Hardcoded AWS Access Key"),
    (r"sk-[a-zA-Z0-9]{32,}",
     "OPENAI_KEY_EXPOSED", "CRITICAL", "Hardcoded OpenAI API Key"),

    # JavaScript / TypeScript
    (r"\beval\s*\(",
     "CODE_INJECTION_EVAL", "CRITICAL", "eval() — arbitrary code execution risk"),
    (r"innerHTML\s*=\s*(?!.*DOMPurify)(?!.*sanitize)",
     "XSS_INNERHTML", "HIGH", "innerHTML without sanitization (XSS risk)"),
    (r"document\.write\s*\(",
     "XSS_DOC_WRITE", "HIGH", "document.write() can enable XSS"),
    (r"dangerouslySetInnerHTML\s*=",
     "XSS_DANGEROUS_INNERHTML", "HIGH", "dangerouslySetInnerHTML in React (XSS risk)"),

    # Python
    (r"subprocess\.run\(.*shell=True",
     "COMMAND_INJECTION", "CRITICAL", "subprocess with shell=True — command injection risk"),
    (r"\bos\.system\s*\(",
     "COMMAND_INJECTION_OS", "HIGH", "os.system() — prefer subprocess with shell=False"),
    (r"execute\s*\(\s*[\"'].*?[\"']\s*\+",
     "SQL_INJECTION_PY", "HIGH", "SQL string concatenation in query (SQLi risk)"),

    # SQL / NoSQL
    (r"(?i)(query|exec)\s*\([^)]*\$\{",
     "SQL_INJECTION_JS", "HIGH", "Template literal in SQL query (SQLi risk)"),
    (r"\.find\(\{.*?\$where",
     "NOSQL_INJECTION", "HIGH", "NoSQL $where injection"),

    # Crypto
    (r"(?i)createHash\s*\(['\"]md5['\"]",
     "WEAK_HASH_MD5", "MEDIUM", "MD5 is cryptographically broken"),
    (r"(?i)createHash\s*\(['\"]sha1['\"]",
     "WEAK_HASH_SHA1", "MEDIUM", "SHA1 deprecated for crypto use"),
    (r"Math\.random\s*\(\)",
     "INSECURE_RANDOM", "MEDIUM", "Math.random() not cryptographically secure"),
    (r"(?i)\brandom\(\)|\brandom\.random\(",
     "INSECURE_RANDOM_PY", "MEDIUM", "random module not cryptographically secure — use secrets()"),

    # Network
    (r"(?i)verify\s*=\s*False",
     "TLS_VERIFY_DISABLED", "CRITICAL", "TLS certificate verification disabled"),
    (r"cors\s*\(\s*\{[^}]*origin:\s*['\"]?\*['\"]?",
     "CORS_WILDCARD", "HIGH", "CORS wildcard — any origin allowed"),
    (r"https?\.get\s*\(['\"]http://",
     "HTTP_NOT_HTTPS", "MEDIUM", "HTTP used instead of HTTPS"),

    # Info Disclosure
    (r"console\.(log|error|warn|info)\s*\([^)]*(?:password|token|secret|key|auth)",
     "INFO_LEAK_CONSOLE", "MEDIUM", "Sensitive data logged to console"),

    # Path traversal
    (r"(?i)(readFile|readFileSync|open)\s*\([^)]*req\.(body|query|params)",
     "PATH_TRAVERSAL", "HIGH", "File operation with unvalidated user input"),
]

SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "venv", "__pycache__", ".tox", "vendor"}
SCAN_EXTS  = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".env", ".json", ".rb", ".php", ".go", ".java"}
SEV_ORDER  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def scan_dir(root: str) -> list[dict]:
    findings = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext not in SCAN_EXTS:
                continue
            filepath = os.path.join(dirpath, filename)
            rel = os.path.relpath(filepath, root)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue
            for lineno, line in enumerate(lines, 1):
                stripped = line.rstrip()
                for pattern, rule_id, severity, message in RULES:
                    try:
                        if re.search(pattern, stripped):
                            findings.append({
                                "rule_id":   rule_id,
                                "severity":  severity,
                                "message":   message,
                                "file":      rel.replace("\\", "/"),
                                "line":      lineno,
                                "snippet":   stripped[:160],
                            })
                    except re.error:
                        pass
    return findings


def main():
    repo_url      = os.environ.get("REPO_URL", "").strip()
    output_format = os.environ.get("OUTPUT_FORMAT", "json").lower()
    github_token  = os.environ.get("GITHUB_TOKEN", "").strip()

    if not repo_url:
        sys.exit("ERROR: REPO_URL environment variable is required.")

    # Inject token for private repo access
    if github_token:
        repo_url = repo_url.replace("https://", f"https://{github_token}@")

    tmpdir = tempfile.mkdtemp(prefix="adversum_scan_")
    try:
        print(f"[*] Cloning {repo_url} ...", flush=True)
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, tmpdir],
                check=True,
                capture_output=True,
                timeout=120
            )
        except subprocess.CalledProcessError as e:
            sys.exit(f"ERROR: Clone failed: {e.stderr.decode().strip()}")
        except subprocess.TimeoutExpired:
            sys.exit("ERROR: Clone timed out after 120 seconds.")

        print(f"[*] Scanning ...", flush=True)
        findings = scan_dir(tmpdir)
        findings.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["file"], x["line"]))

        # ── Output ──────────────────────────────────────────────────────────
        result = {
            "repo_url": repo_url.split("@")[-1] if "@" in repo_url else repo_url,  # strip token
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "summary": {
                "CRITICAL": sum(1 for f in findings if f["severity"] == "CRITICAL"),
                "HIGH":     sum(1 for f in findings if f["severity"] == "HIGH"),
                "MEDIUM":   sum(1 for f in findings if f["severity"] == "MEDIUM"),
                "LOW":      sum(1 for f in findings if f["severity"] == "LOW"),
            },
            "findings": findings,
        }

        if output_format == "json":
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"\n{'='*60}")
            print(f"  ADVERSUM SAST — {result['repo_url']}")
            print(f"  Scanned at : {result['scanned_at']}")
            print(f"  Findings   : {result['total_findings']}  "
                  f"(C:{result['summary']['CRITICAL']} H:{result['summary']['HIGH']} "
                  f"M:{result['summary']['MEDIUM']})")
            print(f"{'='*60}\n")
            for f in findings:
                print(f"  [{f['severity']:8}] {f['rule_id']}")
                print(f"  Location  : {f['file']}:{f['line']}")
                print(f"  Message   : {f['message']}")
                print(f"  Snippet   : {f['snippet'][:100]}")
                print("-" * 60)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
