import os
import sys
import re
import io
import codecs

# Force UTF-8 output on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

TARGET_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../tmp_repos/omnirepurpose'))

# === RULE ENGINE ===
RULES = [
    # --- Hardcoded Secrets ---
    (r"(?i)(api[_-]?key|api[_-]?secret|secret[_-]?key|password|token|auth)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]",
     "HARDCODED_SECRET", "CRITICAL", "Hardcoded credential/secret detected"),
    (r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
     "EXPOSED_JWT", "CRITICAL", "Hardcoded JWT token detected (exposed credential)"),
    (r"AKIA[0-9A-Z]{16}",
     "AWS_KEY_EXPOSED", "CRITICAL", "Hardcoded AWS Access Key"),
    (r"sk-[a-zA-Z0-9]{32,}",
     "OPENAI_KEY_EXPOSED", "CRITICAL", "Hardcoded OpenAI API Key"),

    # --- Dangerous JS/TS patterns ---
    (r"\beval\s*\(",
     "CODE_INJECTION_EVAL", "CRITICAL", "Use of eval() — arbitrary code execution risk"),
    (r"innerHTML\s*=\s*(?!.*DOMPurify)(?!.*sanitize)",
     "XSS_INNERHTML", "HIGH", "Direct innerHTML assignment without sanitization (XSS risk)"),
    (r"document\.write\s*\(",
     "XSS_DOCTYPE_WRITE", "HIGH", "document.write() can enable XSS"),
    (r"dangerouslySetInnerHTML\s*=",
     "XSS_DANGEROUS_INNERHTML", "HIGH", "dangerouslySetInnerHTML in React (XSS risk if unvalidated)"),

    # --- SQL / NoSQL Injection ---
    (r"(?i)(query|exec|execute)\s*\([^)]*\$\{",
     "SQL_INJECTION", "HIGH", "Potential SQL injection: template literal in query"),
    (r"(?i)\.find\(\{.*\$where",
     "NOSQL_INJECTION", "HIGH", "Potential NoSQL $where injection"),

    # --- Insecure Crypto ---
    (r"(?i)createHash\s*\(['\"]md5['\"]",
     "WEAK_HASH_MD5", "MEDIUM", "MD5 is cryptographically broken, use SHA-256+"),
    (r"(?i)createHash\s*\(['\"]sha1['\"]",
     "WEAK_HASH_SHA1", "MEDIUM", "SHA1 is deprecated for security use, use SHA-256+"),
    (r"Math\.random\s*\(\)",
     "INSECURE_RANDOM", "MEDIUM", "Math.random() is not cryptographically secure"),

    # --- Path Traversal ---
    (r"(?i)(readFile|readFileSync|writeFile|writeFileSync)\s*\([^)]*req\.(body|query|params)",
     "PATH_TRAVERSAL", "HIGH", "File operation using unvalidated user input (path traversal risk)"),

    # --- Information Disclosure ---
    (r"console\.(log|error|warn|info)\s*\([^)]*(?:password|token|secret|key|auth)",
     "INFO_LEAK_CONSOLE", "MEDIUM", "Logging sensitive data to console (info disclosure)"),
    (r"(?i)process\.env\.[A-Z_]+\s*\|\|\s*['\"].*['\"]",
     "ENV_FALLBACK_HARDCODED", "MEDIUM", "Hardcoded fallback for environment variable (insecure default)"),

    # --- Outdated/Insecure Patterns ---
    (r"cors\s*\(\s*\{[^}]*origin:\s*['\"]?\*['\"]?",
     "CORS_WILDCARD", "HIGH", "CORS configured with wildcard origin — any site can access this API"),
    (r"(?i)SameSite\s*=\s*None(?!\s*;\s*Secure)",
     "COOKIE_SAMESITE_INSECURE", "MEDIUM", "SameSite=None without Secure flag (CSRF risk)"),
    (r"(?i)verify\s*:\s*false",
     "TLS_VERIFICATION_DISABLED", "CRITICAL", "TLS certificate verification disabled"),
    (r"https?\.get\s*\(['\"]http://",
     "HTTP_NOT_HTTPS", "MEDIUM", "HTTP used instead of HTTPS for sensitive request"),

    # --- SSRF / Open Redirect ---
    (r"(?i)(fetch|axios\.get|http\.get|request)\s*\([^)]*req\.(body|query|params)\.",
     "SSRF_RISK", "HIGH", "Potential SSRF: outbound request with unvalidated user input as URL"),
]

EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".env", ".json", ".mjs", ".cjs"}

# Files to skip
SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "__pycache__"}

findings = []
files_scanned = 0

print(f"\n{'='*60}")
print(f"  ADVERSUM JS/TS SAST — omnirepurpose-ai-studio")
print(f"{'='*60}\n")


# == .env special scan ==
env_path = os.path.join(TARGET_DIR, ".env")
if os.path.exists(env_path):
    print("[*] Scanning .env file for exposed secrets...\n")
    with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f, 1):
            line = line.rstrip()
            for pat, rule_id, severity, msg in RULES:
                if re.search(pat, line):
                    findings.append({
                        "file": ".env",
                        "line": i,
                        "snippet": line[:120],
                        "rule": rule_id,
                        "severity": severity,
                        "message": msg
                    })

# The instruction "Only clone if target dir doesn't already exist" implies a cloning step.
# Since no cloning logic is present, and the provided snippet for insertion is syntactically incorrect
# in its suggested placement, I will place the print statement where it makes the most sense
# given the instruction, which is before the main file scanning loop, assuming TARGET_DIR
# is expected to exist for scanning.
if os.path.exists(TARGET_DIR):
    print(f"[-] Repo already present at {TARGET_DIR}, skipping clone.")
else:
    # Placeholder for actual cloning logic if it were to be added.
    # For now, if the directory doesn't exist, the os.walk will simply find nothing.
    print(f"[!] Target directory {TARGET_DIR} not found. Skipping scan.")


for root, dirs, files in os.walk(TARGET_DIR):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    for filename in files:
        ext = os.path.splitext(filename)[1].lower()
        if ext not in EXTENSIONS:
            continue
        
        filepath = os.path.join(root, filename)
        rel_path = os.path.relpath(filepath, TARGET_DIR)
        files_scanned += 1

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            continue
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.rstrip()
            for pat, rule_id, severity, msg in RULES:
                try:
                    if re.search(pat, line_stripped):
                        findings.append({
                            "file": rel_path,
                            "line": i,
                            "snippet": line_stripped[:120],
                            "rule": rule_id,
                            "severity": severity,
                            "message": msg
                        })
                except re.error:
                    pass

# === SORT & DISPLAY ===
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
findings.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["file"], x["line"]))

EMOJIS = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[.]", "INFO": "[i]"}

print(f"  Files scanned : {files_scanned}")
print(f"  Findings total: {len(findings)}\n")
print(f"{'='*60}\n")

by_sev = {}
for f in findings:
    by_sev.setdefault(f["severity"], []).append(f)

for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
    group = by_sev.get(sev, [])
    if not group:
        continue
    emoji = EMOJIS.get(sev, "●")
    print(f"\n{emoji} [{sev}] — {len(group)} finding(s)")
    print("-" * 60)
    for item in group:
        print(f"  Rule     : {item['rule']}")
        print(f"  Location : {item['file']}:{item['line']}")
        print(f"  Message  : {item['message']}")
        print(f"  Snippet  : {item['snippet']}")
        print()

print(f"\n{'='*60}")
print("  Scan complete.")
print(f"{'='*60}\n")
