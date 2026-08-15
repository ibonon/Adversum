import logging
import os
import re
import json
from typing import List, Optional, Any, Dict, Tuple
from ..models.findings import RawFinding

logger = logging.getLogger(__name__)


def _mock_core_forced() -> bool:
    """True when MOCK_CORE is explicitly enabled via the settings singleton
    or via the ADVERSUM_MOCK_CORE env var. The env var is authoritative so
    tests can toggle the flag without re-importing the settings module."""
    env_forced = os.getenv("ADVERSUM_MOCK_CORE", "false").lower() == "true"
    if env_forced:
        return True
    try:
        from ..config.settings import settings

        return bool(getattr(settings, "MOCK_CORE", False))
    except Exception:
        # Never let a config import error silently force the fallback;
        # default to the real engine.
        return False


class CoreWrapper:
    """
    Bridge between Python Orchestrator and Rust Core.
    Attempts to use the compiled Rust extension via FFI.
    Falls back to the Python fallback engine if the extension is not available
    or if MOCK_CORE is explicitly enabled (tests only).
    """

    def __init__(self):
        self.use_ffi = False
        self.rust_core = None

        if _mock_core_forced():
            logger.warning(
                "MOCK_CORE is explicitly enabled — Python fallback engine forced "
                "(tests only). Do NOT use in production."
            )
            return

        try:
            import adversum_core
            # Verify that the extension is fully functional and the correct version
            # The current version MUST have 'Finding' class exported for validation
            if hasattr(adversum_core, "Finding"):
                self.rust_core = adversum_core
                self.use_ffi = True
                logger.info("Initializing CoreWrapper (FFI Linked - Rust Engine Active)")
            else:
                logger.warning("Rust Core Extension found but version is OUTDATED (missing Finding). Falling back to Python engine.")
        except ImportError:
            logger.error("CRITICAL: Rust Core Extension NOT found. Industrial analysis is disabled.")
            logger.error("Run `maturin develop` in `adversum/core` to build the engine.")

    def get_hashes(self, paths: List[str]) -> dict[str, str]:
        """Computes XXH3 hashes for a list of file paths via Rust Core."""
        if not self.use_ffi:
            return {}
        try:
            # Direct native object from Rust (pythonize)
            result = self.rust_core.compute_hashes(paths)
            if isinstance(result, str):
                import json
                return json.loads(result)
            return result
        except Exception as e:
            logger.error(f"Failed to compute hashes: {e}")
            return {}

    def analyze(self, paths: list[str], dirty_ranges: Optional[dict[str, list[tuple[int, int]]]] = None) -> tuple[list[RawFinding], dict[str, str], float]:
        """
        Runs the Rust Core SAST analysis on a list of paths.
        Returns a tuple of (findings, file_hashes, robustness_score).
        """
        if not self.use_ffi:
            logger.warning("Core engine not linked. Using Python Fallback Analysis.")
            return self._analyze_fallback(paths)

        logger.info(f"Sending {len(paths)} files to Core for parallel AST analysis.")
        
        all_findings = []
        file_hashes = {}
        try:
            # 1. Targeted Scan Support (Dirty Ranges)
            if dirty_ranges and hasattr(self.rust_core, "inspect_targeted"):
                logger.info(f"Core: Running TARGETED scan on {len(dirty_ranges)} files for efficiency.")
                result = self.rust_core.inspect_targeted(dirty_ranges)
            else:
                result = self.rust_core.inspect_files(paths)
            
            # Handle backward compatibility for JSON string return
            if isinstance(result, str):
                import json
                data = json.loads(result)
                # Mock object to match structure
                class MockResult:
                    def __init__(self, d):
                        self.findings = []
                        for f in d.get("findings", []):
                            if isinstance(f, dict):
                                class MockFinding:
                                    def __init__(self, fd):
                                        self.file_path = fd.get("file_path", "unknown")
                                        self.line = fd.get("line", 0)
                                        self.snippet = fd.get("snippet", "")
                                        self.id = fd.get("id", "UNKNOWN")
                                        self.severity = fd.get("severity", "LOW")
                                        self.message = fd.get("message", "")
                                        self.flow_path = fd.get("flow_path", [])
                                        self.proof = fd.get("proof") 
                                        self.immune_context = fd.get("immune_context")
                                        self.proof_anchor = fd.get("proof_anchor")
                                self.findings.append(MockFinding(f))
                            else:
                                self.findings.append(f)
                        self.file_hashes = d.get("file_hashes", {})
                        self.robustness_score = d.get("robustness_score", 1.0)
                
                result = MockResult(data)

            # O(1) Rules map for FFI reduction (Including semantic, attack_graph, scoring, and adversarial modules)
            RULES_DICT = {
                1: ("RUST_CORE_001_DANGEROUS_EVAL", "CRITICAL", "Dangerous eval() detected"),
                2: ("RUST_CORE_002_OS_SYSTEM", "CRITICAL", "os.system() call detected"),
                3: ("RUST_CORE_003_SUBPROCESS_POPEN", "CRITICAL", "subprocess.Popen() shell invocation"),
                4: ("RUST_CORE_004_PATH_TRAVERSAL", "HIGH", "Arbitrary file open() detected"),
                6: ("RUST_CORE_006_SMB_VULN", "CRITICAL", "Insecure SMBConnection configuration"),
                10: ("SEMANTIC_001_TAINT_FLOW", "HIGH", "Taint flow detected via semantic analysis"),
                11: ("GRAPH_001_ATTACK_PATH", "CRITICAL", "Critical attack path constructed from multiple vulnerabilities"),
                12: ("SCORING_001_RISK_DEGRADATION", "MEDIUM", "Component risk score degraded due to cumulative flaws"),
                13: ("ADVERSARIAL_001_PROMPT_INJECTION", "CRITICAL", "LLM Prompt Injection vector detected (Fast Adversarial Kit)"),
                0: ("RUST_CORE_GENERIC_FLOW", "MEDIUM", "Semantic flow violation")
            }
            
            # Group by file to read efficiently
            by_file = {}
            for f in result.findings:
                fp = getattr(f, 'file_path', None) or 'unknown'
                by_file.setdefault(fp, []).append(f)
                
            for file_path, light_findings in by_file.items():
                file_lines = []
                if file_path != "unknown" and os.path.exists(file_path):
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as file_obj:
                            file_lines = file_obj.readlines()
                    except Exception as e:
                        logger.warning(f"Could not read {file_path} for snippet rehydration: {e}")
                
                for f in light_findings:
                    rule_info = RULES_DICT.get(f.rule_id, RULES_DICT[0])
                    snippet = ""
                    # 1-indexed lines
                    if 0 < f.line <= len(file_lines):
                        snippet = file_lines[f.line - 1].strip()
                        
                    all_findings.append(RawFinding(
                        file_path=file_path,
                        line=f.line,
                        snippet=snippet,
                        id=rule_info[0],
                        severity=rule_info[1],
                        message=rule_info[2],
                        flow_path=["Native Core Flow"],
                        proof=None,
                        immune_context=None,
                        proof_anchor=None
                    ))
            
            file_hashes = result.file_hashes
            robustness_score = result.robustness_score
        except Exception as e:
            logger.error(f"Engine failure during AST analysis: {e}")
            robustness_score = 1.0

        logger.info(f"Core analysis complete. {len(all_findings)} findings reported.")
        return all_findings, file_hashes, robustness_score

    def validate_findings(self, findings: List[RawFinding]) -> List[Any]:
        """
        Validates findings using the Rust Core Deterministic Validator.
        """
        if not self.use_ffi:
            logger.warning("Core FFI not available. Skipping deterministic validation.")
            return []
            
        try:
            rust_findings = []
            for f in findings:
                rf = self.rust_core.Finding(
                    id=f.id,
                    message=f.message,
                    severity=f.severity.value if hasattr(f.severity, 'value') else f.severity,
                    line=f.line,
                    snippet=f.snippet or "",
                    file_path=f.file_path,
                    flow_path=f.flow_path or []
                )
                rust_findings.append(rf)
            
            validated = self.rust_core.validate_findings(rust_findings)
            return validated
        except Exception as e:
            logger.error(f"Rust validation failed: {e}")
            return []

    # ------------------------------------------------------------------
    # TAINT SOURCES — variables that carry user-controlled data
    # ------------------------------------------------------------------
    _TAINT_SOURCES = re.compile(
        r"""
        \b(
            request\.(args|form|json|data|values|files|cookies|headers|get_json)\b |
            os\.environ(?:\.get)?\b |
            os\.getenv\b |
            sys\.argv\b |
            input\s*\( |
            sys\.stdin |
            flask\.request |
            django\.http\.QueryDict |
            bottle\.request |
            tornado\.httputil\.HTTPServerRequest
        )
        """,
        re.VERBOSE,
    )

    # ------------------------------------------------------------------
    # SINK PATTERNS — (regex, rule_id, severity, message)
    # ------------------------------------------------------------------
    _SINK_PATTERNS = [
        # ── Command Injection ───────────────────────────────────────────
        (re.compile(r"\beval\s*\("), "RUST_CORE_001_DANGEROUS_EVAL", "CRITICAL",
         "eval() with potentially tainted input — arbitrary code execution"),
        (re.compile(r"\bos\.system\s*\("), "RUST_CORE_002_OS_SYSTEM", "CRITICAL",
         "os.system() — prefer subprocess with shell=False"),
        (re.compile(r"\bos\.popen\s*\("), "RUST_CORE_002_OS_SYSTEM", "CRITICAL",
         "os.popen() — command injection risk"),
        (re.compile(r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True"),
         "RUST_CORE_003_SUBPROCESS_POPEN", "CRITICAL",
         "subprocess with shell=True — command injection risk"),
        (re.compile(r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\("),
         "RUST_CORE_003_SUBPROCESS_POPEN", "HIGH",
         "subprocess call — verify arguments are not user-controlled"),

        # ── Path Traversal ──────────────────────────────────────────────
        (re.compile(r"\bopen\s*\(\s*(?:f['\"]|['\"][^'\"]*\{|os\.path\.join)"),
         "RUST_CORE_004_PATH_TRAVERSAL", "HIGH",
         "file open() with f-string or join — potential path traversal"),
        (re.compile(r"\bos\.path\.join\s*\([^)]*(?:request|args|params|user)"),
         "RUST_CORE_004_PATH_TRAVERSAL", "HIGH",
         "os.path.join() with user-supplied data — path traversal risk"),

        # ── SQL Injection ───────────────────────────────────────────────
        (re.compile(r"\.execute\s*\(\s*[\"'][^\"']*[\"']\s*\+"),
         "RUST_CORE_005_SQL_INJECTION", "CRITICAL",
         "SQL string concatenation in execute() — SQLi risk"),
        (re.compile(r"\.execute\s*\(\s*f['\"]"),
         "RUST_CORE_005_SQL_INJECTION", "CRITICAL",
         "f-string in SQL execute() — SQLi risk"),
        (re.compile(r"\.execute\s*\(\s*\"\"\"[^\"]*%\s*\("),
         "RUST_CORE_005_SQL_INJECTION", "HIGH",
         "%-format in SQL execute() — SQLi risk"),
        (re.compile(r"\.raw\s*\(\s*(?:f['\"]|[\"'][^\"']*[\"']\s*\+)"),
         "RUST_CORE_005_SQL_INJECTION", "HIGH",
         "Django .raw() SQL with dynamic content — SQLi risk"),

        # ── Template Injection ──────────────────────────────────────────
        (re.compile(r"\brender_template_string\s*\("),
         "RUST_CORE_007_TEMPLATE_INJECTION", "CRITICAL",
         "Flask render_template_string() with user data — SSTI risk"),
        (re.compile(r"\bEnvironment\s*\(.*\bloader\s*="),
         "RUST_CORE_007_TEMPLATE_INJECTION", "HIGH",
         "Jinja2 Environment with configurable loader — SSTI risk"),
        (re.compile(r"jinja2\.Template\s*\("),
         "RUST_CORE_007_TEMPLATE_INJECTION", "HIGH",
         "jinja2.Template() with dynamic content — SSTI risk"),

        # ── Hardcoded Secrets ───────────────────────────────────────────
        (re.compile(r"""(?i)(?:password|passwd|secret|api[_-]?key|token|auth[_-]?key)\s*=\s*['"][A-Za-z0-9+/=_\-\.]{8,}['"]"""),
         "HARDCODED_SECRET", "CRITICAL",
         "Hardcoded credential detected"),
        (re.compile(r"AKIA[0-9A-Z]{16}"),
         "HARDCODED_SECRET", "CRITICAL",
         "Hardcoded AWS Access Key ID"),
        (re.compile(r"sk-[a-zA-Z0-9]{20,}"),
         "HARDCODED_SECRET", "CRITICAL",
         "Hardcoded OpenAI API Key"),
        (re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
         "HARDCODED_SECRET", "CRITICAL",
         "Hardcoded JWT token"),
        (re.compile(r"ghp_[A-Za-z0-9]{36}"),
         "HARDCODED_SECRET", "CRITICAL",
         "Hardcoded GitHub Personal Access Token"),

        # ── Weak Crypto ─────────────────────────────────────────────────
        (re.compile(r"hashlib\.(?:md5|sha1)\s*\("),
         "WEAK_CRYPTO", "MEDIUM",
         "Weak hash function (MD5/SHA1) — use SHA-256 or stronger"),
        (re.compile(r"(?:DES|RC4|Blowfish)\s*\("),
         "WEAK_CRYPTO", "HIGH",
         "Deprecated symmetric cipher — use AES-GCM"),
        (re.compile(r"\brandom\.(?:random|randint|choice|seed)\s*\("),
         "INSECURE_RANDOM", "MEDIUM",
         "random module not cryptographically secure — use secrets"),

        # ── Unsafe Deserialization ──────────────────────────────────────
        (re.compile(r"\bpickle\.(?:loads?|Unpickler)\s*\("),
         "UNSAFE_DESERIALIZATION", "CRITICAL",
         "pickle.load() with untrusted data — arbitrary code execution"),
        (re.compile(r"\byaml\.(?:load|unsafe_load)\s*\("),
         "UNSAFE_DESERIALIZATION", "HIGH",
         "yaml.load() without Loader=yaml.SafeLoader — code injection"),
        (re.compile(r"\beval\s*\(.*(?:json|yaml|pickle|input|request)"),
         "UNSAFE_DESERIALIZATION", "CRITICAL",
         "eval() on network/user data — RCE risk"),

        # ── SSRF / Open Redirect ────────────────────────────────────────
        (re.compile(r"\brequests\.(?:get|post|put|delete|request)\s*\(\s*(?:url\s*=)?\s*(?:f['\"]|[a-z_]+\s*\+)"),
         "SSRF", "HIGH",
         "HTTP request with dynamic URL — potential SSRF"),

        # ── TLS / SSL ───────────────────────────────────────────────────
        (re.compile(r"verify\s*=\s*False"),
         "TLS_VERIFY_DISABLED", "CRITICAL",
         "TLS certificate verification disabled — MITM attack possible"),
        (re.compile(r"ssl\._create_unverified_context\s*\("),
         "TLS_VERIFY_DISABLED", "CRITICAL",
         "Unverified SSL context — TLS validation bypassed"),

        # ── XSS (Django/Flask templates) ────────────────────────────────
        (re.compile(r"mark_safe\s*\("),
         "XSS", "HIGH",
         "Django mark_safe() — ensure content is sanitized"),
        (re.compile(r"Markup\s*\("),
         "XSS", "HIGH",
         "Jinja2 Markup() — ensures HTML is trusted, verify source"),

        # ── Debug / Info Disclosure ─────────────────────────────────────
        (re.compile(r"DEBUG\s*=\s*True"),
         "DEBUG_ENABLED", "MEDIUM",
         "DEBUG=True in production exposes stack traces and settings"),
        (re.compile(r"(?:print|logger?\.\w+)\s*\([^)]*(?:password|secret|token|key|auth)"),
         "INFO_LEAK", "MEDIUM",
         "Sensitive data logged — review log statements"),
    ]

    def _analyze_fallback(self, paths: list[str]) -> tuple[list[RawFinding], dict[str, str], float]:
        """
        Production-quality Python SAST fallback.

        Two-pass per file:
          Pass 1 — identify lines that assign taint sources to local variables.
          Pass 2 — scan sink patterns; if a sink line references a tainted var,
                   severity is escalated. All sinks are reported regardless
                   (conservative approach: report, validate later via LLM).

        Used when the Rust Core extension is unavailable.
        """
        import re
        import hashlib

        findings: list[RawFinding] = []
        hashes: dict[str, str] = {}

        SKIP_EXTS = {".pyc", ".pyd", ".so", ".dll", ".png", ".jpg",
                     ".gif", ".zip", ".tar", ".gz", ".lock"}

        for path in paths:
            ext = os.path.splitext(path)[1].lower()
            if ext in SKIP_EXTS:
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()

                hashes[path] = hashlib.xxh3_64_hexdigest(content.encode()) \
                    if hasattr(hashlib, "xxh3_64_hexdigest") \
                    else hashlib.sha256(content.encode()).hexdigest()

                lines = content.splitlines()

                # ── Pass 1: build taint set (variable names receiving taint sources) ──
                tainted_vars: set[str] = set()
                for raw_line in lines:
                    stripped = raw_line.strip()
                    if self._TAINT_SOURCES.search(stripped):
                        # Extract LHS of assignment  e.g.  user_input = request.args.get(...)
                        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*)\s*=\s*", stripped)
                        if m:
                            for var in m.group(1).split(","):
                                tainted_vars.add(var.strip())

                # ── Pass 2: check sinks ──────────────────────────────────────────────
                seen: set[tuple[str, int, str]] = set()  # deduplicate

                for lineno, raw_line in enumerate(lines, start=1):
                    stripped = raw_line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue

                    for pattern, rule_id, severity, message in self._SINK_PATTERNS:
                        if not pattern.search(stripped):
                            continue

                        # Escalate severity if a known tainted var appears on this line
                        final_severity = severity
                        if tainted_vars:
                            for tv in tainted_vars:
                                if re.search(r'\b' + re.escape(tv) + r'\b', stripped):
                                    if severity == "HIGH":
                                        final_severity = "CRITICAL"
                                    elif severity == "MEDIUM":
                                        final_severity = "HIGH"
                                    break

                        key = (path, lineno, rule_id)
                        if key in seen:
                            continue
                        seen.add(key)

                        findings.append(RawFinding(
                            file_path=path,
                            line=lineno,
                            snippet=stripped[:200],
                            id=rule_id,
                            severity=final_severity,
                            message=message,
                            flow_path=["Python Fallback Analyzer (Taint-Aware Regex)"],
                            proof=None,
                            immune_context=None,
                        ))

            except Exception as e:
                logger.error(f"Fallback scan error for {path}: {e}")

        logger.info(
            f"[Fallback] Scanned {len(paths)} files → {len(findings)} findings "
            f"(taint vars tracked: {len(set()) if not paths else '?'})"
        )
        return findings, hashes, 0.6
