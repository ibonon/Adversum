import ast
import logging
import os
import hashlib
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from ..models.findings import RawFinding, Severity

logger = logging.getLogger(__name__)

class ScoringEngine:
    """Assigns risk scores to potential discovery candidates."""
    
    # Weights for specific patterns
    PATTERN_WEIGHTS = {
        'eval': 1.0,
        'exec': 1.0,
        'os.system': 0.9,
        'subprocess.run': 0.8,
        'pickle.load': 0.9,
        'socket.connect': 0.6,
        'requests.post': 0.5,
        'yaml.load': 0.8,
    }

    @staticmethod
    def calculate_score(func_name: str, has_variable_args: bool, is_builtin: bool) -> float:
        base_score = 0.2
        
        # Direct match weight
        for pattern, weight in ScoringEngine.PATTERN_WEIGHTS.items():
            if pattern in func_name:
                base_score = max(base_score, weight)
        
        # Risk multiplier if arguments are dynamic (not literals)
        if has_variable_args:
            base_score = min(1.0, base_score * 1.5)
        
        # Penalty for non-builtins (unless explicitly in PATTERN_WEIGHTS)
        if not is_builtin and func_name not in ScoringEngine.PATTERN_WEIGHTS:
            # If it's an attribute call like obj.load(), it's likely benign
            base_score *= 0.5
            
        return base_score

    @staticmethod
    def get_severity(score: float) -> Severity:
        if score >= 0.85: return Severity.CRITICAL
        if score >= 0.65: return Severity.HIGH
        if score >= 0.35: return Severity.MEDIUM
        return Severity.LOW

class DiscoveryVisitor(ast.NodeVisitor):
    """Speed-optimized AST visitor for finding sensitive calls."""
    
    # Whitelist of absolutely benign functions that look like sinks
    BENIGN_WHITELIST = {
        'os.path.join', 'os.path.exists', 'os.path.abspath', 'os.path.dirname',
        'os.getcwd', 'os.environ.get', 'json.load', 'json.loads', 'json.dump',
        'json.dumps', 'logging.info', 'logging.error', 'logging.warning',
        'logging.debug', 'print'
    }

    # Decorators that signal a function is safe for discovery (tests/mocks)
    SAFE_DECORATORS = {'test', 'mock', 'fixture', 'pytest.mark'}

    # Dangerous built-ins (must be checked as built-ins, not just strings)
    DANGEROUS_BUILTINS = {'eval', 'exec', 'open', 'compile'}

    # Sensitive namespaces
    SENSITIVE_NAMESPACES = {
        'os', 'subprocess', 'socket', 'pickle', 'marshal', 'yaml', 
        'sqlite3', 'psycopg2', 'shutil', 'requests'
    }

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.candidates = []
        self._local_shadows = set() # Track names redefined locally (eval = 1)
        self._in_safe_scope = False # Track if we are inside a @test decorated function

    def visit_Call(self, node: ast.Call):
        if self._in_safe_scope:
            return

        func_name, is_builtin = self._resolve_call(node.func)
        
        # 0. Anti-FP Check: Shadowing & Whitelist
        if not func_name or func_name in self.BENIGN_WHITELIST or func_name in self._local_shadows:
            return

        is_candidate = False
        reason = ""

        # 1. Built-in check
        if is_builtin and func_name in self.DANGEROUS_BUILTINS:
            is_candidate = True
            reason = f"Dangerous built-in call: {func_name}"
        
        # 2. Namespace check
        if not is_candidate:
            parts = func_name.split('.')
            if parts[0] in self.SENSITIVE_NAMESPACES:
                # Check for critical methods within these namespaces
                is_candidate = True
                reason = f"Sensitive module call: {func_name}"

            # Anti-FP: Configuration Patterns
            if func_name == "os.getenv":
                # If it's a standard config lookup with a constant key, ignore it
                if all(isinstance(arg, ast.Constant) for arg in node.args):
                    return

            has_variable_args = any(not isinstance(arg, ast.Constant) for arg in node.args)
            score = ScoringEngine.calculate_score(func_name, has_variable_args, is_builtin)
            severity = ScoringEngine.get_severity(score)
            
            snippet = ast.unparse(node) if hasattr(ast, 'unparse') else "Source unavailable"
            clean_snippet = "".join(snippet.split())
            context_hash = hashlib.md5(f"{self.file_path}:{clean_snippet}".encode()).hexdigest()

            self.candidates.append(RawFinding(
                id="SHADOW_SINK_CANDIDATE",
                message=f"Shadow Discovery [{score:.2f}]: {reason}",
                severity=severity,
                file_path=self.file_path,
                line=node.lineno,
                snippet=snippet,
                flow_path=[func_name],
                proof_anchor=context_hash
            ))
        
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Track potential shadowing of sinks (e.g. eval = 1)."""
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in self.DANGEROUS_BUILTINS:
                self._local_shadows.add(target.id)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # 1. Check for safe decorators (Anti-FP Audit)
        old_safe = self._in_safe_scope
        old_shadows = self._local_shadows.copy() # Local scope for shadows
        
        for dec in node.decorator_list:
            dec_name = self._resolve_decorator(dec)
            if any(s in dec_name.lower() for s in self.SAFE_DECORATORS if dec_name):
                self._in_safe_scope = True
                break
        
        self.generic_visit(node)
        
        # Restore scope
        self._in_safe_scope = old_safe
        self._local_shadows = old_shadows

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node) # Same logic

    def _resolve_decorator(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute):
            val, _ = self._resolve_call(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        if isinstance(node, ast.Call): return self._resolve_decorator(node.func)
        return None

    def _resolve_call(self, node: ast.AST) -> Tuple[Optional[str], bool]:
        """Resolves function name and determines if it's a built-in call."""
        if isinstance(node, ast.Name):
            return node.id, True # Likely a built-in or locally defined
        elif isinstance(node, ast.Attribute):
            val_name, _ = self._resolve_call(node.value)
            if val_name:
                return f"{val_name}.{node.attr}", False # Definitely NOT a built-in
            return node.attr, False
        return None, False

class ShadowDiscoveryEngine:
    """Refined Anomaly Discovery Engine using DiscoveryVisitor."""
    
    def discover_candidates(self, file_path: str) -> List[RawFinding]:
        if not file_path.endswith(".py"):
            return []
            
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                tree = ast.parse(f.read())
            
            visitor = DiscoveryVisitor(file_path)
            visitor.visit(tree)
            return visitor.candidates
        except Exception as e:
            logger.error(f"Error in ShadowDiscoveryEngine for {file_path}: {e}")
            return []

class ShadowDiscoveryMiner:
    """High-performance Discovery Orchestrator with Massive Parallelization."""
    
    def __init__(self, ai_validator=None, core_wrapper=None):
        self.discovery_engine = ShadowDiscoveryEngine()
        self._ai_validator = ai_validator
        self._core_wrapper = core_wrapper
        self._max_file_concurrency = asyncio.Semaphore(50) # Increased for efficiency

    @property
    def validator(self):
        if not self._ai_validator:
            from ..reasoning.ai_validator import AIValidator
            self._ai_validator = AIValidator()
        return self._ai_validator

    @property
    def core(self):
        if not self._core_wrapper:
            from ..core_bridge.core_wrapper import CoreWrapper
            self._core_wrapper = CoreWrapper()
        return self._core_wrapper

    async def _scan_file_async(self, path: str) -> List[RawFinding]:
        """Async wrapper for the CPU-bound AST scan."""
        async with self._max_file_concurrency:
            # We run the discovery in a thread to keep the event loop reactive
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self.discovery_engine.discover_candidates, path)

    async def mine(self, file_paths: List[str]) -> List[Any]:
        # Anti-FP: Filter out noisy directories (libraries/docs/vcs)
        EXCLUDED_PATTERNS = {
            'tests', 'venv', '.venv', 'env', '.env', 
            'node_modules', 'docs', '.git', 'site-packages', 
            'dist-packages', '__pycache__', '.pytest_cache'
        }
        filtered_paths = [
            p for p in file_paths 
            if not any(ex in p.split(os.sep) for ex in EXCLUDED_PATTERNS)
        ]
        
        if not filtered_paths:
            return []

        logger.info(f"ShadowDiscoveryMiner: Parallel Scan initiated on {len(filtered_paths)} files.")
        
        # 1. MASSIVE PARALLEL DISCOVERY
        tasks = [self._scan_file_async(p) for p in filtered_paths]
        results = await asyncio.gather(*tasks)
        
        all_candidates = [item for sublist in results for item in sublist]
            
        if not all_candidates:
            return []
            
        logger.info(f"ShadowDiscoveryMiner: {len(all_candidates)} candidates discovered. Running Anomaly Reasoning...")
        
        # 2. AI Reasoning (already async)
        research_results = await self.validator.validate(all_candidates)
        
        # 3. Deterministic Proofing
        if self.core.use_ffi:
            try:
                # Proofing is generally fast and parallelized in Rust
                proven_results = self.core.validate_findings(all_candidates)
                proof_map = {p.proof_anchor if hasattr(p, 'proof_anchor') and p.proof_anchor else (p.file_path, p.line): p for p in proven_results}
                
                for res in research_results:
                    anchor = res.raw.proof_anchor
                    proof = proof_map.get(anchor) or proof_map.get((res.raw.file_path, res.raw.line))
                    
                    if proof and proof.validation_status == "CONFIRMED":
                        res.ai_confidence = 1.0
                        res.reasoning_notes += "\n\n[DETERMINISTIC PROOF]: Rust Core verified this shadow sink."
            except Exception as e:
                logger.error(f"ShadowDiscoveryMiner: Proofing failed: {e}")
        
        # Only keep top-tier and proven candidates
        return [f for f in research_results if f.ai_confidence > 0.6 or f.raw.severity == Severity.CRITICAL]
