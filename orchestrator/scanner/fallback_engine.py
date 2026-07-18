import ast
import logging
import os
from typing import List, Dict, Tuple
from ..models.findings import RawFinding
import hashlib

logger = logging.getLogger(__name__)

class FallbackASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []

    def visit_Call(self, node):
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name:
            rule_id = None
            if func_name == "eval":
                rule_id = "RUST_CORE_001_DANGEROUS_EVAL"
                msg = "[Fallback Engine] Utilisation potentiellement dangereuse de eval()"
            elif func_name in ("system", "popen", "execv"):
                rule_id = "RUST_CORE_002_OS_SYSTEM"
                msg = f"[Fallback Engine] Utilisation de {func_name}() detectee"
            elif func_name in ("Popen", "run", "call", "check_output"):
                rule_id = "RUST_CORE_003_SUBPROCESS_POPEN"
                msg = f"[Fallback Engine] Appel process suspect ({func_name})"
            elif func_name == "open":
                rule_id = "RUST_CORE_004_PATH_TRAVERSAL"
                msg = "[Fallback Engine] Fonction open() avec donnees potentiellement non sanitisees"

            if rule_id:
                self.findings.append(RawFinding(
                    id=rule_id,
                    message=msg,
                    severity="HIGH",
                    line=node.lineno,
                    snippet=f"{func_name}(...)",
                    file_path=self.file_path,
                    flow_path=["Fallback Detection -> Sink"],
                    proof=None,
                    immune_context=None
                ))
        self.generic_visit(node)

class FallbackEngine:
    """Moteur de secours 100% Python en cas de crash du composant Rust."""
    def __init__(self):
        logger.info("FallbackEngine (Beast Mode) initialized.")

    def analyze(self, files: List[str]) -> Tuple[List[RawFinding], Dict[str, str], float]:
        findings = []
        hashes = {}
        for file_path in files:
            hash_md5 = hashlib.md5()
            try:
                with open(file_path, 'rb') as f:
                    content_bytes = f.read()
                    hash_md5.update(content_bytes)
                
                hashes[file_path] = hash_md5.hexdigest()
                
                content_str = content_bytes.decode('utf-8', errors='replace')
                tree = ast.parse(content_str)
                visitor = FallbackASTVisitor(file_path)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except Exception as e:
                logger.error(f"FallbackEngine failed parsing {file_path}: {e}")
        
        return findings, hashes, 0.7  # 0.7 robustness to distinguish from Rust (1.0)
