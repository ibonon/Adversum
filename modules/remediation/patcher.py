"""
Adversum Remediation Patcher — Unified Diff Generator & Fixer
"""
import os
import difflib
from typing import List, Dict, Tuple
from .fixers import fix_solidity, fix_crypto, fix_iac, fix_python

class RemediationPatcher:
    """
    Moteur de remédiation automatique.
    Génère des diffs unifiés et applique les correctifs.
    """
    def __init__(self):
        pass

    def generate_patch(self, finding: Dict, file_content: str = None) -> Tuple[str, str]:
        """
        Génère le nouveau contenu et le diff unifié pour un finding.
        Retourne (fixed_content, diff_text).
        """
        file_path = finding.get("file", "")
        if file_content is None and file_path and os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                file_content = f.read()

        if not file_content:
            return "", ""

        module = finding.get("module", "")
        rule_id = finding.get("rule_id", "")
        
        # Sélection du fixer selon le module et le fichier
        if module == "solidity" or file_path.endswith((".sol", ".vy")):
            fixed = fix_solidity(finding, file_content)
        elif module == "crypto":
            fixed = fix_crypto(finding, file_content)
        elif module == "iac" or file_path.endswith((".tf", ".yaml", ".yml")) or "Dockerfile" in file_path:
            fixed = fix_iac(finding, file_content)
        else:
            fixed = fix_python(finding, file_content)

        diff_text = self._generate_unified_diff(file_content, fixed, file_path)
        return fixed, diff_text

    def _generate_unified_diff(self, original: str, fixed: str, file_path: str = "") -> str:
        diff_lines = list(difflib.unified_diff(
            original.splitlines(keepends=True),
            fixed.splitlines(keepends=True),
            fromfile=f"a/{os.path.basename(file_path)}",
            tofile=f"b/{os.path.basename(file_path)}",
        ))
        return "".join(diff_lines)

    def apply_fix(self, finding: Dict) -> bool:
        """
        Applique directement le correctif sur le fichier du finding.
        """
        file_path = finding.get("file", "")
        if not file_path or not os.path.exists(file_path):
            return False

        fixed, diff = self.generate_patch(finding)
        if fixed and diff:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(fixed)
            return True
        return False

# Alias for backward compatibility
AutoPatcher = RemediationPatcher

def apply_patch(findings: List[Dict]) -> Dict[str, str]:
    """
    Applique les patchs pour une liste de findings et retourne un dictionnaire {file_path: diff_text}.
    """
    patcher = RemediationPatcher()
    diffs = {}
    for f in findings:
        file_path = f.get("file", "")
        if file_path:
            fixed, diff = patcher.generate_patch(f)
            if diff:
                diffs[file_path] = diff
                patcher.apply_fix(f)
    return diffs
