"""
Adversum Auto-Remediation Engine (AVR)
Générateur de correctifs automatiques et de diffs unifiés.
"""
from .patcher import RemediationPatcher, apply_patch

__all__ = ["RemediationPatcher", "apply_patch"]
