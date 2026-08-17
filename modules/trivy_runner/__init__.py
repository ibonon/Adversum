"""
Adversum Trivy Runner Package
Software Composition Analysis (SCA), Dependency CVEs, IaC Misconfigurations & Secrets
"""
from .scanner import TrivyScanner, TrivyFinding

__all__ = ["TrivyScanner", "TrivyFinding"]
