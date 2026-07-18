"""
Wrapper for Adversum Rust Core integration.

Supports two modes:
- PyO3 (PRODUCTION): Direct FFI with compiled Rust core
- Mock (FALLBACK): Simulated findings for development/testing
"""

import json
import os
from typing import List, Dict, Any
from .schemas import Finding


class CoreWrapper:
    """Wrapper for Adversum Rust Core via PyO3 FFI or Mock fallback"""
    
    def __init__(self, core_binary_path: str = None):
        """
        Initialize the core wrapper.
        
        Args:
            core_binary_path: Deprecated (kept for compatibility)
        """
        # Try to import the compiled Rust core via PyO3
        try:
            import adversum_core
            self.core = adversum_core
            self.mode = "pyo3"
            print("✓ Rust Core loaded via PyO3 (PRODUCTION MODE)")
        except ImportError as e:
            print(f"⚠ WARNING: Could not import adversum_core: {e}")
            print("  Falling back to mock mode. To enable production mode:")
            print("  1. cd core")
            print("  2. maturin develop --release")
            self.core = None
            self.mode = "mock"
    
    def analyze_file(self, file_path: str) -> List[Finding]:
        """
        Analyze a single file for vulnerabilities.
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            List of Finding objects
        """
        if self.mode == "pyo3":
            return self._run_pyo3([file_path])
        else:
            return self._run_mock(file_path)
    
    def analyze_files(self, file_paths: List[str]) -> List[Finding]:
        """
        Analyze multiple files (batch processing).
        
        Args:
            file_paths: List of file paths
            
        Returns:
            List of Finding objects from all files
        """
        if self.mode == "pyo3":
            return self._run_pyo3(file_paths)
        else:
            # Mock mode: analyze each file separately
            all_findings = []
            for fp in file_paths:
                all_findings.extend(self._run_mock(fp))
            return all_findings
    
    def _run_pyo3(self, file_paths: List[str]) -> List[Finding]:
        """
        Run Rust Core via PyO3 FFI - PRODUCTION MODE
        
        Args:
            file_paths: List of files to analyze
            
        Returns:
            List of Finding objects
        """
        try:
            # Call Rust function directly via PyO3
            result_json = self.core.inspect_files(file_paths)
            result = json.loads(result_json)
            
            # Convert Rust findings to Python Finding objects
            findings = []
            for f in result.get("findings", []):
                # Extract file path from finding or use first file
                file_path = f.get("file_path", file_paths[0] if file_paths else "unknown")
                line_num = f.get("line", 1)
                
                findings.append(Finding(
                    rule_id=f.get("id", "UNKNOWN"),
                    description=f.get("message", "No description"),
                    severity=self._normalize_severity(f.get("severity", "MEDIUM")),
                    location=f"{file_path}:{line_num}",
                    score=self._severity_to_score(f.get("severity", "MEDIUM"))
                ))
            
            return findings
            
        except Exception as e:
            print(f"ERROR in PyO3 wrapper: {e}")
            print(f"  Files: {file_paths}")
            # Fallback to empty list on error
            return []
    
    def _run_mock(self, file_path: str) -> List[Finding]:
        """
        Simulates Core analysis findings for demo/dev purposes - FALLBACK MODE
        
        Args:
            file_path: Path to file
            
        Returns:
            List of mock Finding objects
        """
        findings = []
        basename = os.path.basename(file_path)
        
        # Simple heuristic simulation
        if "secret" in basename.lower() or "key" in basename.lower():
            findings.append(Finding(
                rule_id="MOCK_HARDCODED_SECRET",
                description="Potential hardcoded secret in filename context (MOCK MODE)",
                severity="High",
                location=f"{file_path}:1",
                score=7.0
            ))
        
        if "password" in basename.lower():
            findings.append(Finding(
                rule_id="MOCK_PASSWORD_FILE",
                description="File name suggests password storage (MOCK MODE)",
                severity="Medium",
                location=f"{file_path}:1",
                score=5.0
            ))
        
        return findings
    
    @staticmethod
    def _normalize_severity(severity: str) -> str:
        """
        Normalize severity string to standard format.
        
        Args:
            severity: Raw severity from Rust
            
        Returns:
            Normalized severity: Low/Medium/High/Critical
        """
        severity_upper = severity.upper()
        
        # Map Rust severity to Python severity
        severity_map = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFO": "Low"
        }
        
        return severity_map.get(severity_upper, "Medium")
    
    @staticmethod
    def _severity_to_score(severity: str) -> float:
        """
        Convert severity string to numeric score (0-10).
        
        Args:
            severity: Severity level
            
        Returns:
            Numeric score
        """
        severity_map = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "INFO": 1.0
        }
        return severity_map.get(severity.upper(), 5.0)

