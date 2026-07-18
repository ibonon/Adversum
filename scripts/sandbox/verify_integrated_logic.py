import asyncio
import os
import sys

# Mocking the discovery path to import orchestrator
sys.path.append(os.getcwd())

from orchestrator.reasoning.deterministic_validator import DeterministicValidator
from orchestrator.models.findings import RawFinding, Severity

async def verify_new_rules():
    print("--- Verifying New Rules Integration ---")
    validator = DeterministicValidator()
    
    # Test Finding 1: Path Traversal
    finding_pt = RawFinding(
        id="RUST_CORE_004_PATH_TRAVERSAL",
        message="Potentially vulnerable open() call detected",
        severity=Severity.HIGH,
        file_path="test_traversal.py",
        line=5,
        snippet="with open(filename, 'r') as f:",
        flow_path=["input()", "open()"]
    )
    
    # Test Finding 2: EternalBlue / SMB
    finding_smb = RawFinding(
        id="RUST_CORE_006_SMB_VULN",
        message="Insecure SMB connection detected",
        severity=Severity.CRITICAL,
        file_path="test_smb.py",
        line=10,
        snippet="conn = SMBConnection('user', 'password', 'client', 'server')",
        flow_path=["SMBConnection()"]
    )
    
    findings = [finding_pt, finding_smb]
    validated = await validator.validate(findings)
    
    for v in validated:
        print(f"\n[Finding: {v.raw.id}]")
        print(f"Status: {v.validation_status}")
        print(f"Confidence: {v.ai_confidence}")
        print(f"Notes: {v.reasoning_notes}")
        print(f"Suggestion: {v.remediation_suggestion}")
        print(f"Fix Description: {v.fix_description}")

if __name__ == "__main__":
    asyncio.run(verify_new_rules())
