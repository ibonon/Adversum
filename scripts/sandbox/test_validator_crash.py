import asyncio
import logging
from orchestrator.reasoning.deterministic_validator import DeterministicValidator
from orchestrator.models.findings import RawFinding, Severity

# Configure logging
logging.basicConfig(level=logging.INFO)

async def test_crash():
    print("Initializing Validator...")
    validator = DeterministicValidator()
    
    print("Creating Findings...")
    f1 = RawFinding(
        id="RUST_CORE_001_DANGEROUS_EVAL",
        message="Test finding",
        severity=Severity.CRITICAL,
        file_path="test_file.py",
        line=10,
        snippet="eval('1+1')",
        flow_path=["main", "eval"]
    )
    
    findings = [f1]
    
    print("Running validate...")
    try:
        results = await validator.validate(findings)
        print(f"Validation success! Results: {len(results)}")
        for r in results:
            print(f"Status: {r.validation_status}")
    except Exception as e:
        print(f"CRASHED: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_crash())
