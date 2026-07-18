import asyncio
import logging
from orchestrator.core_bridge.core_wrapper import CoreWrapper
from orchestrator.models.findings import RawFinding, Severity

# Configure logging
logging.basicConfig(level=logging.INFO)

async def test_bridge():
    print("Initializing CoreWrapper...")
    wrapper = CoreWrapper()
    
    if not wrapper.use_ffi:
        print("FFI not active. Cannot test real Rust objects.")
        return

    print("Creating Findings...")
    f1 = RawFinding(
        id="RUST_CORE_002_OS_SYSTEM",
        message="Test system call",
        severity=Severity.HIGH,
        file_path="test_bridge.py",
        line=42,
        snippet="os.system(cmd)",
        flow_path=["main", "system"]
    )
    
    findings = [f1]
    
    print("Running validate_findings via FFI...")
    try:
        results = wrapper.validate_findings(findings)
        print(f"Validation via FFI success! Results: {len(results)}")
        for r in results:
            # Check fields of ValidatedFinding (Rust object)
            print(f"Status: {r.validation_status}")
            print(f"Notes: {r.reasoning_notes}")
            print(f"Fix Code: {r.fix_code}")
    except Exception as e:
        print(f"CRASHED: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_bridge())
