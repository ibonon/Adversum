import asyncio
import os
import shutil
import logging
from orchestrator.services.avr import AVREngine
from orchestrator.pipeline.analysis_pipeline import AnalysisPipeline
from orchestrator.models.findings import RawFinding

# Setup logging to see the loop in action
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

TEST_DIR = "temp_test_avr"
TEST_FILE = os.path.join(TEST_DIR, "vulnerable.py")

VULNERABLE_CODE = """
def process_data(user_input):
    # DANGEROUS: eval with user input
    result = eval(user_input)
    print(f"Result: {result}")

if __name__ == "__main__":
    process_data("input('enter code: ')")
"""

VALID_FIX = "result = int(user_input) # Safe conversion"
INVALID_FIX = "result = eval(user_input) # Still dangerous!"

async def run_test():
    print("\n🚀 [AVR TEST] Starting Autonomous Verified Remediation Test")
    
    # 1. Setup Test Environment
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)
    os.makedirs(TEST_DIR)
    
    with open(TEST_FILE, "w") as f:
        f.write(VULNERABLE_CODE)
    
    print(f"✓ Created vulnerable file: {TEST_FILE}")

    pipeline = AnalysisPipeline()
    avr = AVREngine()

    # 2. Initial Scan
    print("\n🔍 [AVR TEST] Step 1: Initial Scan...")
    result = await pipeline.run(TEST_FILE)
    findings = result["findings"]
    
    if not findings:
        print("❌ FAILED: No vulnerabilities detected in initial scan.")
        return

    target_finding = findings[0]
    print(f"✓ Detected: {target_finding.raw.rule_id} at line {target_finding.raw.line_number}")

    # 3. Test INVALID Fix (Should fail verification)
    print("\n🛡️ [AVR TEST] Step 2: Testing INVALID Fix (Expect failure)...")
    # We simulate the finding details
    success = await avr.run_remediation(
        finding_id=1,
        file_path=os.path.abspath(TEST_FILE),
        line_number=target_finding.raw.line_number,
        old_snippet=target_finding.raw.snippet,
        fix_code=INVALID_FIX
    )
    
    if not success:
        print("✓ SUCCESS: Invalid fix correctly rejected by Rust Core verification.")
    else:
        print("❌ FAILED: Invalid fix was wrongly accepted.")

    # 4. Test VALID Fix (Should pass verification)
    print("\n🛡️ [AVR TEST] Step 3: Testing VALID Fix (Expect success)...")
    success = await avr.run_remediation(
        finding_id=2,
        file_path=os.path.abspath(TEST_FILE),
        line_number=target_finding.raw.line_number,
        old_snippet=target_finding.raw.snippet,
        fix_code=VALID_FIX
    )
    
    if success:
        print("✓ SUCCESS: Valid fix applied and VERIFIED by Rust Core.")
    else:
        print("❌ FAILED: Valid fix was rejected.")

    # 5. Cleanup
    # shutil.rmtree(TEST_DIR)
    print("\n✨ [AVR TEST] Test Cycle Complete.")

if __name__ == "__main__":
    asyncio.run(run_test())
