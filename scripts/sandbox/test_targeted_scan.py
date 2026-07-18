import time
import os
import logging
from orchestrator.core_bridge.core_wrapper import CoreWrapper

logging.basicConfig(level=logging.INFO)

LARGE_FILE = "large_vulnerable_file.py"

def create_large_file():
    print(f"📦 Generating large file: {LARGE_FILE} (5000 lines)...")
    with open(LARGE_FILE, "w") as f:
        # Add 2500 lines of junk
        for i in range(2500):
            f.write(f"def junk_{i}(): pass\n")
        
        # Add the "vulnerable" patch zone
        f.write("# --- TARGET ZONE START ---\n")
        f.write("def sensitive_function():\n")
        f.write("    eval('dangerous_input') # Line 2503\n")
        f.write("# --- TARGET ZONE END ---\n")
        
        # Add 2500 more lines of junk
        for i in range(2500, 5000):
            f.write(f"def junk_{i}(): pass\n")

def run_benchmark():
    core = CoreWrapper()
    if not core.use_ffi:
        print("❌ FFI not linked. Cannot run Rust benchmark.")
        return

    create_large_file()
    
    print("\n⏱️  Starting FULL SCAN...")
    start_full = time.time()
    findings_full, _, _ = core.analyze([LARGE_FILE])
    end_full = time.time()
    print(f"✅ FULL SCAN complete: {len(findings_full)} findings found in {end_full - start_full:.4f}s")

    print("\n⏱️  Starting TARGETED SCAN (±15 lines around vulnerability)...")
    # Vulnerability is around line 2503
    dirty_ranges = {LARGE_FILE: [(2490, 2520)]}
    start_targeted = time.time()
    findings_target, _, _ = core.analyze([LARGE_FILE], dirty_ranges=dirty_ranges)
    end_targeted = time.time()
    print(f"✅ TARGETED SCAN complete: {len(findings_target)} findings found in {end_targeted - start_targeted:.4f}s")

    gain = (1 - (end_targeted - start_targeted) / (end_full - start_full)) * 100
    print(f"\n🚀 PERFORMANCE GAIN: {gain:.2f}%")
    
    if len(findings_target) == 1 and "dangerous_input" in findings_target[0].snippet:
        print("🎯 TARGETED PRECISION: SUCCESS (Exact threat identified)")
    else:
        print(f"⚠️  TARGETED PRECISION: FAIL (Found {len(findings_target)} findings)")

    if os.path.exists(LARGE_FILE): os.remove(LARGE_FILE)

if __name__ == "__main__":
    run_benchmark()
