import os
import shutil
import logging
from orchestrator.services.patcher import PatchService

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

TEST_FILE = "temp_batch_test.py"
INITIAL_CODE = """
def first():
    eval(input())

def second():
    exec(input())

def third():
    os.system(input())
"""

def test_batch_patching():
    print("\n🚀 [PATCH BATCH TEST] Starting Batch Patching Test")
    
    # 1. Setup
    if os.path.exists(TEST_FILE):
        os.remove(TEST_FILE)
    
    with open(TEST_FILE, "w") as f:
        f.write(INITIAL_CODE)
        
    patcher = PatchService()
    
    # 2. Define fixes
    # Note: We provide line numbers relative to the INITIAL code. 
    # Batch patching should handle line order internally (descending).
    fixes = [
        (3, "    eval(input())", "    int(input()) # SAFE"),
        (6, "    exec(input())", "    print(input()) # SAFE"),
        (9, "    os.system(input())", "    subprocess.run(input()) # SAFE")
    ]
    
    # 3. Apply
    print("Applying 3 fixes in batch...")
    success = patcher.apply_batch_fixes(TEST_FILE, fixes)
    
    # 4. Verify
    if success:
        with open(TEST_FILE, "r") as f:
            new_content = f.read()
        
        print("\nNew Content:")
        print(new_content)
        
        # Check if all replacements are there
        if "int(input()) # SAFE" in new_content and \
           "print(input()) # SAFE" in new_content and \
           "subprocess.run(input()) # SAFE" in new_content:
            print("\n✅ SUCCESS: All 3 patches applied correctly with offset handling.")
        else:
            print("\n❌ FAILED: Some patches are missing or corrupted.")
    else:
        print("\n❌ FAILED: Batch patch operation failed.")

    # Cleanup
    if os.path.exists(TEST_FILE):
        os.remove(TEST_FILE)
    if os.path.exists(f"{TEST_FILE}.bak"):
        os.remove(f"{TEST_FILE}.bak")

if __name__ == "__main__":
    test_batch_patching()
