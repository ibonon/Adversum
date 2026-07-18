import os
import logging
from orchestrator.services.shadow_discovery import ShadowDiscoveryEngine
from orchestrator.models.findings import Severity

# Setup logging
logging.basicConfig(level=logging.INFO)

TEST_FILE = "temp_shadow_test.py"
CODE = """
import os
import json

def benign_noise():
    # TEST 1: Whitelisted namespace (Should be IGNORED)
    os.path.join('a', 'b')
    os.getcwd()
    
    # TEST 2: Whitelisted function (Should be IGNORED)
    json.load(f)
    
    # TEST 3: Attribute collision (Should be IGNORED or Low Score)
    class MyObj:
        def load(self): pass
    obj = MyObj()
    obj.load()

def dangerous_calls(user_input):
    # TEST 4: Dangerous Built-in (Should be CRITICAL)
    eval(user_input)
    
    # TEST 5: Dangerous Namespace (Should be HIGH)
    os.system(user_input)
"""

def test_shadow_discovery():
    print("\n🚀 [SHADOW DISCOVERY PHASE 2 TEST] Starting Optimization Verification")
    
    if os.path.exists(TEST_FILE):
        os.remove(TEST_FILE)
    
    with open(TEST_FILE, "w") as f:
        f.write(CODE)
        
    engine = ShadowDiscoveryEngine()
    candidates = engine.discover_candidates(TEST_FILE)
    
    print(f"\nDiscovered {len(candidates)} candidates.")
    
    # Check Whitelist
    whitelisted = [c for c in candidates if "os.path.join" in c.snippet or "json.load" in c.snippet]
    if not whitelisted:
        print("✅ SUCCESS: Whitelisted functions (os.path.join, json.load) correctly ignored.")
    else:
        print(f"❌ FAILED: Whitelisted functions were flagged: {[c.snippet for c in whitelisted]}")

    # Check Attribute Collision
    attr_collision = [c for c in candidates if "obj.load()" in c.snippet]
    if not attr_collision:
        print("✅ SUCCESS: Attribute collision 'obj.load()' correctly ignored.")
    else:
        # If it's flagged, it should have a very low score
        print(f"❌ FAILED: Attribute collision 'obj.load()' was flagged (Snippet: {attr_collision[0].snippet})")

    # Check Real Threats
    criticals = [c for c in candidates if c.severity == Severity.CRITICAL]
    critical_snippets = [c.snippet for c in criticals]
    
    if "eval(user_input)" in critical_snippets and "os.system(user_input)" in critical_snippets:
        print(f"✅ SUCCESS: Both 'eval' and 'os.system' flagged as CRITICAL.")
    else:
        print(f"❌ FAILED: Real threats not flagged correctly. (Criticals: {critical_snippets})")

    if os.path.exists(TEST_FILE):
        os.remove(TEST_FILE)

if __name__ == "__main__":
    test_shadow_discovery()
