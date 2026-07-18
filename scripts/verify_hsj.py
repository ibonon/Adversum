import sys
import os
import json
import logging

# Ensure orchestrator is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestrator.services.adversarial_sim import AdversarialSimulator

def test_hsj_blackbox():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("Adversum.HSJTest")
    
    sim = AdversarialSimulator()
    
    # Sample input vector (10 features)
    # The oracle in Rust is hardcoded to respond to this shape and simulated behavior
    input_vector = [0.5] * 10
    
    print("\n" + "="*50)
    print(" BLACK-BOX ATTACK (HOPSKIPJUMP) VERIFICATION ")
    print("="*50)
    
    # Test HSJ
    method = "HSJ"
    print(f"\nTesting Method: {method} (Query-Based / Decision-Only)")
    
    # We use a slightly larger epsilon to allow the simulated oracle to be triggered
    result = sim.simulate_attack(method, input_vector, epsilon=0.2)
    
    if result.get("success"):
        print(f"  [OK] Success: True")
        print(f"  [OK] Algorithm: {result.get('algorithm')}")
        print(f"  [OK] Perturbation Norm (L2): {result.get('perturbation_norm', 0):.4f}")
        
        # Check if data actually changed
        perturbed = result.get("perturbed_data", [])
        diff = sum((p - o)**2 for p, o in zip(perturbed, input_vector))**0.5
        print(f"  [OK] Real L2 Distance: {diff:.4f}")
        
        if diff > 0:
            print(f"  [OK] Adversarial sample generated successfully.")
        else:
            print(f"  [WARN] Data did not change despite success flag.")
    else:
        print(f"  [FAIL] Failed: {result.get('error', 'Unknown Error')}")
        if not result.get("success") and "error" not in result:
             print(f"  [INFO] Attack unsuccessful (expected if boundary not found in mock).")
            
    print("="*50)

if __name__ == "__main__":
    test_hsj_blackbox()
