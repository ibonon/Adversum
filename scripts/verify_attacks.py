import sys
import os
import json
import logging

# Ensure orchestrator is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestrator.services.adversarial_sim import AdversarialSimulator

def test_evasion_kit():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("Adversum.AdversarialTest")
    
    sim = AdversarialSimulator()
    
    # Sample input vector (e.g., 10 features normalized)
    input_vector = [0.5, 0.2, 0.8, 0.1, 0.9, 0.4, 0.3, 0.7, 0.6, 0.0]
    
    methods = ["FGSM", "PGD", "C&W"]
    
    print("\n" + "="*50)
    print(" ADVERSARIAL EVASION KIT VERIFICATION ")
    print("="*50)
    
    for method in methods:
        print(f"\nTesting Method: {method}")
        result = sim.simulate_attack(method, input_vector, epsilon=0.1)
        
        if result.get("success"):
            print(f"  [OK] Success: True")
            print(f"  [OK] Perturbation Norm: {result.get('perturbation_norm', 0):.4f}")
            
            # Check if data actually changed
            perturbed = result.get("perturbed_data", [])
            diff = sum(abs(p - o) for p, o in zip(perturbed, input_vector))
            print(f"  [OK] Data Divergence (Sum Abs Diff): {diff:.4f}")
        else:
            print(f"  [FAIL] Failed: {result.get('error', 'Unknown Error')}")
            
    print("="*50)

if __name__ == "__main__":
    test_evasion_kit()
