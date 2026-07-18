import sys
import os
import json
import logging

# Ensure orchestrator is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestrator.services.adversarial_sim import AdversarialSimulator

def test_advanced_attacks():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("Adversum.AdvancedTest")
    
    sim = AdversarialSimulator()
    input_vector = [0.1, 0.1, 0.1, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5]
    
    print("\n" + "="*60)
    print(" ADVANCED BLACK-BOX ATTACK VERIFICATION ")
    print("="*60)
    
    # 1. Test Dynamic Oracle (Improvement 1)
    print(f"\n[SCENARIO 1] HSJ with Dynamic Pattern-Based Oracle")
    # Rule: Boundary is crossed if sum(first 3) > 1.0 (currently 0.3)
    oracle_config = {
        "boundary_type": "pattern",
        "threshold": 1.0,
        "sensitive_patterns": None,
        "defense_level": 0.0,
        "defense_type": None,
        "waf_enabled": False,
        "threat_threshold": 50.0,
        "block_threshold": 100.0
    }
    
    result_dsj = sim.simulate_attack("HSJ", input_vector, epsilon=0.2, oracle_config=oracle_config)
    
    if result_dsj.get("success"):
        print(f"  [OK] HSJ Success: {result_dsj['success']}")
        print(f"  [OK] Queries: {result_dsj.get('query_count')}")
        perturbed = result_dsj.get("perturbed_data", [])
        pattern_sum = sum(perturbed[:3])
        print(f"  [OK] Perturbed Pattern Sum: {pattern_sum:.4f} (Goal: > 1.0)")
    else:
        print(f"  [FAIL] HSJ Scenario 1 Failed: {result_dsj.get('error', 'Boundary not reached')}")

    # 2. Test Transfer Attack (Improvement 4)
    print(f"\n[SCENARIO 2] Transfer Attack (Shadow Model Simulation)")
    result_transfer = sim.simulate_attack("TRANSFER", input_vector, epsilon=0.1)
    
    if "success" in result_transfer:
        print(f"  [OK] Transfer Success on Black-Box: {result_transfer['success']}")
        print(f"  [OK] Algorithm Used: {result_transfer.get('algorithm')}")
        print(f"  [OK] Perturbation Norm: {result_transfer.get('perturbation_norm', 0):.4f}")
    else:
         print(f"  [FAIL] Transfer Test Failed: {result_transfer.get('error')}")

    print("\n" + "="*60)

if __name__ == "__main__":
    test_advanced_attacks()
