import sys
import os
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestrator.services.adversarial_sim import AdversarialSimulator

def test_attacker_vs_defender():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("Adversum.DefenderTest")
    
    sim = AdversarialSimulator()
    input_vector = [0.5] * 10
    
    print("\n" + "="*70)
    print(" ATTACKER VS DEFENDER DYNAMICS VERIFICATION ")
    print("="*70)
    
    # Scenario 1: Normal HSJ (no defense)
    print(f"\n[SCENARIO 1] Normal HSJ (No Defense)")
    result_normal = sim.simulate_attack("HSJ", input_vector, epsilon=0.2)
    print(f"  [OK] Success: {result_normal.get('success')}")
    print(f"  [OK] Queries: {result_normal.get('query_count')}")
    print(f"  [OK] Detected: {result_normal.get('detected')}")
    print(f"  [OK] Cost: ${result_normal.get('cost', 0.0):.4f}")

    # Scenario 2: HSJ vs Intelligent Defense
    print(f"\n[SCENARIO 2] HSJ vs Intelligent Defense (Geometric Filter)")
    oracle_config = {
        "boundary_type": "distance",
        "threshold": 0.3,
        "sensitive_patterns": None,
        "defense_level": 0.9,
        "defense_type": "geometric_filter",
        "waf_enabled": False,
        "threat_threshold": 50.0,
        "block_threshold": 100.0
    }
    result_defended = sim.simulate_attack("HSJ", input_vector, epsilon=0.2, oracle_config=oracle_config)
    print(f"  [OK] Success: {result_defended.get('success')}")
    print(f"  [OK] Queries: {result_defended.get('query_count')}")
    print(f"  [OK] Detected: {result_defended.get('detected')}")
    print(f"  [OK] Cost: ${result_defended.get('cost', 0.0):.4f}")

    # Scenario 3: Stealthy HSJ vs Defense
    print(f"\n[SCENARIO 3] Stealthy HSJ vs Defense (Evasion Attempt)")
    result_stealthy = sim.simulate_attack("STEALTHY_HSJ", input_vector, epsilon=0.2, oracle_config=oracle_config)
    print(f"  [OK] Success: {result_stealthy.get('success')}")
    print(f"  [OK] Queries: {result_stealthy.get('query_count')}")
    print(f"  [OK] Detected: {result_stealthy.get('detected')}")
    print(f"  [OK] Cost: ${result_stealthy.get('cost', 0.0):.4f}")

    # Scenario 4: Active Transfer Attack
    print(f"\n[SCENARIO 4] Active Transfer Attack (Shadow Model Refinement)")
    result_active = sim.simulate_attack("ACTIVE_TRANSFER", input_vector, epsilon=0.1)
    print(f"  [OK] Success: {result_active.get('success')}")
    print(f"  [OK] Queries: {result_active.get('query_count')}")
    print(f"  [OK] Algorithm: {result_active.get('algorithm')}")
    print(f"  [OK] Perturbation: {result_active.get('perturbation_norm', 0):.4f}")

    print("\n" + "="*70)
    print("\n[ANALYSIS]")
    print(f"  Detection Rate: {sum([result_defended.get('detected', False), result_stealthy.get('detected', False)]) / 2 * 100:.0f}%")
    print(f"  Stealthy Evasion: {'SUCCESS' if not result_stealthy.get('detected') else 'FAILED'}")
    print("="*70)

if __name__ == "__main__":
    test_attacker_vs_defender()
