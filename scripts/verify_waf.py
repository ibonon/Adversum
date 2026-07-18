import sys
import os
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestrator.services.adversarial_sim import AdversarialSimulator

def test_waf_ids():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("Adversum.WAFTest")
    
    sim = AdversarialSimulator()
    input_vector = [0.5] * 10
    
    print("\n" + "="*70)
    print(" WAF/IDS SIMULATION VERIFICATION ")
    print("="*70)
    
    # Scenario 1: HSJ without WAF
    print(f"\n[SCENARIO 1] HSJ without WAF/IDS")
    result_no_waf = sim.simulate_attack("HSJ", input_vector, epsilon=0.2)
    print(f"  Success: {result_no_waf.get('success')}")
    print(f"  Queries: {result_no_waf.get('query_count')}")
    print(f"  Blocked by WAF: {result_no_waf.get('blocked_by_waf')}")
    print(f"  Threat Score: {result_no_waf.get('threat_score', 0.0):.1f}")

    # Scenario 2: HSJ vs WAF/IDS (Low Threshold)
    print(f"\n[SCENARIO 2] HSJ vs WAF/IDS (Aggressive Blocking)")
    oracle_config_aggressive = {
        "boundary_type": "distance",
        "threshold": 0.3,
        "sensitive_patterns": None,
        "defense_level": 0.9,
        "defense_type": "none",
        "waf_enabled": True,
        "threat_threshold": 30.0,
        "block_threshold": 80.0
    }
    result_waf_aggressive = sim.simulate_attack("HSJ", input_vector, epsilon=0.2, oracle_config=oracle_config_aggressive)
    print(f"  Success: {result_waf_aggressive.get('success')}")
    print(f"  Queries: {result_waf_aggressive.get('query_count')}")
    print(f"  Blocked by WAF: {result_waf_aggressive.get('blocked_by_waf')}")
    print(f"  Threat Score: {result_waf_aggressive.get('threat_score', 0.0):.1f}")
    print(f"  Attack Progress: {(result_waf_aggressive.get('query_count') / 1200) * 100:.1f}%")

    # Scenario 3: HSJ vs WAF/IDS (Moderate Threshold)
    print(f"\n[SCENARIO 3] HSJ vs WAF/IDS (Moderate Blocking)")
    oracle_config_moderate = {
        "boundary_type": "distance",
        "threshold": 0.3,
        "sensitive_patterns": None,
        "defense_level": 0.9,
        "defense_type": "none",
        "waf_enabled": True,
        "threat_threshold": 50.0,
        "block_threshold": 150.0
    }
    result_waf_moderate = sim.simulate_attack("HSJ", input_vector, epsilon=0.2, oracle_config=oracle_config_moderate)
    print(f"  Success: {result_waf_moderate.get('success')}")
    print(f"  Queries: {result_waf_moderate.get('query_count')}")
    print(f"  Blocked by WAF: {result_waf_moderate.get('blocked_by_waf')}")
    print(f"  Threat Score: {result_waf_moderate.get('threat_score', 0.0):.1f}")
    print(f"  Attack Progress: {(result_waf_moderate.get('query_count') / 1200) * 100:.1f}%")

    print("\n" + "="*70)
    print("\n[ANALYSIS]")
    print(f"  WAF Effectiveness: Blocked at {(result_waf_aggressive.get('query_count') / 1200) * 100:.0f}% completion")
    print(f"  Threat Detection: {'ACTIVE' if result_waf_aggressive.get('blocked_by_waf') else 'INACTIVE'}")
    print(f"  Protection Level: {'STRONG' if result_waf_aggressive.get('blocked_by_waf') else 'WEAK'}")
    print("="*70)

if __name__ == "__main__":
    test_waf_ids()
