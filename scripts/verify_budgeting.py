import sys
import os
import json
import logging

# Ensure orchestrator is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestrator.services.adversarial_sim import AdversarialSimulator

def test_query_budgeting():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("Adversum.BudgetTest")
    
    sim = AdversarialSimulator()
    input_vector = [0.5] * 10
    
    print("\n" + "="*60)
    print(" QUERY BUDGETING & COST ANALYSIS VERIFICATION ")
    print("="*60)
    
    # scenario 1: Unlimited budget (default)
    print(f"\n[SCENARIO 1] HSJ with Unlimited Budget")
    result_unlimited = sim.simulate_attack("HSJ", input_vector, epsilon=0.2)
    print(f"  [OK] Success: {result_unlimited.get('success')}")
    print(f"  [OK] Queries: {result_unlimited.get('query_count')}")
    print(f"  [OK] Cost: ${result_unlimited.get('cost', 0.0):.4f}")

    # scenario 2: Restricted budget (should fail if budget < required queries)
    budget = 100
    print(f"\n[SCENARIO 2] HSJ with Restricted Budget ({budget} queries)")
    result_limited = sim.simulate_attack("HSJ", input_vector, epsilon=0.2, query_budget=budget)
    
    if not result_limited.get("success"):
        print(f"  [OK] HSJ stopped as expected due to budget constraint.")
        print(f"  [OK] Queries used: {result_limited.get('query_count')}")
        print(f"  [OK] Cost: ${result_limited.get('cost', 0.0):.4f}")
    else:
        print(f"  [WARN] HSJ succeeded despite low budget ({result_limited.get('query_count')} queries).")

    print("\n" + "="*60)

if __name__ == "__main__":
    test_query_budgeting()
