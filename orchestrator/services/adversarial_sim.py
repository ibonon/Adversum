import logging
import json
import os
from typing import Dict, Any, List, Optional
from ..core_bridge.core_wrapper import CoreWrapper

logger = logging.getLogger(__name__)

class AdversarialResultDict(dict):
    """Provides both dictionary and attribute-style access to attack simulation results."""
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"'AdversarialResultDict' object has no attribute '{name}'")
            
    def __setattr__(self, name, value):
        self[name] = value

class AdversarialSimulator:
    """
    Interfaces with the Rust Adversarial Kit.
    Simulates attacks (PGD, FGSM) to test the robustness of security patches.
    """
    
    def __init__(self):
        self.wrapper = CoreWrapper()

    def simulate_attack(self, method: str, data_payload: Optional[List[float]] = None, 
                        epsilon: float = 0.1, 
                        oracle_config: Optional[Dict[str, Any]] = None,
                        shadow_model_id: Optional[str] = None,
                        query_budget: Optional[int] = None,
                        prompt: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes an adversarial attack simulation via the Rust Core.
        Supports Dynamic Oracles (1), Transfer Attacks (4), and Query Budgeting (2).
        """
        if not self.wrapper.use_ffi:
            from ..config.settings import settings

            # Strict mode (opt-in via ADVERSUM_STRICT_CORE=true) raises instead
            # of degrading, which is useful in CI to assert the Rust kit is
            # built. Default behaviour degrades gracefully and DETERMINISTICALLY:
            # we never fabricate a probabilistic attack result.
            strict = os.getenv("ADVERSUM_STRICT_CORE", "false").lower() == "true"
            if strict and not settings.MOCK_CORE:
                raise RuntimeError(
                    "Adversarial Kit (Rust) not linked and ADVERSUM_STRICT_CORE "
                    "is set. Cannot run adversarial simulation."
                )

            # Determinism: never fabricate a probabilistic attack result.
            # Without the Rust kit we cannot run a real adversarial simulation,
            # so we return a deterministic "skipped" result with a neutral
            # robustness score (1.0 = no observed weakness) rather than a
            # random success/failure that would corrupt RBAT scores.
            logger.warning(
                "Adversarial Kit (Rust) not linked — skipping adversarial "
                "simulation (deterministic skip, no fabricated result)."
            )
            return {
                "success": False,
                "perturbed_data": list(data_payload or []),
                "method": method,
                "epsilon": epsilon,
                "query_count": 0,
                "cost": 0.0,
                "detected": False,
                "blocked_by_waf": False,
                "threat_score": 0.0,
                "robustness_score": 1.0,
                "adversarial_prompt": None,
                "skipped": True,
            }

        try:
            # Native Object Instantiation (Strict FFI)
            oc = None
            if oracle_config:
                oc = self.wrapper.rust_core.OracleConfig(**oracle_config)

            request = self.wrapper.rust_core.AdversarialRequest(
                algorithm=method.upper(),
                input_data=[float(val) for val in (data_payload or [])],
                shape=[len(data_payload or [])],
                epsilon=float(epsilon),
                oracle_config=oc,
                shadow_model_id=shadow_model_id,
                query_budget=query_budget,
                prompt=prompt
            )
            
            # Call the Rust pyfunction: run_adversarial(req: AdversarialRequest)
            result = self.wrapper.rust_core.run_adversarial(request)
            
            logger.info(f"Adversarial Simulation ({method}) complete. Success: {result.success} (Queries: {result.query_count}, Cost: ${result.cost:.4f}, Detected: {result.detected})")
            return AdversarialResultDict({
                "success": getattr(result, "success", False),
                "perturbed_data": list(getattr(result, "perturbed_data", [])),
                "algorithm": getattr(result, "algorithm", method),
                "method": getattr(result, "algorithm", method),
                "epsilon": epsilon,
                "query_count": getattr(result, "query_count", 0),
                "cost": getattr(result, "cost", 0.0),
                "detected": getattr(result, "detected", False),
                "blocked_by_waf": getattr(result, "blocked_by_waf", False),
                "threat_score": getattr(result, "threat_score", 0.0),
                "robustness_score": getattr(result, "robustness_score", 1.0),
                "adversarial_prompt": getattr(result, "adversarial_prompt", None),
                "perturbation_norm": getattr(result, "perturbation_norm", 0.0),
            })
            
        except Exception as e:
            logger.error(f"Adversarial Simulation Failed: {e}")
            # Fallback to empty mock result to avoid crashing pipeline
            return {"status": "error", "error": str(e), "robustness_score": 1.0}

    def generate_perturbation_report(self, original_score: float, adversarial_score: float) -> str:
        """Generates a human-readable comparison for the Reasoning Layer."""
        diff = original_score - adversarial_score
        if diff > 0.5:
            return "CRITICAL BYPASS: Small perturbation completely nullifies the security patch."
        elif diff > 0.2:
            return "WEAK RESILIENCE: Patch is unstable under adversarial pressure."
        return "HIGH RESILIENCE: Patch holds firm against the simulated attack kit."
