"""
Real-world DeFi attack scenarios for Adversum Attack Simulator
"""
from .euler_finance import euler_finance_scenario
from .ronin_bridge import ronin_bridge_scenario
from .mango_markets import mango_markets_scenario
from .wormhole import wormhole_scenario
from .generic_flashloan_cascade import generic_flashloan_cascade_scenario

SCENARIO_REGISTRY = {
    "euler_finance": euler_finance_scenario,
    "ronin_bridge": ronin_bridge_scenario,
    "mango_markets": mango_markets_scenario,
    "wormhole": wormhole_scenario,
    "generic_flashloan_cascade": generic_flashloan_cascade_scenario,
}

__all__ = ["SCENARIO_REGISTRY"]
