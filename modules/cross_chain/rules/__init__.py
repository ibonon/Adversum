"""
Cross-chain security detection rules.
"""
from .replay import ReplayVulnerabilityRule
from .proof_bypass import ProofBypassRule
from .quorum import QuorumSecurityRule
from .unbacked_mint import UnbackedMintRule

ALL_RULES = [
    ReplayVulnerabilityRule,
    ProofBypassRule,
    QuorumSecurityRule,
    UnbackedMintRule,
]
