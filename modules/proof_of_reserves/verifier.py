#!/usr/bin/env python3
"""
Adversum Proof of Reserves Standalone Verifier
Allows clients, auditors, and individual users to mathematically verify their account balance inclusion.
"""
import sys
import json
import argparse
from typing import Dict, Any

try:
    from .merkle_sum_tree import verify_inclusion_proof
except ImportError:
    from merkle_sum_tree import verify_inclusion_proof

class PoRVerifier:
    @staticmethod
    def verify_proof_file(proof_path: str, root_hash: str, total_liabilities: float, salt: str) -> Dict[str, Any]:
        with open(proof_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        user_id = data["user_id"]
        balance = float(data["balance"])
        steps = data["proof_steps"]

        is_valid, msg = verify_inclusion_proof(
            user_id=user_id,
            balance=balance,
            salt=salt,
            root_hash=root_hash,
            root_total_liabilities=total_liabilities,
            proof_steps=steps
        )

        return {
            "verified": is_valid,
            "user_id": user_id,
            "balance": balance,
            "message": msg
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Adversum Proof of Reserves Proof Verifier")
    parser.add_argument("--proof", required=True, help="Path to JSON inclusion proof file")
    parser.add_argument("--root", required=True, help="Published Merkle Root Hash")
    parser.add_argument("--total", required=True, type=float, help="Total Declared Liabilities")
    parser.add_argument("--salt", required=True, help="User secret salt")
    args = parser.parse_args()

    res = PoRVerifier.verify_proof_file(args.proof, args.root, args.total, args.salt)
    print(json.dumps(res, indent=2))
    if not res["verified"]:
        sys.exit(1)
