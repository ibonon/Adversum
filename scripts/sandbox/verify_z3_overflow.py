"""ÉTAPE 3 — preuve Z3 réelle sur un fixture overflow, via la règle regex existante."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from modules.solidity.rules import arithmetic
from modules.formal_verification.z3_prover import prove_overflow

FIXTURE = os.path.join(
    "modules", "solidity", "tests", "test_contracts", "overflow.sol"
)

with open(FIXTURE, "r", encoding="utf-8") as fh:
    source = fh.read()

findings = arithmetic.analyze(source)
print(f"Findings SOL-004 detectes par la regle regex : {len(findings)}")

for finding in findings:
    print(f"\n--- ligne {finding['line']} : {finding['snippet']}")
    proof = prove_overflow(finding)
    print(json.dumps(proof, indent=2, ensure_ascii=False))
