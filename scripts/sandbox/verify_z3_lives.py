"""Preuve de vie Z3 — vérifie que z3-solver est installé et fonctionne réellement."""
from z3 import Solver, Int, sat

x = Int('x')
s = Solver()
s.add(x > 64)
s.add(x < 200)
result = s.check()
print(f"Z3 check result: {result}")
if result == sat:
    print(f"Model: {s.model()}")
