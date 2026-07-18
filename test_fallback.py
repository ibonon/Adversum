import logging
from adversum.orchestrator.core_bridge.core_wrapper import CoreWrapper

logging.basicConfig(level=logging.INFO)

dummy_vuln = "dummy_vuln.py"
with open(dummy_vuln, "w") as f:
    f.write("""
import os
import subprocess

def bad_func():
    user_input = request.args.get('cmd')
    os.system(user_input)
    subprocess.run(f"ls {user_input}", shell=True)
    open(f"/tmp/{user_input}")
""")

wrapper = CoreWrapper()
findings, hashes, ms = wrapper.analyze([dummy_vuln])

print(f"\n--- FINDINGS ({len(findings)}) ---")
for f in findings:
    print(f"[{f.severity}] {f.id} @ line {f.line}: {f.message}")
    print(f"  Snippet: {f.snippet}")
    print()
