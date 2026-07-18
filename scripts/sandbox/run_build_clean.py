import subprocess
import os

cwd = r"F:\Adversum\adversum\core"
log_file = r"F:\Adversum\adversum\core\build_log_clean.txt"

print(f"Running cargo build in {cwd}...")
with open(log_file, "w", encoding="utf-8") as f:
    result = subprocess.run(["cargo", "build", "--release"], cwd=cwd, stdout=f, stderr=subprocess.STDOUT, text=True, encoding="utf-8")
    
print(f"Build finished with code {result.returncode}")
