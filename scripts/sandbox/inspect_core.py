import sys
import os
from pathlib import Path

# Add project root to sys.path
project_root = Path(r"f:\Adversum\adversum").resolve()
sys.path.append(str(project_root))

try:
    import adversum_core
    print(f"SUCCESS: adversum_core imported from {adversum_core.__file__}")
    print("Attributes in adversum_core:")
    for attr in sorted(dir(adversum_core)):
        if not attr.startswith("__"):
            print(f"  - {attr}")
            
except Exception as e:
    print(f"FAILURE: {e}")
