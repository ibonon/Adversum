import sys
import os
from pathlib import Path

# Add project root to sys.path
project_root = Path(r"f:\Adversum\adversum").resolve()
sys.path.append(str(project_root))

try:
    import adversum_core
    print("SUCCESS: adversum_core imported")
    
    # Test a simple function
    hashes = adversum_core.compute_hashes([str(project_root / "check_audit.py")])
    print(f"Hashes test: {hashes}")
    
    # Test validate_findings
    # We need a Finding object
    f = adversum_core.Finding(
        id="RUST_CORE_001_DANGEROUS_EVAL",
        message="Test message",
        severity="HIGH",
        line=10,
        snippet="eval(input())",
        file_path="test.py",
        flow_path=["input", "eval"],
        proof=None,
        immune_context=None
    )
    
    validated = adversum_core.validate_findings([f])
    print(f"Validation test: {len(validated)} findings validated")
    for v in validated:
        print(f"  Status: {v.validation_status}")
        print(f"  Notes: {v.reasoning_notes}")
        
except ImportError as e:
    print(f"FAILURE: Could not import adversum_core: {e}")
except Exception as e:
    print(f"FAILURE: Unexpected error: {e}")
