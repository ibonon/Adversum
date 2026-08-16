import json
try:
    import adversum_core
except ImportError:
    print("Warning: adversum_core not found. SMT verification will not work.")

def verify_invariant_smt(ir_json: str, invariant_type: str, target: str):
    """
    Wrapper around adversum_core.verify_invariant_smt.
    ir_json: JSON representation of FunctionIR
    invariant_type: "overflow", "divzero", "path", "nonneg"
    target: name of function/file analyzed
    """
    return adversum_core.verify_invariant_smt(ir_json, invariant_type, target)
