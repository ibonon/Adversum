"""Vérification factuelle de l'état du moteur Rust (core/ast, core/ir,
core/cfg, core/dataflow) exposé via PyO3.

Ne suppose rien : imprime ce qui existe réellement — les attributs du module
`adversum_core` installé, l'état du bridge (use_ffi), et la sortie brute
produite sur overflow.sol.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

SEP = "=" * 78
overflow = os.path.join(ROOT, "modules", "solidity", "tests", "test_contracts", "overflow.sol")
with open(overflow, "r", encoding="utf-8", errors="ignore") as fh:
    src = fh.read()

print(SEP)
print("1. MODULE PYTHON `adversum_core`")
print(SEP)
try:
    import adversum_core
    print("import           : OK")
    print("__file__         :", adversum_core.__file__)
    print("chemin          :", os.path.dirname(adversum_core.__file__))
    public = sorted(a for a in dir(adversum_core) if not a.startswith("_"))
    print("attributs        :", public)
    for needed in ("Finding", "inspect_files", "analyze_auto_py", "inspect_code",
                   "build_attack_graph", "validate_findings", "verify_invariant_smt"):
        print(f"  hasattr({needed:22s}) = {hasattr(adversum_core, needed)}")
except Exception as exc:
    print("import           : ÉCHEC", type(exc).__name__, exc)
    adversum_core = None

print()
print(SEP)
print("2. ÉTAT DU BRIDGE CoreWrapper")
print(SEP)
try:
    from orchestrator.core_bridge.core_wrapper import CoreWrapper
    wrapper = CoreWrapper()
    print("use_ffi          :", wrapper.use_ffi)
    print("rust_core        :", wrapper.rust_core)
except Exception as exc:
    print("CoreWrapper      : ÉCHEC", type(exc).__name__, exc)
    wrapper = None

print()
print(SEP)
print("3. SORTIE BRUTE SUR overflow.sol")
print(SEP)
print("fixture          :", overflow)

if adversum_core is not None:
    # 3a. analyze_auto_py : l'API "analyse d'un fichier" exposée à Python
    try:
        res = adversum_core.analyze_auto_py(src, overflow)
        print("\n[analyze_auto_py] type =", type(res).__name__, "| len =", len(res))
        print("[analyze_auto_py] findings =", res)
    except Exception as exc:
        print("\n[analyze_auto_py] EXCEPTION:", type(exc).__name__, exc)

    # 3b. inspect_files : l'API effectivement appelée par CoreWrapper.analyze
    try:
        res = adversum_core.inspect_files([overflow])
        print("\n[inspect_files] objet renvoyé :", type(res).__name__)
        print("[inspect_files] findings      :", list(getattr(res, "findings", [])))
        print("[inspect_files] file_hashes   :", dict(getattr(res, "file_hashes", {})))
        print("[inspect_files] robustness    :", getattr(res, "robustness_score", None))
    except Exception as exc:
        print("\n[inspect_files] EXCEPTION:", type(exc).__name__, exc)

    # 3c. Contrôle : le moteur produit-il des findings sur un fichier *Python* ?
    py_src = (
        "import os\n"
        "import sys\n"
        'cmd = os.environ.get("CMD")\n'
        "os.system(cmd)\n"
        "eval(sys.argv[1])\n"
    )
    try:
        res = adversum_core.analyze_auto_py(py_src, "sample.py")
        print(f"\n[analyze_auto_py sur sample.py] findings = {len(res)}")
        for f in res:
            print(f"   - {f.id} | line {f.line} | {f.severity} | {f.snippet!r}")
    except Exception as exc:
        print("\n[analyze_auto_py sur sample.py] EXCEPTION:", type(exc).__name__, exc)

    # 3d. Y a-t-il un export AST / CFG / dataflow ?
    ast_like = [a for a in dir(adversum_core) if any(k in a.lower() for k in
                ("ast", "cfg", "dataflow", "taint", "ir", "graph", "parse"))]
    print("\n[exposition AST/CFG/dataflow] attributs candidats :", ast_like)
else:
    print("skip (module non importable)")

print()
print(SEP)
print("4. SUPPORT SOLIDITY DANS LE MOTEUR RUST (source)")
print(SEP)
for f in ("core/src/lib.rs",):
    p = os.path.join(ROOT, f)
    with open(p, "r", encoding="utf-8", errors="ignore") as fh:
        for i, line in enumerate(fh, 1):
            if "from_extension" in line or '"sol"' in line or "Solidity" in line:
                print(f"{f}:{i}: {line.rstrip()}")

print()
print(SEP)
print("5. MATRICE DE SONDES — le moteur Rust produit-il le moindre finding ?")
print(SEP)
SAMPLES = [
    ("eval direct",            "eval(input())\n"),
    ("os.system direct",       "import os\nos.system(input())\n"),
    ("taint via variable",     "import os\nx = os.environ.get('C')\nos.system(x)\n"),
    ("pickle.loads",           "import pickle\npickle.loads(open('f','rb').read())\n"),
    ("yaml.load",              "import yaml\nyaml.load(open('f').read())\n"),
    ("subprocess shell=True",  "import subprocess\nsubprocess.run(input(), shell=True)\n"),
]
if adversum_core is not None:
    for label, code in SAMPLES:
        try:
            r = adversum_core.analyze_auto_py(code, "probe.py")
            ids = [f.id for f in r]
            print(f"  {label:24s} -> {len(r)} finding(s) {ids}")
        except Exception as exc:
            print(f"  {label:24s} -> EXCEPTION {type(exc).__name__}: {exc}")
