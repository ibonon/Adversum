"""ÉTAPE R3 — visibilité et distinction du champ `scope` ET du verdict
UNSAT/guarded dans le rapport HTML réel.

Exécute la chaîne de production complète (règle regex -> SmartPatchValidator
-> HTMLReportGenerator) sur deux fixtures :
  - un contrat VULNÉRABLE (aucune garde)  -> verdict attendu SAT
  - un contrat PROTÉGÉ (SafeMath dans le fichier) -> verdict UNSAT/UNPARSED,
    guarded=True, qui doit être présenté comme « protégé », pas comme une
    simple absence de résultat.

Sortie : chemin du HTML généré + vérification littérale des marqueurs.
"""
import json
import os
import sys
import tempfile
from dataclasses import asdict

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from modules.solidity.rules import arithmetic
from modules.intelligence.smart_patch_validator import SmartPatchValidator
from modules.html_report.generator import HTMLReportGenerator

SEP = "=" * 78


def banner(title):
    print(f"\n{SEP}\n{title}\n{SEP}")


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures : deux contrats ciblant la même règle SOL-004.
# ─────────────────────────────────────────────────────────────────────────────
VULNERABLE_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract InsecureCounter {
    uint256 public totalSupply;

    function add(uint256 amount) public {
        totalSupply = totalSupply + amount;
    }
}
"""

# SafeMath présent dans le fichier MAIS sans directive `using SafeMath` :
# la garde fichier-entier de la règle regex (arithmetic.py:36) ne s'applique
# donc pas, et la règle émet bien des findings — ce qui rend la branche
# UNSAT/guarded du solveur réellement atteignable en production.
PROTECTED_SOL = """pragma solidity ^0.4.24;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }
}

contract GuardedToken {
    uint256 public totalSupply;

    function mint(uint256 amount) public {
        totalSupply = totalSupply + amount;
    }
}
"""

FIXTURES = [
    ("InsecureCounter.sol", VULNERABLE_SOL, "vulnerable"),
    ("GuardedToken.sol", PROTECTED_SOL, "protected"),
]

# ─────────────────────────────────────────────────────────────────────────────
# 1. Règle regex réelle -> findings
# ─────────────────────────────────────────────────────────────────────────────
banner("1. Findings SOL-004 émis par la règle regex")

all_findings = []
for fname, src, kind in FIXTURES:
    findings = arithmetic.analyze(src)
    print(f"{kind:11s} {fname:22s} -> {len(findings)} finding(s)")
    for f in findings:
        f["file"] = fname
        f["severity"] = "HIGH"
        f["module"] = "solidity"
        f["title"] = "Integer Overflow (SOL-004)"
        print(f"    L{f['line']}: {f['snippet']}")
        all_findings.append(f)

# ─────────────────────────────────────────────────────────────────────────────
# 2. SmartPatchValidator réel -> verdict / scope / guarded
# ─────────────────────────────────────────────────────────────────────────────
banner("2. Verdict du SmartPatchValidator (propagation verdict/scope/guarded)")

validator = SmartPatchValidator()
validated_patches = []
source_by_name = {name: src for name, src, _ in FIXTURES}
for f in all_findings:
    vp = validator.generate_and_verify_patch(f, source_by_name[f["file"]])
    if vp:
        validated_patches.append(asdict(vp))

hdr = f"{'patch_id':34s} {'verdict':9s} {'guarded':7s} {'smt':5s}  scope"
print(hdr)
print("-" * len(hdr))
for pt in validated_patches:
    print(
        f"{pt['patch_id']:34s} {pt['verdict']:9s} {str(pt['guarded']):7s} "
        f"{str(pt['is_smt_verified']):5s}  {pt['scope'] or '(aucun)'}"
    )

verdicts = {pt["verdict"] for pt in validated_patches}
print(f"\nVerdicts distincts produits : {sorted(verdicts)}")

# ─────────────────────────────────────────────────────────────────────────────
# 3. Rapport HTML réel
# ─────────────────────────────────────────────────────────────────────────────
banner("3. Génération du rapport HTML réel")

intelligence_data = {"validated_patches": validated_patches}
html_out = HTMLReportGenerator().generate(
    project_name="R3 Visibility Proof",
    target_path=ROOT,
    findings=all_findings,
    intelligence_data=intelligence_data,
)

out_path = os.path.join(tempfile.gettempdir(), "adversum_R3_scope_visibility.html")
with open(out_path, "w", encoding="utf-8") as fh:
    fh.write(html_out)
print(f"Rapport écrit : {out_path}  ({len(html_out)} octets)")

# ─────────────────────────────────────────────────────────────────────────────
# 4. Vérifications littérales : scope + statut UNSAT/guarded visibles
# ─────────────────────────────────────────────────────────────────────────────
banner("4. Vérifications de visibilité dans le HTML")

checks = [
    ("Badge SAT (cas exploitable)",
     "Z3 SAT — débordement représentable (exploitable)"),
    ("Badge UNSAT guarded (contrat protégé)",
     "Z3 UNSAT — protégé : garde (SafeMath / pragma ≥0.8) vérifiée"),
    ("Badge protégé (garde détectée, preuve non concluante)",
     "Protégé — garde modélisée (SafeMath / pragma ≥0.8)"),
    ("Champ scope affiché (portée honnête)",
     "Portée de la preuve : overflow representable for this operation (not reachability-proven)"),
    ("Récapitulatif : compteur UNSAT/protégé",
     "Z3 UNSAT — protégé / non représentable"),
]

failures = 0
for label, needle in checks:
    ok = needle in html_out
    failures += 0 if ok else 1
    print(f"  [{'OK ' if ok else 'MANQUE'}] {label}")
    if not ok:
        print(f"        chaîne recherchée : {needle!r}")

# Le cas SAT ne doit PAS porter le libellé « protégé », et inversement :
# on vérifie que les deux libellés coexistent (donc sont bien distingués).
sat_present = "Z3 SAT — débordement représentable" in html_out
protected_present = "protégé : garde (SafeMath / pragma ≥0.8) vérifiée" in html_out
distinguished = sat_present and protected_present
print(f"\n  [{'OK ' if distinguished else 'MANQUE'}] SAT et PROTÉGÉ coexistent et sont distingués dans la même page")

banner("RÉSULTAT R3")
if failures == 0 and distinguished:
    print("PASS — le champ scope et le statut UNSAT/guarded sont visibles ET")
    print("       distingués du cas SAT/exploitable dans le rapport HTML.")
else:
    print(f"ÉCHEC — {failures} vérification(s) en échec.")

sys.exit(1 if (failures or not distinguished) else 0)
