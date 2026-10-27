"""ÉTAPE RE2 — Nemotron génère des hypothèses de REENTRANCY (SOL-001) sur code brut.

Appel RÉEL NVIDIA NIM uniquement (garde-fou explicite : aucun mock).
Compare, ligne par ligne, ce que Nemotron rapporte et ce qu'un lecteur humain
verrait réellement dans les deux fixtures :
  - reentrancy_vulnerable.sol : modification d'état APRÈS l'appel externe (DAO).
  - reentrancy_protected.sol  : modification d'état AVANT l'appel + nonReentrant.

Contrat d'erreur distingué (nebius_llm.generate_reentrancy_hypotheses) :
  - `[]`                                  → appel réussi, modèle sans hypothèse.
  - `NebiusReentrancyGenerationError`      → échec réel (API/timeout/JSON) :
                                            signalé, JAMAIS déguisé en `[]`.
"""
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

from orchestrator.services import nebius_llm as nb

SEP = "=" * 78
CONTRACTS = ROOT / "modules" / "solidity" / "tests" / "test_contracts"

# Vérité terrain établie par lecture humaine du source (numéros de ligne réels).
GROUND_TRUTH = {
    "reentrancy_vulnerable.sol": {
        "function": "withdraw",
        "external_call_line": 13,   # (bool success, ) = msg.sender.call{value: amount}("");
        "state_update_line": 15,    # balances[msg.sender] = 0;
        "order": "call_before_update",
        "guard_present": "none",
    },
    "reentrancy_protected.sol": {
        "function": "withdraw",
        "external_call_line": 23,   # (bool success, ) = msg.sender.call{value: amount}("");
        "state_update_line": 22,    # balances[msg.sender] = 0;
        "order": "update_before_call",
        "guard_present": "nonReentrant",
    },
}

FIXTURES = [
    ("reentrancy_vulnerable.sol", "vulnérable (effets APRÈS appel externe)"),
    ("reentrancy_protected.sol", "protégée (effets AVANT appel + nonReentrant)"),
]


def _truth_lines(src: str) -> list:
    """Vérifie la vérité terrain en relisant le fichier réel (numéroté)."""
    out = {}
    for i, line in enumerate(src.split("\n"), start=1):
        if ".call{" in line or ".transfer(" in line or ".send(" in line:
            out.setdefault("call", []).append((i, line.strip()))
        if "balances[msg.sender] = 0" in line:
            out.setdefault("update", []).append((i, line.strip()))
    return out


async def main() -> int:
    print(SEP)
    print("RE2 — GARDE-FOU D'EXÉCUTION")
    print(SEP)
    print("_is_demo_mode() :", nb._is_demo_mode())
    print("_is_available() :", nb._is_available())
    if nb._is_demo_mode() or not nb._is_available():
        print("\nARRÊT : appel réel indisponible — aucun mock ne sera produit.")
        return 2

    report = {}
    failures = []
    for name, desc in FIXTURES:
        src = (CONTRACTS / name).read_text(encoding="utf-8")
        print()
        print(SEP)
        print(f"FICHIER : {name}  —  {desc}")
        print(SEP)

        truth = _truth_lines(src)
        print(f"[humain] lignes appel externe  : {truth.get('call', [])}")
        print(f"[humain] lignes mise à jour    : {truth.get('update', [])}")
        print(f"[humain] vérité terrain        : {GROUND_TRUTH[name]}")

        try:
            hypotheses = await nb.generate_reentrancy_hypotheses(src, file_path=name)
        except nb.NebiusReentrancyGenerationError as e:
            print(f"[Nemotron] ÉCHEC RÉEL (aucune hypothèse produite) : {e}")
            failures.append(name)
            report[name] = {"error": str(e), "status": "NebiusReentrancyGenerationError"}
            continue

        print(f"\n[Nemotron] {len(hypotheses)} hypothèse(s) — JSON brut normalisé :")
        print(json.dumps(hypotheses, indent=2, ensure_ascii=False))

        # Écarts par hypothèse
        gaps = []
        for h in hypotheses:
            gt = GROUND_TRUTH[name]
            gap = {
                "call_line_nemotron": h["external_call_line"],
                "call_line_real": gt["external_call_line"],
                "update_line_nemotron": h["state_update_line"],
                "update_line_real": gt["state_update_line"],
                "order_nemotron": h["order"],
                "order_real": gt["order"],
                "guard_nemotron": h["guard_present"],
                "guard_real": gt["guard_present"],
            }
            gap["call_line_ok"] = h["external_call_line"] == gt["external_call_line"]
            gap["update_line_ok"] = h["state_update_line"] == gt["state_update_line"]
            gap["order_ok"] = h["order"] == gt["order"]
            gap["guard_ok"] = h["guard_present"] == gt["guard_present"]
            gaps.append(gap)

        print("\n[ÉCART Nemotron vs humain]")
        print(json.dumps(gaps, indent=2, ensure_ascii=False))

        report[name] = {
            "status": "ok",
            "human_truth": GROUND_TRUTH[name],
            "nemotron_hypotheses": hypotheses,
            "gaps": gaps,
        }

    out = Path(os.environ.get("TEMP", "/tmp")) / "nemotron_reentrancy_re2.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print()
    print(SEP)
    print(f"Rapport JSON écrit : {out}")
    if failures:
        print(f"ÉCHECS RÉELS (appel Nemotron) : {failures} — aucune valeur simulée affichée.")
        print(SEP)
        return 3
    print(SEP)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
