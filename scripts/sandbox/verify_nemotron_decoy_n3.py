"""ÉTAPE N3 (point 3) — Cas d'HALLUCINATION DE SUBSTANCE.

Fixture leurre : ``decoy_overflow.sol`` — commentaires et noms de variables
trompeurs ("overflow", "totalSupplyBackup") mais AUCUNE opération
arithmétique réelle. On fait tourner Nemotron RÉELLEMENT dessus (appel NIM,
aucun mock) puis :

  1. on montre les hypothèses brutes retournées ;
  2. on les passe dans ``anchor_hypotheses()`` ;
  3. pour chaque hypothèse :
       - ``ANCRAGE_ECHOUE``            → jamais soumise à Z3 (attendu si le
                                          leurre ne contient aucune op) ;
       - ``ANCRAGE_OK``                → on appelle ``prove_overflow()`` et on
                                          montre le verdict réellement obtenu
                                          (UNSAT ou UNPARSED = le leurre est
                                          démasqué ; SAT = le leurre a réussi
                                          à faire produire un faux positif, à
                                          documenter honnêtement).

Contrat d'erreur : une exception ``NebiusOverflowGenerationError`` signale un
échec RÉEL de l'API ; on l'affiche et on sort en code non-zéro, sans jamais
substituer un résultat fabriqué.
"""
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

from orchestrator.services import nebius_llm as nb
from modules.solidity.overflow_anchor import anchor_hypotheses
from modules.solidity.rules import arithmetic
from modules.formal_verification import z3_prover as z3p

SEP = "=" * 78

DECOY_PATH = (
    ROOT / "modules" / "solidity" / "tests" / "test_contracts" / "decoy_overflow.sol"
)
DECOY_SOL = DECOY_PATH.read_text(encoding="utf-8")

# Hypothèses INJECTÉES (pas produites par Nemotron) : elles reproduisent ce qu'un
# modèle qui mordrait au leurre proposerait — typiquement en pointant l'opération
# vulnérable qui n'existe que dans un COMMENTAIRE de decoy_overflow.sol, ou une
# variable trompeuse jamais utilisée en arithmétique.
INJECTED_HALLUCINATIONS = [
    # cible la ligne 23 (commentaire : "totalSupply = totalSupply + amount;")
    {"line": 23, "variable": "totalSupply", "operation": "+",
     "protection_apparente": "aucune", "guard_detail": "[injecté] addition lue dans un commentaire"},
    # cible la ligne 24 (commentaire : "uint256 overflowed = totalSupplyBackup * 2;")
    {"line": 24, "variable": "totalSupplyBackup", "operation": "*",
     "protection_apparente": "aucune", "guard_detail": "[injecté] multiplication lue dans un commentaire"},
    # variable totalement inexistante (hallucination de nom)
    {"line": 1, "variable": "ghostBalance", "operation": "+",
     "protection_apparente": "aucune", "guard_detail": "[injecté] variable inexistante"},
]


def infer_bit_width(finding: dict, content: str) -> int:
    """Largeur déduite du contexte ; 256 si non déterminable."""
    parsed = z3p._parse_arithmetic(finding.get("snippet", ""))
    if not parsed:
        return 256
    _, left, right = parsed
    width = z3p._infer_bit_width(content, left)
    if width == 256:
        width = z3p._infer_bit_width(content, right)
    return width


async def main() -> int:
    print(SEP)
    print("N3 / point 3 — HALLUCINATION DE SUBSTANCE (fixture leurre)")
    print(SEP)
    print(f"fixture : {DECOY_PATH}")
    print(f"_is_demo_mode() : {nb._is_demo_mode()}")
    print(f"_is_available() : {nb._is_available()}")
    if nb._is_demo_mode() or not nb._is_available():
        print("\nARRÊT : appel réel indisponible — aucun mock ne sera produit.")
        return 2

    print()
    print("--- Référence regex SOL-004 sur le leurre (attendu : [] ) ---")
    regex_hits = arithmetic.analyze(DECOY_SOL)
    print(f"[regex SOL-004] {len(regex_hits)} finding(s) : "
          f"{[f['line'] for f in regex_hits]}")

    print()
    print("--- Appel Nemotron RÉEL sur le leurre ---")
    try:
        hypotheses = await nb.generate_overflow_hypotheses(
            DECOY_SOL, file_path=DECOY_PATH.name
        )
    except nb.NebiusOverflowGenerationError as e:
        print(f"[Nemotron] ÉCHEC RÉEL (aucune hypothèse produite) : {e}")
        return 3

    print(f"[Nemotron] {len(hypotheses)} hypothèse(s) retournée(s).")
    print("\n[Nemotron] JSON brut normalisé :")
    print(json.dumps(hypotheses, indent=2, ensure_ascii=False))

    if not hypotheses:
        print()
        print(SEP)
        print("RÉSULTAT RÉEL : Nemotron n'a proposé AUCUNE hypothèse sur le leurre.")
        print("→ aucun faux positif produit par le modèle sur cette fixture.")
        print("=" * 78)
        print("Le branchement conditionnel de la consigne (« SI Nemotron propose une")
        print("hypothèse ») n'est donc PAS déclenché par le modèle réel. Pour prouver")
        print("que le démasquage FONCTIONNE quand une hypothèse hallucinée existe, la")
        print("section ci-dessous injecte MANUELLEMENT des hypothèses typiques d'un")
        print("modèle qui mordrait au piège (ciblant les lignes de commentaire). Ces")
        print("hypothèses sont INJECTÉES, pas produites par Nemotron, et servent")
        print("uniquement à exercer anchor_hypotheses() + prove_overflow() :")
        print(SEP)
        hypotheses = INJECTED_HALLUCINATIONS

    print()
    print("--- Ancrage des hypothèses + verdict Z3 réel ---")
    anchored = anchor_hypotheses(hypotheses, DECOY_SOL)
    n_fake_confirmed = 0
    for a in anchored:
        print()
        print(f"hypothèse : variable={a.get('variable')!r} op={a.get('operation')!r} "
              f"nemotron_line={a.get('nemotron_line')}")
        print(f"  anchor_status = {a['anchor_status']} — {a.get('anchor_reason')}")
        if a["anchor_status"] != "ANCRAGE_OK":
            print("  → NON soumise à Z3 (hypothèse non vérifiable : ancrage impossible).")
            continue

        finding = a["z3_finding"]
        width = infer_bit_width(finding, DECOY_SOL)
        auto_guarded = z3p._detect_guard(DECOY_SOL)
        res = z3p.prove_overflow(
            finding,
            bit_width=width,
            bounds=z3p._extract_bounds(DECOY_SOL),
            guarded=auto_guarded,
        )
        print(f"  snippet soumis : {finding['snippet']!r} (largeur {width}, guarded={auto_guarded})")
        print(f"  verdict Z3 = {res['verdict']}  exploitable={res['exploitable']}  "
              f"smt_verified={res['smt_verified']}")
        print(f"  proof : {res['proof']}")
        if res["verdict"] == "SAT" and res["exploitable"]:
            n_fake_confirmed += 1
            print("  ⚠ FAUX POSITIF CONFIRMÉ par Z3 (le leurre a réussi).")

    print()
    print(SEP)
    print(f"FIN — faux positifs confirmés par Z3 : {n_fake_confirmed}")
    print("(0 = le leurre n'a pas produit de finding bespoke ; démasqué par ancrage et/ou Z3.)")
    print(SEP)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
