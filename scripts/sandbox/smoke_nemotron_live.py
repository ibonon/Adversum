"""Smoke test AVANT N2 : confirme que l'appel RÉEL NVIDIA NIM fonctionne.

Aucun mock. Aucun contournement : utilise exactement `_get_client()`,
`_is_demo_mode()`, `_is_available()` et `get_active_model()` du module
`orchestrator.services.nebius_llm`.
"""
import asyncio
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

from orchestrator.services import nebius_llm as nb

SEP = "=" * 78


async def main() -> int:
    print(SEP)
    print("SMOKE TEST — appel RÉEL NVIDIA NIM")
    print(SEP)
    print("_is_demo_mode() :", nb._is_demo_mode())
    print("_is_available() :", nb._is_available())
    print("model           :", nb.get_active_model())
    print("base_url        :", nb.get_active_base_url())

    if nb._is_demo_mode():
        print("\nARRÊT : _is_demo_mode() == True — refus de basculer sur un mock.")
        return 2
    if not nb._is_available():
        print("\nARRÊT : _is_available() == False — aucun appel réel possible.")
        return 3

    client = nb._get_client()
    t0 = time.time()
    try:
        resp = await client.chat.completions.create(
            model=nb.get_active_model(),
            messages=[
                {"role": "system", "content": "You reply with strict JSON only."},
                {"role": "user", "content": 'Reply exactly: {"pong": true, "engine": "nemotron"}'},
            ],
            temperature=0.0,
            max_tokens=64,
        )
    except Exception as exc:
        print(f"\nÉCHEC DE L'APPEL RÉEL : {type(exc).__name__}: {exc}")
        print("ARRÊT — je ne bascule PAS sur un mock. À signaler.")
        return 4

    dt = time.time() - t0
    msg = resp.choices[0].message
    raw = (msg.content or getattr(msg, "reasoning_content", "") or "").strip()
    print(f"\nHTTP OK en {dt:.2f}s")
    print("réponse brute (200 chars) :", raw[:200])
    print("json extrait             :", nb._extract_json(raw))

    print()
    print(SEP)
    print("APPEL RÉEL CONFIRMÉ — N2 peut procéder.")
    print(SEP)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
