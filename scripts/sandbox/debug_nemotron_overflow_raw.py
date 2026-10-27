"""Diagnostic N2 : affiche la réponse BRUTE de Nemotron pour overflow.sol
afin de comprendre l'échec de parsing JSON (sans masquer l'erreur)."""
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

from orchestrator.services import nebius_llm as nb

SRC = (ROOT / "modules" / "solidity" / "tests" / "test_contracts" / "overflow.sol").read_text(encoding="utf-8")
SEP = "=" * 78


async def main():
    client = nb._get_client()
    resp = await client.chat.completions.create(
        model=nb.get_active_model(),
        messages=[
            {"role": "system", "content": nb._OVERFLOW_SYSTEM_PROMPT},
            {"role": "user", "content": nb._OVERFLOW_PROMPT.format(file_path="overflow.sol", source=SRC)},
        ],
        temperature=0.0,
        max_tokens=8000,
    )
    msg = resp.choices[0].message
    content = msg.content or ""
    reasoning = getattr(msg, "reasoning_content", "") or ""
    print(SEP)
    print(f"champs du message : {list(msg.model_dump().keys())}")
    print(f"content   : {len(content)} caractères")
    print(f"reasoning : {len(reasoning)} caractères")
    print(f"finish_reason : {resp.choices[0].finish_reason}")
    print(f"usage : {resp.usage}")
    print(SEP)
    print("RAW CONTENT (3000 premiers caractères) :")
    print(content[:3000])
    print(SEP)
    print("RAW REASONING (600 derniers caractères) :")
    print(reasoning[-600:])
    print(SEP)
    try:
        print("extract_json(content)  ->", nb._extract_json(content))
    except Exception as e:
        print("extract_json(content)  -> ÉCHEC:", e)
    try:
        print("extract_json(reasoning)->", str(nb._extract_json(reasoning))[:300])
    except Exception as e:
        print("extract_json(reasoning)-> ÉCHEC:", e)


asyncio.run(main())
