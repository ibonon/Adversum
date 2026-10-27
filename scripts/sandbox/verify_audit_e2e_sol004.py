"""ÉTAPE N4 (point 4) — Scan de bout en bout RÉEL via POST /audit.

Cible : la fixture overflow.sol (copiée dans un dossier temporaire autorisé).
Affiche le JSON final renvoyé par l'API, en mettant en évidence, pour chaque
finding SOL-004 : la provenance (nemotron vs regex_fallback) et le verdict Z3.

Aucune simulation : l'API et l'appel Nemotron sont réels (l'API tourne déjà).
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

API_URL = os.environ.get("API_URL", "http://127.0.0.1:8123")
API_KEY = os.environ.get("API_KEY", "adv-dev-key-123")
TARGET = os.environ.get(
    "TARGET",
    os.path.join(os.environ.get("TEMP", "/tmp"), "adversum_sol_e2e"),
)
SEP = "=" * 78


def _req(method, endpoint, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(f"{API_URL}{endpoint}", method=method, data=data)
    req.add_header("X-API-Key", API_KEY)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    print(SEP)
    print("N4 / point 4 — SCAN BOUT-EN-BOUT RÉEL VIA POST /audit")
    print(SEP)
    print(f"API    : {API_URL}")
    print(f"TARGET : {TARGET}")

    try:
        jobs = _req("GET", "/audits")
    except urllib.error.URLError as e:
        print(f"ARRÊT : API injoignable ({e}).")
        return 2
    print(f"jobs existants : {len(jobs)}")

    resp = _req("POST", "/audit", {"target_path": TARGET, "project_name": "sol004_e2e"})
    job_id = resp["id"]
    print(f"\nPOST /audit -> job {job_id}, status={resp['status']}")
    print("Attente de la fin du job (Nemotron réel peut prendre ~1-3 min)...")

    data = None
    for _ in range(180):
        time.sleep(3)
        data = _req("GET", f"/audit/{job_id}")
        print(f"  status = {data['status']}")
        if data["status"] in ("COMPLETED", "FAILED"):
            break

    print()
    print(SEP)
    print("JSON FINAL (GET /audit/%s)" % job_id)
    print(SEP)
    print(json.dumps(data, indent=2, ensure_ascii=False))

    print()
    print(SEP)
    print("SYNTHÈSE SOL-004 — provenance + verdict Z3 par finding")
    print(SEP)
    sol = [
        f for f in data.get("result", [])
        if f.get("raw", {}).get("rule_id") == "SOL-004"
    ]
    if not sol:
        print("Aucun finding SOL-004 dans le résultat.")
        return 0

    for f in sol:
        raw = f["raw"]
        print(f"\n- {raw['rule_id']}  {raw['file_path']}:{raw['line_number']}")
        print(f"  snippet        : {raw.get('snippet')!r}")
        print(f"  validation     : {f.get('validation_status')}  (confidence={f.get('ai_confidence')})")
        print("  --- champs structurés (hors reasoning_notes) ---")
        for key in ("provenance", "z3_verdict", "anchor_status",
                    "nemotron_line", "resolved_line", "proof_anchor"):
            value = f.get(key)
            flag = "" if value is not None else "   <-- NULL/ABSENT"
            print(f"  {key:<14} = {value!r}{flag}")
        print(f"  reasoning_notes: {f.get('reasoning_notes')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
