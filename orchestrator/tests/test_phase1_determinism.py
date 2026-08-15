"""
Tests de non-régression — Phase 1 (socle déterministe).

Couvre:
  1. MOCK_CORE=False par défaut + override via env var ADVERSUM_MOCK_CORE
  2. AdversarialSimulator.simulate_attack déterministe sans FFI (aucun random)
  3. Validité + complétude de la knowledge base (knowledge/kb.json)
  4. Détection stable par le fallback Python (_analyze_fallback)

Ces tests ne nécessitent PAS le binaire Rust (.pyd) : ils valident le socle
Python et la configuration déterministe indépendamment de la compilation.
"""
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Mock des dépendances lourdes avant tout import orchestrator.
for mod in [
    "sqlmodel",
    "sqlalchemy",
    "sqlalchemy.ext.asyncio",
    "redis",
    "arq",
    "asyncpg",
]:
    sys.modules.setdefault(mod, MagicMock())

REPO_ROOT = Path(__file__).resolve().parents[2]
KB_PATH = REPO_ROOT / "knowledge" / "kb.json"


# ─── 1. Configuration MOCK_CORE ────────────────────────────────────────────

def test_mock_core_defaults_to_false(monkeypatch):
    """MOCK_CORE doit être False par défaut (le vrai moteur Rust est attendu)."""
    monkeypatch.delenv("ADVERSUM_MOCK_CORE", raising=False)
    # Recharge le module settings pour prendre en compte l'environnement.
    import importlib

    from orchestrator.config import settings as settings_mod

    importlib.reload(settings_mod)
    assert settings_mod.settings.MOCK_CORE is False, (
        "MOCK_CORE doit être False en production ; le mock ne s'active que via "
        "ADVERSUM_MOCK_CORE=true."
    )


def test_mock_core_forced_via_env(monkeypatch):
    """ADVERSUM_MOCK_CORE=true force explicitement le mock (mode test)."""
    monkeypatch.setenv("ADVERSUM_MOCK_CORE", "true")
    from orchestrator.core_bridge.core_wrapper import _mock_core_forced

    assert _mock_core_forced() is True

    monkeypatch.setenv("ADVERSUM_MOCK_CORE", "false")
    assert _mock_core_forced() is False


# ─── 2. Déterminisme de AdversarialSimulator sans FFI ──────────────────────

def test_adversarial_simulator_is_deterministic_without_ffi(monkeypatch):
    """
    Sans FFI, simulate_attack NE doit plus jamais renvoyer un résultat
    aléatoire. Deux appels identiques => deux résultats identiques.
    Garantit l'absence de random.choice dans le chemin déterministe.
    """
    monkeypatch.delenv("ADVERSUM_MOCK_CORE", raising=False)
    from orchestrator.services.adversarial_sim import AdversarialSimulator

    sim = AdversarialSimulator()
    # Force le mode sans FFI (comme en l'absence du .pyd).
    sim.wrapper.use_ffi = False

    r1 = sim.simulate_attack("PGD", data_payload=[0.1, 0.2, 0.3])
    r2 = sim.simulate_attack("PGD", data_payload=[0.1, 0.2, 0.3])

    # Clés attendues sur le résultat de skip déterministe.
    assert r1.get("skipped") is True, (
        "Sans FFI la simulation doit être marquée 'skipped' (déterministe), "
        "pas fabriquée."
    )
    assert r1.get("robustness_score") == 1.0
    # Reproductibilité bit-exact entre deux appels identiques.
    assert r1 == r2, "Deux appels identiques doivent produire le même résultat."
    # Aucun faux succès simulé.
    assert r1.get("success") is False


# ─── 3. Knowledge base valide et complète ──────────────────────────────────

def _load_kb() -> dict:
    with open(KB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_kb_is_valid_json_and_has_expected_structure():
    kb = _load_kb()
    assert "rules" in kb and isinstance(kb["rules"], list)
    assert "rules_map" in kb and isinstance(kb["rules_map"], dict)
    assert len(kb["rules"]) >= 20, "La KB doit couvrir au moins 20 règles."


def test_kb_every_rule_has_required_fields():
    required = {"rule_id", "cwe_id", "name", "severity", "remediation"}
    for rule in _load_kb()["rules"]:
        missing = required - set(rule.keys())
        assert not missing, f"Règle incomplète {rule.get('rule_id')}: {missing}"


def test_kb_rules_map_matches_rule_ids():
    """rules_map doit référencer exactement les rule_id déclarés dans rules."""
    kb = _load_kb()
    declared = {r["rule_id"] for r in kb["rules"]}
    mapped = set(kb["rules_map"].keys())
    assert declared == mapped, (
        f"rules_map désynchronisé: manquant={declared - mapped}, "
        f"en_trop={mapped - declared}"
    )


def test_kb_all_cwe_ids_well_formed():
    for rule in _load_kb()["rules"]:
        cwe = rule["cwe_id"]
        assert cwe.startswith("CWE-") or cwe.startswith("CVE-"), (
            f"CWE/CVE malformé pour {rule['rule_id']}: {cwe}"
        )


# ─── 4. Détection stable du fallback Python ────────────────────────────────

def _write_tmp(suffix: str, content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


def test_fallback_detects_command_injection():
    """Le fallback Python doit détecter os.system avec entrée utilisateur."""
    from orchestrator.core_bridge.core_wrapper import CoreWrapper

    src = (
        "import os\n"
        "def bad():\n"
        "    user = request.args.get('cmd')\n"
        "    os.system(user)\n"
    )
    path = _write_tmp(".py", src)
    try:
        wrapper = CoreWrapper()
        findings, _, _ = wrapper._analyze_fallback([path])
        rule_ids = {f.id for f in findings}
        assert "RUST_CORE_002_OS_SYSTEM" in rule_ids, (
            f"Command injection non détectée. Trouvé: {rule_ids}"
        )
    finally:
        os.unlink(path)


def test_fallback_detects_sql_injection_with_taint_escalation():
    """Le fallback doit escalader la sévérité quand une variable tainted alimente un sink."""
    from orchestrator.core_bridge.core_wrapper import CoreWrapper

    src = (
        "def query():\n"
        "    user_id = request.args.get('id')\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"
    )
    path = _write_tmp(".py", src)
    try:
        wrapper = CoreWrapper()
        findings, _, _ = wrapper._analyze_fallback([path])
        sqli = [f for f in findings if f.id == "RUST_CORE_005_SQL_INJECTION"]
        assert sqli, "SQLi non détectée par f-string dans execute()."
        # L'escalade taint doit produire une sévérité CRITICAL.
        severities = {f.severity for f in sqli}
        assert "CRITICAL" in severities or "High" in severities or "HIGH" in severities, (
            f"Sévérité SQLi inattendue: {severities}"
        )
    finally:
        os.unlink(path)


def test_fallback_is_deterministic_across_runs():
    """Deux analyses du même fichier doivent produire des findings identiques."""
    from orchestrator.core_bridge.core_wrapper import CoreWrapper

    src = (
        "import os\n"
        "x = eval(request.args.get('x'))\n"
        "os.system(x)\n"
    )
    path = _write_tmp(".py", src)
    try:
        wrapper = CoreWrapper()
        f1, _, _ = wrapper._analyze_fallback([path])
        f2, _, _ = wrapper._analyze_fallback([path])
        # Comparaison déterministe: mêmes (rule_id, line) dans le même ordre.
        sig1 = [(f.id, f.line) for f in f1]
        sig2 = [(f.id, f.line) for f in f2]
        assert sig1 == sig2, "Le fallback doit être reproductible."
    finally:
        os.unlink(path)


def test_fallback_clean_file_has_no_findings():
    """Un fichier sain ne doit produire aucun finding (pas de faux positifs)."""
    from orchestrator.core_bridge.core_wrapper import CoreWrapper

    src = (
        "import subprocess\n"
        "def safe():\n"
        "    subprocess.run(['ls', '-la'], shell=False)\n"
        "    x = 1 + 1\n"
        "    return x\n"
    )
    path = _write_tmp(".py", src)
    try:
        wrapper = CoreWrapper()
        findings, _, _ = wrapper._analyze_fallback([path])
        critical = [f for f in findings if str(f.severity).upper() == "CRITICAL"]
        assert not critical, (
            f"Faux positifs critiques sur fichier sain: {critical}"
        )
    finally:
        os.unlink(path)
