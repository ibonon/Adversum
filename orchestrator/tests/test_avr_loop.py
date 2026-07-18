"""
Tests pour le moteur AVR (Autonomous Verified Remediation).
Ces tests fonctionnent avec mocks complets (sans DB, sans Rust natif requis).
"""
import pytest
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock, AsyncMock

# ─── Mock des dépendances lourdes avant tout import ───────────────────────────
import sys
for mod in ["sqlmodel", "sqlalchemy", "sqlalchemy.ext.asyncio", "redis", "arq", "asyncpg"]:
    sys.modules.setdefault(mod, MagicMock())

from orchestrator.services.avr import AVREngine  # noqa: E402
from orchestrator.models.findings import RawFinding  # noqa: E402


def _make_finding(path: str, line: int) -> RawFinding:
    return RawFinding(
        file_path=path,
        line=line,
        snippet="eval(user_input)",
        id="RUST_CORE_001_DANGEROUS_EVAL",
        severity="CRITICAL",
        message="Dangerous eval() detected",
        flow_path=["fallback"],
        proof=None,
        immune_context=None,
        proof_anchor=None,
    )


@pytest.fixture
def tmp_vulnerable_file():
    """Crée un fichier temporaire avec un eval vulnérable."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, "vulnerable.py")
    with open(path, "w") as f:
        f.write("def run(user_input):\n    result = eval(user_input)\n    return result\n")
    yield path
    shutil.rmtree(d, ignore_errors=True)


@pytest.mark.asyncio
@patch("orchestrator.core_bridge.core_wrapper.CoreWrapper.analyze")
@patch("orchestrator.services.patcher.PatchService.apply_fix", return_value=True)
async def test_avr_valid_fix_accepted(mock_patch, mock_analyze, tmp_vulnerable_file):
    """Un fix valide (qui élimine le finding) doit être accepté par l'AVR."""
    # Après application du patch, le scan retourne 0 findings
    mock_analyze.return_value = ([], {}, 1.0)

    avr = AVREngine()
    success = await avr.run_remediation(
        finding_id=1,
        file_path=tmp_vulnerable_file,
        line_number=2,
        old_snippet="result = eval(user_input)",
        fix_code="result = int(user_input)  # Safe conversion",
    )
    assert success is True, "L'AVR doit accepter un fix qui élimine le finding"


@pytest.mark.asyncio
@patch("orchestrator.core_bridge.core_wrapper.CoreWrapper.analyze")
@patch("orchestrator.services.patcher.PatchService.apply_fix", return_value=True)
async def test_avr_invalid_fix_rejected(mock_patch, mock_analyze, tmp_vulnerable_file):
    """Un fix invalide (qui ne corrige pas la vulnérabilité) doit être rejeté."""
    # Après application du patch, le scan retourne encore le même finding
    mock_analyze.return_value = (
        [_make_finding(tmp_vulnerable_file, 2)],
        {},
        0.4,
    )

    avr = AVREngine()
    # Désactiver le mode speculatif pour éviter les appels AI
    success = await avr.run_remediation(
        finding_id=2,
        file_path=tmp_vulnerable_file,
        line_number=2,
        old_snippet="result = eval(user_input)",
        fix_code="result = eval(user_input)  # Still dangerous!",
        speculative=False,
    )
    assert success is False, "L'AVR doit rejeter un fix qui laisse la vulnérabilité"


@pytest.mark.asyncio
@patch("orchestrator.core_bridge.core_wrapper.CoreWrapper.analyze")
@patch("orchestrator.services.patcher.PatchService.apply_fix", return_value=False)
async def test_avr_patch_failure(mock_patch, mock_analyze, tmp_vulnerable_file):
    """Si l'application du patch échoue, l'AVR doit retourner False."""
    avr = AVREngine()
    success = await avr.run_remediation(
        finding_id=3,
        file_path=tmp_vulnerable_file,
        line_number=2,
        old_snippet="result = eval(user_input)",
        fix_code="result = safe_eval(user_input)",
    )
    assert success is False
    mock_analyze.assert_not_called()
