"""
Tests pour le pipeline d'analyse avec mocks complets.
Ces tests fonctionnent sans base de données et sans le binaire Rust.
"""
import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock, AsyncMock

# ─── Mock des dépendances lourdes avant tout import ───────────────────────────
import sys
for mod in ["sqlmodel", "sqlalchemy", "sqlalchemy.ext.asyncio", "redis", "arq", "asyncpg"]:
    sys.modules.setdefault(mod, MagicMock())

from orchestrator.pipeline.analysis_pipeline import AnalysisPipeline  # noqa: E402
from orchestrator.models.findings import RawFinding  # noqa: E402


def _make_raw_finding(path: str, line: int = 5, rule_id: str = "RULE_001") -> RawFinding:
    return RawFinding(
        file_path=path,
        line=line,
        snippet="eval(user_input)",
        id=rule_id,
        severity="CRITICAL",
        message="Dangerous eval() detected",
        flow_path=["Python Fallback Analyzer"],
        proof=None,
        immune_context=None,
        proof_anchor=None,
    )


@pytest.mark.asyncio
@patch("orchestrator.core_bridge.core_wrapper.CoreWrapper.analyze")
@patch("orchestrator.pipeline.analysis_pipeline.AnalysisPipeline._validate_with_ai", new_callable=AsyncMock)
async def test_pipeline_detects_eval(mock_validate, mock_analyze):
    """Le pipeline doit détecter un eval() dans un fichier vulnérable."""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write("x = eval(user_input)\n")
        tmp_path = f.name

    try:
        mock_raw = _make_raw_finding(tmp_path)
        mock_analyze.return_value = ([mock_raw], {tmp_path: "abc123"}, 0.6)
        mock_validate.return_value = [MagicMock(raw=mock_raw, validation_status="CONFIRMED")]

        pipeline = AnalysisPipeline()
        result = await pipeline.run(tmp_path)

        findings = result.get("findings", [])
        assert len(findings) >= 1, "Le pipeline doit détecter au moins 1 finding"
    finally:
        os.unlink(tmp_path)


@pytest.mark.asyncio
@patch("orchestrator.core_bridge.core_wrapper.CoreWrapper.analyze")
@patch("orchestrator.pipeline.analysis_pipeline.AnalysisPipeline._validate_with_ai", new_callable=AsyncMock)
async def test_pipeline_clean_file(mock_validate, mock_analyze):
    """Le pipeline doit retourner 0 finding sur un fichier sain."""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write("x = 1 + 1\nprint(x)\n")
        tmp_path = f.name

    try:
        mock_analyze.return_value = ([], {tmp_path: "def456"}, 1.0)
        mock_validate.return_value = []

        pipeline = AnalysisPipeline()
        result = await pipeline.run(tmp_path)

        findings = result.get("findings", [])
        assert len(findings) == 0, "Aucun finding attendu sur un fichier sain"
    finally:
        os.unlink(tmp_path)
