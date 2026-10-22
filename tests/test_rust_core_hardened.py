"""
Tests for Hardened Rust Core (adversum_core) integration.
Verifies memory-safety on empty files, Web3/Solidity deterministic validation,
sanitizer detection, and Tier-0 pre-filtering.
"""
import os
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import adversum_core
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False

pytestmark = pytest.mark.skipif(not RUST_AVAILABLE, reason="adversum_core native extension required")


class TestRustCoreHardened:
    def test_empty_file_handling_does_not_panic(self, tmp_path):
        """Rust Mmap must safely handle 0-byte empty files without panicking."""
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("")
        assert empty_file.stat().st_size == 0

        # Compute hash
        hashes = adversum_core.compute_hashes([str(empty_file)])
        assert str(empty_file) in hashes
        assert len(hashes[str(empty_file)]) == 16  # XXH3 64-bit hex length

        # Inspect files
        res = adversum_core.inspect_files([str(empty_file)])
        assert len(res.findings) == 0
        assert str(empty_file) in res.file_hashes

    def test_deterministic_validator_web3_tx_origin(self):
        """Validator must confirm tx.origin violation and suggest msg.sender."""
        finding = adversum_core.Finding(
            id="HEU-003",
            message="tx.origin authorization",
            severity="HIGH",
            line=12,
            snippet="require(tx.origin == owner, 'Unauthorized');",
        )
        validated = adversum_core.validate_findings([finding])
        assert len(validated) == 1
        val = validated[0]
        assert val.validation_status == "CONFIRMED"
        assert val.ai_confidence >= 0.9
        assert "msg.sender" in val.fix_code

    def test_deterministic_validator_reentrancy_guard_low_risk(self):
        """Validator must classify guarded reentrancy pattern as LOW_RISK."""
        finding = adversum_core.Finding(
            id="HEU-004",
            message="Reentrancy",
            severity="CRITICAL",
            line=40,
            snippet="function withdraw() external nonReentrant {",
            flow_path=["nonReentrant"],
        )
        validated = adversum_core.validate_findings([finding])
        assert len(validated) == 1
        val = validated[0]
        assert val.validation_status == "LOW_RISK"
        assert val.ai_confidence <= 0.4

    def test_deterministic_validator_eval_false_positive(self):
        """Validator must reject ast.literal_eval as false positive."""
        finding = adversum_core.Finding(
            id="RUST_CORE_001_DANGEROUS_EVAL",
            message="Eval",
            severity="CRITICAL",
            line=5,
            snippet="data = ast.literal_eval(user_payload)",
        )
        validated = adversum_core.validate_findings([finding])
        assert len(validated) == 1
        val = validated[0]
        assert val.validation_status == "REJECTED"
        assert val.ai_confidence <= 0.2

    def test_deterministic_validator_sql_parameterized_query(self):
        """Validator must reject parameterized SQL query as false positive."""
        finding = adversum_core.Finding(
            id="RUST_CORE_005_SQL_INJECTION",
            message="SQLi",
            severity="HIGH",
            line=22,
            snippet="cursor.execute('SELECT * FROM accounts WHERE id = ?', (acc_id,))",
        )
        validated = adversum_core.validate_findings([finding])
        assert len(validated) == 1
        val = validated[0]
        assert val.validation_status == "REJECTED"

    def test_deterministic_validator_path_resolve_sanitizer(self):
        """Validator must recognize Path.resolve as a valid path sanitizer."""
        finding = adversum_core.Finding(
            id="RUST_CORE_004_PATH_TRAVERSAL",
            message="Path traversal",
            severity="HIGH",
            line=15,
            snippet="target = Path(base).resolve() / user_input",
            flow_path=["Path.resolve"],
        )
        validated = adversum_core.validate_findings([finding])
        assert len(validated) == 1
        assert validated[0].validation_status == "LOW_RISK"
